import os
import atexit
import json
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from logger import get_logger

logger = get_logger()
_scheduler_initialized = False

class MessageScheduler:
    """Планировщик для автоматической отправки сообщений (v3)"""
    
    def __init__(self, app, db):
        self.app = app
        self.db = db
        self.scheduler = BackgroundScheduler()
        
        # Основная задача: проверка очереди (пункт 1 плана)
        self.scheduler.add_job(
            func=self.process_queue,
            trigger=IntervalTrigger(seconds=30), # Уменьшаем частоту опроса до 30 секунд для экономии ресурсов
            id='process_queue',
            name='Process pending message slots v3',
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            misfire_grace_time=10
        )
        
        # ... (rest of jobs)
        
        # Задача очистки
        self.scheduler.add_job(
            func=self.auto_cleanup,
            trigger=IntervalTrigger(hours=12),
            id='auto_cleanup',
            name='Automatic data cleanup',
            replace_existing=True
        )

        # Задача восстановления зависших слотов (пункт 2 плана)
        self.scheduler.add_job(
            func=self.check_stale_slots,
            trigger=IntervalTrigger(minutes=1), # Increased frequency for Stage 4
            id='check_stale_slots',
            name='Recover executing slots that timed out',
            replace_existing=True
        )
        
        # 4️⃣ Zombie slot recovery (Stage 4)
        self.scheduler.add_job(
            func=self.recover_zombies,
            trigger=IntervalTrigger(minutes=1),
            id='recover_zombie_slots',
            name='Recover zombie slots with no heartbeat',
            replace_existing=True
        )
        
        self.scheduler.start()
        logger.info("Планировщик сообщений (v2) инициализирован")
    
    def recover_zombies(self):
        """4️⃣ Zombie slot recovery: recovers slots with no recent heartbeat"""
        try:
            with self.app.app_context():
                from sqlalchemy import text
                sql = """
                UPDATE scheduled_time_slots
                SET status = 'pending'
                WHERE status = 'executing'
                AND last_heartbeat < NOW() - INTERVAL '90 seconds'
                """
                res = self.db.session.execute(text(sql))
                count = res.rowcount
                self.db.session.commit()
                if count > 0:
                    logger.info(f"Восстановлено {count} зомби-слотов")
        except Exception as e:
            logger.error(f"Ошибка в recover_zombies: {e}")

    def check_stale_slots(self):
        """Периодическая проверка и восстановление зависших слотов"""
        try:
            from task_service import TaskService
            recovered_count = TaskService.recover_stale_slots(self.app, timeout_minutes=30)
            if recovered_count > 0:
                logger.info(f"Восстановлено {recovered_count} зависших слотов.")
        except Exception as e:
            logger.error(f"Ошибка в фоновой задаче check_stale_slots: {e}")
    
    def process_queue(self):
        """Проверяет БД на наличие слотов, готовых к отправке (Atomic Claim)"""
        try:
            with self.app.app_context():
                from sqlalchemy import text
                
                # STAGE 3 HARDEN: Atomic Slot Claim (Status pending -> executing)
                sql = """
                UPDATE scheduled_time_slots
                SET status = 'executing', last_heartbeat = NOW()
                WHERE id = (
                    SELECT id FROM scheduled_time_slots
                    WHERE
                      status = 'pending'
                      AND scheduled_datetime <= NOW()
                    ORDER BY scheduled_datetime
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                RETURNING id, task_id
                """
                result = self.db.session.execute(text(sql))
                slot_row = result.fetchone()
                self.db.session.commit()
                
                if not slot_row:
                    return

                slot_id = slot_row[0]
                task_id = slot_row[1]

                # 2️⃣ HARDEN: SELECT is_active FROM scheduled_tasks WHERE id = task_id
                check_sql = text("SELECT is_active FROM scheduled_tasks WHERE id = :task_id")
                is_active = self.db.session.execute(check_sql, {"task_id": task_id}).scalar()
                
                if not is_active:
                    # UPDATE scheduled_time_slots SET status='cancelled'
                    update_sql = text("UPDATE scheduled_time_slots SET status='cancelled' WHERE id=:slot_id")
                    self.db.session.execute(update_sql, {"slot_id": slot_id})
                    self.db.session.commit()
                    return

                from task_service import TaskService
                job_id = f'execute_slot_{slot_id}'
                self.scheduler.add_job(
                    func=TaskService.execute_slot,
                    args=[self.app, slot_id],
                    id=job_id,
                    misfire_grace_time=60,
                    replace_existing=True
                )
                
                def job_listener(event):
                    if event.job_id == job_id:
                        try:
                            self.scheduler.remove_job(job_id)
                        except: pass
                        self.scheduler.remove_listener(job_listener)
                
                from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
                self.scheduler.add_listener(job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
                
                logger.info(f"Слот {slot_id} запущен в обработку")
                    
        except Exception as e:
            logger.error(f"Ошибка очереди планировщика: {e}")

    def add_task(self, task, utc_times):
        """Интеграция новой задачи в очередь планировщика"""
        try:
            from models import ScheduledTimeSlot
            with self.app.app_context():
                self.db.session.add(task)
                self.db.session.flush() # Получаем task.id
                
                # Создаем слоты времени
                for time_str in utc_times:
                    dt = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                    slot = ScheduledTimeSlot(
                        task_id=task.id,
                        scheduled_datetime=dt,
                        status='pending',
                        total_recipients=len(json.loads(task.recipients))
                    )
                    self.db.session.add(slot)
                
                self.db.session.commit()
                return {'success': True, 'task_id': task.id}
        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Ошибка добавления задачи в планировщик: {e}")
            return {'success': False, 'error': str(e)}

    def remove_task(self, task_id):
        """Удаление задачи из планировщика (отмена)"""
        try:
            with self.app.app_context():
                from models import ScheduledTimeSlot
                # Помечаем все ожидающие слоты как отмененные
                slots = ScheduledTimeSlot.query.filter_by(task_id=task_id).filter(ScheduledTimeSlot.status == 'pending').all()
                for slot in slots:
                    slot.status = 'cancelled'
                self.db.session.commit()
                logger.info(f"Задача {task_id} отменена в планировщике")
                return True
        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Ошибка отмены задачи {task_id}: {e}")
            return False

    def trigger_immediate_process(self):
        """Мгновенно пробуждает планировщик для обработки очереди"""
        try:
            if self.scheduler.running:
                # Находим джоб по ID и запускаем его немедленно
                job = self.scheduler.get_job('process_queue')
                if job:
                    job.modify(next_run_time=datetime.utcnow())
                    logger.info("Планировщик принудительно пробужден для обработки новой задачи")
        except Exception as e:
            logger.error(f"Ошибка при пробуждении планировщика: {e}")

    def auto_cleanup(self):
        """Автоматическая очистка старых данных"""
        try:
            from cleanup import run_auto_cleanup
            run_auto_cleanup(self.app, self.db)
        except Exception as e:
            logger.error(f"Ошибка авто-очистки: {e}")

    def shutdown(self):
        """Остановить планировщик"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Планировщик остановлен")

message_scheduler = None

def _cleanup_scheduler():
    global message_scheduler
    if message_scheduler:
        message_scheduler.shutdown()

def init_scheduler(app, db, telegram_manager=None):
    global message_scheduler, _scheduler_initialized
    if message_scheduler is None and not _scheduler_initialized:
        _scheduler_initialized = True
        message_scheduler = MessageScheduler(app, db)
        atexit.register(_cleanup_scheduler)
    return message_scheduler

def get_scheduler():
    return message_scheduler
