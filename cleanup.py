import os
import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger('telegram_sender')

def load_cleanup_config():
    """Загрузить конфигурацию очистки"""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            return config.get('cleanup', {})
    except Exception as e:
        logger.error(f"Ошибка загрузки конфигурации очистки: {e}")
        return {}

def run_auto_cleanup(app, db):
    """Выполнить автоматическую очистку данных"""
    logger.info("Запуск автоматической очистки данных...")
    
    with app.app_context():
        try:
            from models import ScheduledTask, ScheduledTimeSlot, MessageLog
            
            cleanup_config = load_cleanup_config()
            cache_days = cleanup_config.get('image_cache_days', 2)
            tasks_months = cleanup_config.get('completed_tasks_months', 1)
            session_days = cleanup_config.get('session_cache_days', 30)
            
            now = datetime.now()
            utc_now = datetime.utcnow()

            # 1. Очистка кэша изображений
            active_tasks = ScheduledTask.query.filter_by(is_active=True).all()
            used_files = set()
            for task in active_tasks:
                if task.image_path:
                    try:
                        paths = json.loads(task.image_path)
                        if isinstance(paths, list):
                            for p in paths:
                                used_files.add(os.path.basename(p))
                        else:
                            used_files.add(os.path.basename(task.image_path))
                    except:
                        used_files.add(os.path.basename(task.image_path))

            upload_folder = app.config['UPLOAD_FOLDER']
            files_removed = 0
            if os.path.exists(upload_folder):
                for f in os.listdir(upload_folder):
                    if f in used_files:
                        continue
                    file_path = os.path.join(upload_folder, f)
                    if os.path.isfile(file_path):
                        file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if now - file_time > timedelta(days=cache_days):
                            try:
                                os.remove(file_path)
                                files_removed += 1
                            except Exception as e:
                                logger.error(f"Ошибка удаления файла кэша {f}: {e}")

            # 2. Очистка старых выполненных задач
            cutoff_date = utc_now - timedelta(days=tasks_months * 30)
            # Принудительно сбрасываем состояние сессии перед запросом, чтобы увидеть изменения из других потоков
            db.session.expire_all()
            old_tasks = ScheduledTask.query.filter(
                ScheduledTask.is_active == False,
                ScheduledTask.created_at < cutoff_date
            ).all()
            
            tasks_removed = 0
            for task in old_tasks:
                try:
                    # Удаляем связанные записи
                    ScheduledTimeSlot.query.filter_by(task_id=task.id).delete()
                    MessageLog.query.filter_by(task_id=task.id).delete()
                    db.session.delete(task)
                    tasks_removed += 1
                except Exception as e:
                    logger.error(f"Ошибка удаления задачи {task.id}: {e}")
            
            db.session.commit()

            # 3. Очистка старых файлов сессий
            session_folder = 'sessions'
            sessions_removed = 0
            if os.path.exists(session_folder):
                for f in os.listdir(session_folder):
                    if f.endswith('.session') or f.endswith('.session-journal'):
                        file_path = os.path.join(session_folder, f)
                        if os.path.isfile(file_path):
                            file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                            if now - file_time > timedelta(days=session_days):
                                try:
                                    os.remove(file_path)
                                    sessions_removed += 1
                                except Exception as e:
                                    logger.error(f"Ошибка удаления старой сессии {f}: {e}")

            db.session.commit()
            logger.info(f"Автоматическая очистка завершена: удалено файлов кэша: {files_removed}, задач: {tasks_removed}, сессий: {sessions_removed}")
            return {
                'files_removed': files_removed,
                'tasks_removed': tasks_removed,
                'sessions_removed': sessions_removed
            }
        except Exception as e:
            logger.error(f"Ошибка при автоматической очистке: {e}")
            db.session.rollback()
            return None
