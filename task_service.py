import os
import time
import json
import traceback
from datetime import datetime

from models import db, MessageLog, SentMessage
from sqlalchemy import text

from logger import get_logger

logger = get_logger('telegram_sender', 'logs')


def get_telegram_manager(config, session_name):
    from telegram_client import TelegramManager

    api_id = None
    api_hash = None
    if hasattr(config, 'get'):
        api_id = config.get('TELEGRAM_API_ID')
        api_hash = config.get('TELEGRAM_API_HASH')
        if not api_id or not api_hash:
            telegram_cfg = config.get('telegram', {})
            api_id = telegram_cfg.get('api_id')
            api_hash = telegram_cfg.get('api_hash')
    if not api_id or not api_hash:
        api_id = getattr(config, 'TELEGRAM_API_ID', None)
        api_hash = getattr(config, 'TELEGRAM_API_HASH', None)
    if not api_id or not api_hash:
        api_id = os.environ.get('TELEGRAM_API_ID')
        api_hash = os.environ.get('TELEGRAM_API_HASH')
    if not api_id or not api_hash:
        try:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    c = json.load(f)
                    api_id = c.get('telegram', {}).get('api_id')
                    api_hash = c.get('telegram', {}).get('api_hash')
        except Exception:
            pass
    return TelegramManager(api_id=api_id, api_hash=api_hash, session_name=session_name)


async def send_message_internal(
    manager,
    p_id,
    txt,
    imgs,
    pos='top',
    *,
    slot_id=None,
    recipient_type='unknown',
    topic_id=None,
):
    """Универсальная функция отправки сообщения в планировщике.

    Возвращает (success: bool, error_message: str | None)
    """

    try:
        p_id_str = str(p_id) if p_id is not None else ''
        txt = txt or ''

        logger.debug(
            "[send_message_internal] called",
            slot_id=slot_id,
            recipient_id=p_id_str,
            recipient_type=recipient_type,
            topic_id=topic_id,
            txt_len=len(txt),
            imgs_type=type(imgs).__name__,
            pos=pos,
        )

        if not txt and not imgs:
            return False, 'No text or images to send'

        if not manager or not getattr(manager, 'client', None):
            return False, 'Telegram manager/client is not initialized'

        try:
            try:
                await manager.client.get_input_entity(int(p_id_str))
            except Exception:
                await manager.client.get_input_entity(p_id_str)
        except Exception as e:
            logger.error(
                f"[send_message_internal] Failed to resolve recipient entity: {p_id_str}: {e}",
                slot_id=slot_id,
                exc_info=True,
            )
            return False, f'Failed to get entity: {e}'

        image_list = []
        if imgs:
            if isinstance(imgs, str):
                try:
                    image_list = json.loads(imgs) or []
                except Exception:
                    image_list = [imgs]
            elif isinstance(imgs, list):
                image_list = imgs

        image_list = [p for p in image_list if p]

        try:
            if image_list:
                if len(image_list) == 1:
                    result = await manager._send_message_with_image_async(
                        p_id_str,
                        txt,
                        image_list[0],
                        entity_type=recipient_type,
                        topic_id=topic_id,
                        image_position=pos,
                    )
                else:
                    result = await manager._send_message_with_images_async(
                        p_id_str,
                        txt,
                        image_list,
                        entity_type=recipient_type,
                        topic_id=topic_id,
                        image_position=pos,
                    )
            else:
                result = await manager._send_message_async(
                    p_id_str,
                    txt,
                    entity_type=recipient_type,
                    topic_id=topic_id,
                )
        except Exception as e:
            logger.error(
                f"[send_message_internal] Exception while sending to {p_id_str}: {e}\n{traceback.format_exc()}",
                slot_id=slot_id,
            )
            return False, str(e)

        success = bool(result.get('success'))
        error_msg = result.get('error') if not success else None

        if success:
            logger.info(
                f"[send_message_internal] Sent successfully to {p_id_str}",
                slot_id=slot_id,
                recipient_type=recipient_type,
            )
        else:
            logger.error(
                f"[send_message_internal] Send failed to {p_id_str}: {error_msg}",
                slot_id=slot_id,
                recipient_type=recipient_type,
            )

        return success, error_msg
    except Exception as e:
        logger.error(
            f"[send_message_internal] Critical error: {e}\n{traceback.format_exc()}",
            slot_id=slot_id,
        )
        return False, str(e)


class TaskService:
    @staticmethod
    def is_slot_cancelled(slot_id):
        try:
            res = db.session.execute(
                text(
                    "SELECT t.is_active, s.status FROM scheduled_tasks t JOIN scheduled_time_slots s ON s.task_id = t.id WHERE s.id = :s"
                ),
                {"s": slot_id},
            ).fetchone()
            if not res or not res.is_active or res.status != 'executing':
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def update_slot_progress(slot_id, processed_increment=1, status=None):
        try:
            db.session.execute(
                text(
                    "UPDATE scheduled_time_slots SET processed_recipients = processed_recipients + :inc WHERE id = :s"
                ),
                {"inc": processed_increment, "s": slot_id},
            )
            if status:
                db.session.execute(
                    text("UPDATE scheduled_time_slots SET status = :st WHERE id = :s"),
                    {"st": status, "s": slot_id},
                )

            res = db.session.execute(
                text("SELECT processed_recipients, total_recipients FROM scheduled_time_slots WHERE id = :s"),
                {"s": slot_id},
            ).fetchone()
            if res and res.processed_recipients >= res.total_recipients:
                has_issues = (
                    db.session.execute(
                        text(
                            "SELECT 1 FROM sent_messages WHERE slot_id = :s AND status IN ('failed', 'cancelled') LIMIT 1"
                        ),
                        {"s": slot_id},
                    ).fetchone()
                    is not None
                )
                final_status = 'completed_with_errors' if has_issues else 'completed'
                db.session.execute(
                    text(
                        "UPDATE scheduled_time_slots SET status = :st, is_sent = true, sent_at = NOW() WHERE id = :s"
                    ),
                    {"st": final_status, "s": slot_id},
                )
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"[update_slot_progress] Error: {e}", slot_id=slot_id, exc_info=True)

    @staticmethod
    def log_message(
        user_id,
        task_id,
        slot_id,
        recipient,
        message_text,
        status='sent',
        error=None,
        tg_username=None,
    ):
        try:
            r_id = str(recipient.get('id', 'unknown')) if isinstance(recipient, dict) else str(recipient)
            r_name = str(recipient.get('name', 'Unknown')) if isinstance(recipient, dict) else str(recipient)
            log = MessageLog(
                user_id=user_id,
                task_id=task_id,
                slot_id=slot_id,
                recipient_id=r_id,
                recipient_name=r_name,
                message_text=message_text,
                status=status,
                error_message=error,
                telegram_username=tg_username,
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"[log_message] Error: {e}", slot_id=slot_id, exc_info=True)

    @classmethod
    def recover_stale_slots(cls, app, timeout_minutes=30):
        with app.app_context():
            try:
                res = db.session.execute(
                    text(
                        "UPDATE scheduled_time_slots SET status = 'pending' WHERE status = 'executing' AND scheduled_datetime < NOW() - INTERVAL '30 minutes' AND (last_heartbeat IS NULL OR last_heartbeat < NOW() - INTERVAL '10 minutes') RETURNING id"
                    )
                )
                ids = res.fetchall()
                db.session.commit()
                return len(ids)
            except Exception:
                db.session.rollback()
                return 0

    @classmethod
    def execute_slot(cls, app, slot_id):
        with app.app_context():
            logger.info(f"[execute_slot] Starting slot {slot_id}")

            init_sql = """
            SELECT t.id as task_id, t.user_id, t.recipients, t.recipients_info, t.message_text, t.image_path,
                   t.telegram_username, t.session_name, t.device_id, t.image_position,
                   s.status, s.processed_recipients
            FROM scheduled_tasks t
            JOIN scheduled_time_slots s ON s.task_id = t.id
            WHERE s.id = :slot_id
            """
            init_res = db.session.execute(text(init_sql), {"slot_id": slot_id}).fetchone()
            if not init_res or init_res.status != 'executing':
                logger.warning(f"[execute_slot] Slot {slot_id} is not in executing status")
                return

            task_id = init_res.task_id
            user_id = init_res.user_id
            msg_text = init_res.message_text
            img_path = init_res.image_path
            img_pos = getattr(init_res, 'image_position', 'top')
            tg_user = init_res.telegram_username
            start_idx = init_res.processed_recipients

            recipients = json.loads(init_res.recipients)

            recipients_info = []
            if getattr(init_res, 'recipients_info', None):
                try:
                    recipients_info = json.loads(init_res.recipients_info) or []
                except Exception as e:
                    logger.warning(f"[execute_slot] Failed to parse recipients_info: {e}")

            recipients_info_map = {
                str(r.get('id')): r
                for r in recipients_info
                if isinstance(r, dict) and r.get('id') is not None
            }

            db.session.execute(
                text(
                    "UPDATE scheduled_time_slots SET total_recipients = :t, last_heartbeat = NOW() WHERE id = :s"
                ),
                {"t": len(recipients), "s": slot_id},
            )
            db.session.commit()

            try:
                from flask import current_app

                config = getattr(current_app, 'config', {})
                messaging_config = config.get('messaging', {}) if hasattr(config, 'get') else {}
                delay_std = messaging_config.get('delay_between_messages', 15)
                delay_grp = messaging_config.get('min_delay_for_groups', 17)

                session_name = init_res.session_name or f"session_user_{user_id}_{init_res.device_id or 'default'}"
                from telegram_client import get_telegram_manager as get_cached_manager

                manager = get_cached_manager(config, session_name=session_name)

                try:
                    if not manager.client:
                        manager._run_async(manager.init_client())
                    manager._run_async(manager.client.connect())
                except Exception as e:
                    logger.error(f"[execute_slot] Telegram connection error for slot {slot_id}: {e}", exc_info=True)
                    db.session.execute(
                        text(
                            "UPDATE scheduled_time_slots SET status = 'failed', last_heartbeat = NOW() WHERE id = :s"
                        ),
                        {"s": slot_id},
                    )
                    db.session.commit()
                    return

                if not manager.is_authorized():
                    logger.error(f"[execute_slot] Telegram not authorized for slot {slot_id}")
                    db.session.execute(
                        text("UPDATE scheduled_time_slots SET status = 'failed' WHERE id = :s"),
                        {"s": slot_id},
                    )
                    db.session.commit()
                    return

                fence_sql = "SELECT t.is_active, s.status FROM scheduled_tasks t JOIN scheduled_time_slots s ON s.task_id = t.id WHERE s.id = :s"
                cancel_sql = "UPDATE sent_messages SET status='cancelled' WHERE slot_id=:s AND status IN ('pending','sending')"
                update_sql = "UPDATE scheduled_time_slots SET status='cancelled' WHERE id=:s"

                for i in range(start_idx, len(recipients)):
                    if i >= len(recipients):
                        break

                    r_data = recipients[i]

                    logger.debug(
                        f"[execute_slot] Processing recipient {i + 1}/{len(recipients)}: {r_data}",
                        slot_id=slot_id,
                    )

                    if not r_data:
                        logger.warning(
                            f"[execute_slot] Slot {slot_id}: empty recipient at index {i}, skipping"
                        )
                        cls.update_slot_progress(slot_id)
                        continue

                    recipient = (
                        r_data
                        if isinstance(r_data, dict)
                        else {'id': str(r_data), 'name': str(r_data)}
                    )

                    if not recipient.get('id'):
                        logger.warning(
                            f"[execute_slot] Slot {slot_id}: recipient without id {r_data}, skipping"
                        )
                        cls.update_slot_progress(slot_id)
                        continue

                    r_id_str = str(recipient.get('id'))
                    info = recipients_info_map.get(r_id_str)
                    if info:
                        recipient['name'] = info.get('name') or recipient.get('name')
                        recipient['type'] = info.get('type') or recipient.get('type')
                        recipient['topic_id'] = info.get('topic_id')

                    f_res = db.session.execute(text(fence_sql), {"s": slot_id}).fetchone()
                    if not f_res or not f_res.is_active or f_res.status != 'executing':
                        db.session.execute(text(cancel_sql), {"s": slot_id})
                        db.session.execute(text(update_sql), {"s": slot_id})
                        db.session.commit()
                        return

                    exists = db.session.execute(
                        text(
                            "SELECT status FROM sent_messages WHERE slot_id = :s AND recipient_id = :r"
                        ),
                        {"s": slot_id, "r": r_id_str},
                    ).fetchone()
                    if exists and exists.status == 'sent':
                        cls.update_slot_progress(slot_id)
                        continue

                    success, error_msg = False, None
                    try:
                        success, error_msg = manager._run_async(
                            send_message_internal(
                                manager,
                                r_id_str,
                                msg_text,
                                img_path,
                                img_pos,
                                slot_id=slot_id,
                                recipient_type=recipient.get('type', 'unknown'),
                                topic_id=recipient.get('topic_id'),
                            ),
                            timeout=300,
                        )
                    except Exception as e:
                        error_msg = str(e)
                        success = False
                        logger.error(
                            f"[execute_slot] Error calling send_message_internal for {r_id_str}: {e}",
                            slot_id=slot_id,
                            exc_info=True,
                        )

                    f_res = db.session.execute(text(fence_sql), {"s": slot_id}).fetchone()
                    final_status = (
                        'cancelled'
                        if (not f_res or not f_res.is_active or f_res.status != 'executing')
                        else ('sent' if success else 'failed')
                    )

                    if exists:
                        db.session.execute(
                            text(
                                "UPDATE sent_messages SET status = :st, error_message = :err, sent_at = NOW() WHERE slot_id = :s AND recipient_id = :r"
                            ),
                            {
                                "st": final_status,
                                "err": error_msg,
                                "s": slot_id,
                                "r": r_id_str,
                            },
                        )
                    else:
                        db.session.add(
                            SentMessage(
                                slot_id=slot_id,
                                recipient_id=r_id_str,
                                status=final_status,
                                error_message=error_msg,
                                sent_at=datetime.utcnow(),
                            )
                        )
                    db.session.commit()

                    cls.log_message(
                        user_id,
                        task_id,
                        slot_id,
                        recipient,
                        msg_text,
                        final_status,
                        error_msg,
                        tg_user,
                    )
                    cls.update_slot_progress(slot_id)

                    db.session.execute(
                        text(
                            "UPDATE scheduled_time_slots SET last_heartbeat = NOW() WHERE id = :s AND status = 'executing'"
                        ),
                        {"s": slot_id},
                    )
                    db.session.commit()

                    if final_status == 'cancelled':
                        return

                    delay = (
                        delay_grp
                        if recipient.get('type', '').lower() in ['group', 'channel', 'megagroup']
                        else delay_std
                    )

                    if i < len(recipients) - 1:
                        w_start = time.time()
                        while time.time() - w_start < delay:
                            f_res = db.session.execute(text(fence_sql), {"s": slot_id}).fetchone()
                            if not f_res or not f_res.is_active or f_res.status != 'executing':
                                db.session.execute(text(cancel_sql), {"s": slot_id})
                                db.session.execute(text(update_sql), {"s": slot_id})
                                db.session.commit()
                                return
                            time.sleep(1)

                rem = db.session.execute(
                    text(
                        "SELECT COUNT(*) FROM scheduled_time_slots WHERE task_id = :t AND status = 'pending'"
                    ),
                    {"t": task_id},
                ).scalar()
                if rem == 0:
                    db.session.execute(
                        text("UPDATE scheduled_tasks SET is_active = false WHERE id = :t"),
                        {"t": task_id},
                    )
                    db.session.commit()
            except Exception as e:
                logger.error(
                    f"[execute_slot] Critical error in slot {slot_id}: {e}\n{traceback.format_exc()}",
                    slot_id=slot_id,
                )
                db.session.execute(
                    text("UPDATE scheduled_time_slots SET status = 'failed' WHERE id = :s"),
                    {"s": slot_id},
                )
                db.session.commit()
