import sys
import os
import json
from functools import wraps

# Add current directory to path so that models and other local modules can be found
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, ScheduledTask, ScheduledTimeSlot, MessageLog, SentMessage, IdempotentRequest, AuthCodeHash
from telegram_client import get_telegram_manager
from scheduler import init_scheduler, get_scheduler
from logger import init_logger, get_logger
from utils import allowed_file, get_user_tz_offset_minutes, local_to_utc, DateTimeEncoder, get_device_id
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
import secrets
import threading
import time
import glob

app_logger = init_logger('telegram_sender', 'logs')
logger = app_logger

logger.info("=" * 80)
logger.info("Запуск приложения Telegram Sender")
logger.info("=" * 80)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
# Переключаем на PostgreSQL для предотвращения 'database is locked'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,
    'max_overflow': 40,
    'pool_timeout': 60,
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'json_serializer': json.dumps,
    'connect_args': {
        'application_name': 'telegram_sender',
        'options': '-c statement_timeout=30000'
    }
}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

csrf = CSRFProtect(app)
migrate = Migrate(app, db)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
db.init_app(app)
logger.info("SQLAlchemy инициализирован")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None

logger.info("Загрузка конфигурации")
try:
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    # Ensure telegram dict exists
    if 'telegram' not in config:
        config['telegram'] = {}
    
    env_api_id = os.environ.get('TELEGRAM_API_ID')
    if env_api_id:
        try:
            config['telegram']['api_id'] = int(env_api_id)
        except (ValueError, TypeError):
            logger.error(f"Невалидный TELEGRAM_API_ID в окружении: {env_api_id}")
            
    if os.environ.get('TELEGRAM_API_HASH'):
        config['telegram']['api_hash'] = os.environ.get('TELEGRAM_API_HASH')
    if os.environ.get('ADMIN_LOGIN'):
        config['admin']['login'] = os.environ.get('ADMIN_LOGIN')
    if os.environ.get('ADMIN_PASSWORD'):
        config['admin']['password'] = os.environ.get('ADMIN_PASSWORD')
    
    logger.info("Конфигурация загружена успешно")
    logger.debug(f"API ID: {'SET' if config['telegram'].get('api_id') else 'NOT SET'}")
except Exception as e:
    logger.critical(f"Ошибка загрузки конфигурации: {e}")
    raise

logger.info("Инициализация Telegram менеджера")

def get_user_telegram_manager(user_id):
    """Создает новый экземпляр TelegramManager для конкретного пользователя.
    Отказ от кэширования для обеспечения изоляции между запросами.
    """
    from flask import has_request_context
    import glob
    
    if has_request_context():
        device_id = get_device_id()
    else:
        # Для планировщика ищем последнюю активную сессию именно для этого пользователя
        # Важно: glob.glob(f'sessions/session_user_{user_id}_*.session') уже содержит user_id в начале,
        # но мы должны убедиться, что не захватываем чужие сессии (например, если user_id=1, не захватить 10, 11 и т.д.)
        # Используем более строгий паттерн с разделителем подчеркивания
        session_pattern = os.path.join('sessions', f'session_user_{user_id}_*.session')
        session_files = [f for f in glob.glob(session_pattern) if os.path.basename(f).startswith(f'session_user_{user_id}_')]
        
        if session_files:
            most_recent = max(session_files, key=lambda x: os.path.getmtime(x))
            # Извлекаем device_id из имени файла
            filename = os.path.basename(most_recent)
            device_id = filename.replace(f'session_user_{user_id}_', '').replace('.session', '')
            logger.debug(f"Scheduler: найдена активная сессия пользователя {user_id} с device_id={device_id}")
        else:
            device_id = 'default'
            logger.debug(f"Scheduler: сессии для пользователя {user_id} не найдены, использую device_id=default")
        
    session_name = f'session_user_{user_id}_{device_id}'
    
    # Каждый вызов возвращает экземпляр через потокобезопасный кэш в telegram_client
    return get_telegram_manager(config, session_name=session_name)

logger.info("Telegram менеджер инициализирован")

logger.info("Инициализация планировщика задач")
with app.app_context():
    db.create_all()
    logger.info("Таблицы базы данных созданы/проверены")
    scheduler = init_scheduler(app, db, None)
    logger.info("Планировщик задач запущен")

logger.info("=" * 80)
logger.info("Приложение полностью инициализировано и готово к работе")
logger.info("=" * 80)


def get_idempotent_request(idempotent_key, endpoint):
    """Базовый поиск идемпотентного запроса"""
    if not idempotent_key:
        return None
    return IdempotentRequest.query.filter_by(
        user_id=current_user.id,
        idempotent_key=idempotent_key,
        endpoint=endpoint
    ).first()

def check_idempotent_key(idempotent_key, endpoint):
    """Проверяет идемпотентный ключ и возвращает кэшированный ответ если есть"""
    existing = get_idempotent_request(idempotent_key, endpoint)
    if existing:
        if existing.is_processing:
            return {'error': 'Запрос уже обрабатывается', 'retry_after': 1}, 409
        logger.info(f"Идемпотентный ключ найден: {idempotent_key}, возвращаю кэшированный ответ")
        return json.loads(existing.response), 200
    return None

def mark_idempotent_processing(idempotent_key, endpoint):
    """Отмечает идемпотентный ключ как обрабатываемый (АТОМАРНАЯ операция)"""
    if not idempotent_key:
        return None
    try:
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        stmt = pg_insert(IdempotentRequest).values(
            user_id=current_user.id,
            idempotent_key=idempotent_key,
            endpoint=endpoint,
            response='{}',
            is_processing=True
        ).on_conflict_do_update(
            index_elements=['idempotent_key'],
            set_={'is_processing': True}
        )
        db.session.execute(stmt)
        db.session.commit()
        return get_idempotent_request(idempotent_key, endpoint)
    except Exception as e:
        logger.error(f"Ошибка отметки идемпотентного ключа: {e}")
        db.session.rollback()
        return None


def save_idempotent_response(idempotent_key, response_data):
    """Сохраняет ответ для идемпотентного ключа"""
    if not idempotent_key:
        return
    
    try:
        existing = IdempotentRequest.query.filter_by(
            idempotent_key=idempotent_key
        ).first()
        
        if existing:
            existing.response = json.dumps(response_data, cls=DateTimeEncoder)
            existing.is_processing = False
            db.session.commit()
            logger.info(f"Ответ сохранен для идемпотентного ключа: {idempotent_key}")
    except Exception as e:
        logger.error(f"Ошибка сохранения ответа идемпотентного ключа: {e}")


@app.context_processor
def inject_csrf_token():
    """Инъектирует CSRF токен в контекст шаблонов"""
    return dict(csrf_token=lambda: session.get('_csrf_token', ''))


# All redundant helper functions have been moved to utils.py


def telegram_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('telegram_authorized'):
            # Double check with manager only if we haven't already checked this request
            if not getattr(request, '_tg_checked', False):
                try:
                    manager = get_user_telegram_manager(current_user.id)
                    if manager and manager.is_authorized():
                        session['telegram_authorized'] = True
                        request._tg_checked = True
                        return f(*args, **kwargs)
                except:
                    pass
                return redirect(url_for('telegram_auth'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.telegram_authorized:
            return redirect(url_for('contacts'))
        return redirect(url_for('telegram_auth'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        logger.log_request('/login', 'POST', data={'username': username})
        logger.info(f"Попытка входа пользователя: {username}")
        
        user = User.query.filter_by(username=username).first()
        
        if not user and username == config['admin']['login'] and password == config['admin']['password']:
            # Создаем админа при первом входе, если его нет
            user = User(username=username, password_hash='')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            logger.info(f"Создан новый пользователь: {username}")
        
        if user and user.check_password(password):
            device_id = get_device_id()
            
            # Очищаем сессию, но сразу восстанавливаем device_id
            session.clear()
            
            # Force non-permanent session that clears on browser close
            session.permanent = False
            login_user(user, remember=False)
            
            session['device_id'] = device_id
            session['current_user_id'] = user.id
            
            # CRITICAL: Mark session as modified to ensure cookie is sent
            session.modified = True
            
            # Reset Telegram auth status for this new session
            session['telegram_authorized'] = False
            
            logger.info(f"Успешный вход пользователя: {username} (устройство: {device_id})")
            logger.log_response('/login', 200, 'Успешный вход')
            flash('Успешный вход!', 'success')
            
            response = redirect(url_for('telegram_auth'))
            # Дублируем device_id в долгосрочную куку (на 30 дней) для надежности
            response.set_cookie('device_id', device_id, max_age=30*24*60*60, httponly=True, samesite='Lax')
            return response
        else:
            logger.warning(f"Неверные учетные данные для пользователя: {username}")
            logger.log_response('/login', 401, 'Неверные учетные данные')
            flash('Неверный логин или пароль', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    try:
        user_id = current_user.id
        device_id = get_device_id()
        
        if device_id:
            session_name = f'session_user_{user_id}_{device_id}'
            from telegram_client import _managers_cache, _managers_lock
            with _managers_lock:
                if session_name in _managers_cache:
                    manager = _managers_cache[session_name]
                    logger.info(f"Выход пользователя {user_id}, принудительное отключение Telegram")
                    try:
                        manager.disconnect()
                    except:
                        pass
                    del _managers_cache[session_name]
    except Exception as e:
        logger.warning(f"Предупреждение при выходе: {e}")
    
    # Сохраняем device_id перед очисткой сессии
    device_id = get_device_id()
    
    # Выходим через Flask-Login
    logout_user()
    
    # Очищаем сессию
    session.clear()
    
    # Создаем ответ
    response = redirect(url_for('login'))
    
    # Если у нас был device_id, восстанавливаем его в сессии и куках
    if device_id:
        session['device_id'] = device_id
        response.set_cookie('device_id', device_id, max_age=30*24*60*60, httponly=True, samesite='Lax')
    
    # Явно удаляем куку сессии Flask (она пересоздастся при необходимости)
    response.set_cookie('session', '', expires=0)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    flash('Вы вышли из системы', 'info')
    return response


@app.route('/api/telegram/logout', methods=['POST'])
@login_required
def telegram_logout_api():
    try:
        device_id = get_device_id()
        session_name = f'session_user_{current_user.id}_{device_id}'
        from telegram_client import _managers_cache, _managers_lock
        with _managers_lock:
            if session_name in _managers_cache:
                manager = _managers_cache[session_name]
                try:
                    manager.disconnect()
                except: pass
                del _managers_cache[session_name]
        
        session.pop('telegram_authorized', None)
        session.pop('tg_phone', None)
        session.pop('tg_phone_code_hash', None)
        session.modified = True
        
        current_user.telegram_authorized = False
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/telegram_auth', methods=['GET', 'POST'])
@login_required
def telegram_auth():
    try:
        manager = get_user_telegram_manager(current_user.id)
        if manager and manager.is_authorized():
            # Обновляем данные пользователя из Telegram
            me = manager._run_async(manager.client.get_me())
            
            tg_display_name = f"@{me.username}" if me.username else f"{me.first_name} {me.last_name or ''}".strip()
            
            # Update session with current Telegram name for header display
            session['telegram_username'] = tg_display_name
            session.modified = True # Гарантируем сохранение имени в сессии
            
            current_user.telegram_authorized = True
            # Обновляем ID и имя, но больше не блокируем вход при несовпадении
            current_user.telegram_id = me.id
            current_user.telegram_username = tg_display_name
            session['telegram_authorized'] = True
            db.session.commit()
            
            # Продлеваем жизнь куки устройства при каждом успешном входе в ТГ
            device_id = get_device_id()
            logger.info(f"Telegram сессия активна для пользователя {current_user.id} (TG ID: {me.id}, Device: {device_id})")
            
            response = redirect(url_for('contacts'))
            if device_id:
                response.set_cookie('device_id', device_id, max_age=30*24*60*60, httponly=True, samesite='Lax')
            return response
    except Exception as e:
        logger.error(f"Ошибка проверки Telegram сессии: {e}", exc_info=True)
    
    return render_template('telegram_auth.html')

@app.route('/api/telegram/status')
@login_required
def telegram_status():
    try:
        manager = get_user_telegram_manager(current_user.id)
        is_auth = manager.is_authorized() if manager else False
        return jsonify({'authorized': is_auth})
    except Exception as e:
        return jsonify({'authorized': False, 'error': str(e)})


def check_rate_limit(user_id, endpoint, target_identifier, limit, period):
    """
    Проверяет лимит запросов для конкретного идентификатора (телефон или устройство).
    """
    from sqlalchemy import func
    
    since = datetime.utcnow() - timedelta(seconds=period)
    count = db.session.query(func.count(IdempotentRequest.id)).filter(
        IdempotentRequest.user_id == user_id,
        IdempotentRequest.endpoint == endpoint,
        IdempotentRequest.target_identifier == target_identifier,
        IdempotentRequest.created_at >= since
    ).scalar()
    
    return count < limit

def record_rate_limit_attempt(user_id, endpoint, target_identifier):
    """
    Записывает попытку запроса в базу данных.
    """
    try:
        temp_key = f"limit_{endpoint.replace('/', '_')}_{target_identifier}_{secrets.token_hex(4)}"
        
        req = IdempotentRequest(
            user_id=user_id,
            idempotent_key=temp_key,
            endpoint=endpoint,
            target_identifier=target_identifier,
            response='{}',
            is_processing=False
        )
        db.session.add(req)
        db.session.commit()
        return True
    except Exception as e:
        logger.error(f"Ошибка записи лимита: {e}")
        db.session.rollback()
        return False

@app.route('/api/telegram/send_code', methods=['POST'])
@login_required
def send_telegram_code():
    data = request.json
    phone = data.get('phone')
    device_id = get_device_id()
    
    if not phone:
        return jsonify({'success': False, 'error': 'Phone number required'})

    # Проверка "Умного возврата" - если номер тот же и есть хэш, не запрашиваем API
    active_phone = session.get('tg_phone')
    active_hash = session.get('tg_phone_code_hash')
    last_send_time = session.get('tg_last_send_time', 0)
    force_retry = data.get('retry') is True
    
    if not force_retry and active_phone == phone and active_hash and (time.time() - last_send_time < 300):
        logger.info(f"Умный возврат: номер {phone} совпадает с активной сессией, переиспользуем хэш")
        return jsonify({'success': True, 'phone_code_hash': active_hash, 'reused': True})
    
        # Если это принудительная переотправка, очищаем старый хэш для чистого запроса
        if force_retry:
            session.pop('tg_phone_code_hash', None)
            session.pop('tg_phone', None)
            session.pop('tg_last_send_time', None) # Очищаем время, чтобы не сработал "Умный возврат"
            session.modified = True
            logger.info(f"Принудительная переотправка для {phone}, данные сессии очищены")
            
            # Также очищаем кэш менеджеров для этого устройства, чтобы пересоздать клиент
            device_id = get_device_id()
            session_name = f'session_user_{current_user.id}_{device_id}'
            from telegram_client import _managers_cache, _managers_lock
            with _managers_lock:
                if session_name in _managers_cache:
                    logger.info(f"Сброс кэша менеджера для {session_name} при переотправке")
                    try:
                        _managers_cache[session_name].disconnect()
                    except: pass
                    del _managers_cache[session_name]

    if not check_rate_limit(current_user.id, '/api/telegram/send_code', f"dev_{device_id}", limit=10, period=300):
        return jsonify({'success': False, 'error': 'Слишком много запросов с вашего устройства. Подождите 5 минут.'})
    
    if not check_rate_limit(current_user.id, '/api/telegram/send_code', f"phone_{phone}", limit=3, period=300):
        return jsonify({'success': False, 'error': f'Слишком много запросов для номера {phone}. Подождите 5 минут.'})

    # Дополнительный лимит по IP
    ip_addr = request.remote_addr
    if not check_rate_limit(current_user.id, '/api/telegram/send_code', f"ip_{ip_addr}", limit=5, period=300):
        return jsonify({'success': False, 'error': 'Слишком много запросов с вашего IP. Подождите 5 минут.'})

    # Фиксируем попытки в базе
    record_rate_limit_attempt(current_user.id, '/api/telegram/send_code', f"dev_{device_id}")
    record_rate_limit_attempt(current_user.id, '/api/telegram/send_code', f"phone_{phone}")
    record_rate_limit_attempt(current_user.id, '/api/telegram/send_code', f"ip_{ip_addr}")
    
    logger.info(f"API запрос на отправку кода: {phone}")
    
    try:
        manager = get_user_telegram_manager(current_user.id)
        result = manager.send_code_request(phone)
        if result['success']:
            # Сохраняем в сессию для "умного возврата" и повторной отправки
            session['tg_phone'] = phone
            session['tg_phone_code_hash'] = result['phone_code_hash']
            session['tg_last_send_time'] = time.time()
            session.modified = True
            
            # Удаляем старые хеши этого устройства для этого пользователя
            AuthCodeHash.query.filter_by(user_id=current_user.id, device_id=device_id).delete()
            
            # Сохраняем новый хеш с привязкой к устройству
            new_hash = AuthCodeHash(
                user_id=current_user.id,
                device_id=device_id,
                phone=phone,
                phone_code_hash=result['phone_code_hash']
            )
            db.session.add(new_hash)
            db.session.commit()
            
            logger.info(f"Код успешно отправлен на: {phone} (устройство: {device_id})")
            logger.log_response('/api/telegram/send_code', 200, 'Код отправлен')
        else:
            logger.error(f"Ошибка отправки кода: {result.get('error')}")
            logger.log_response('/api/telegram/send_code', 500, result.get('error'))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Исключение при отправке кода: {e}")
        logger.log_response('/api/telegram/send_code', 500, str(e))
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/telegram/resend_code', methods=['POST'])
@login_required
def resend_telegram_code():
    phone = session.get('tg_phone')
    device_id = session.get('device_id', 'default')
    last_send = session.get('tg_last_send_time', 0)
    
    if not phone:
        return jsonify({'success': False, 'error': 'Сессия истекла или номер не указан'})
        
    # Проверка интервала 60 секунд на бэкенде
    if time.time() - last_send < 60:
        remaining = int(60 - (time.time() - last_send))
        return jsonify({'success': False, 'error': f'Подождите еще {remaining} сек. перед повторной отправкой'})

    # Лимиты
    if not check_rate_limit(current_user.id, '/api/telegram/resend_code', f"phone_{phone}", limit=3, period=300):
        return jsonify({'success': False, 'error': 'Слишком много попыток. Подождите 5 минут.'})

    record_rate_limit_attempt(current_user.id, '/api/telegram/resend_code', f"phone_{phone}")
    
    try:
        manager = get_user_telegram_manager(current_user.id)
        # Используем resend_code если есть в клиенте, иначе обычный запрос
        result = manager.send_code_request(phone)
        if result['success']:
            session['tg_phone_code_hash'] = result['phone_code_hash']
            session['tg_last_send_time'] = time.time()
            session.modified = True
            
            # Обновляем в базе для совместимости
            AuthCodeHash.query.filter_by(user_id=current_user.id, device_id=device_id).delete()
            new_hash = AuthCodeHash(
                user_id=current_user.id,
                phone=phone,
                device_id=device_id,
                phone_code_hash=result['phone_code_hash']
            )
            db.session.add(new_hash)
            db.session.commit()
            
            return jsonify({'success': True})
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/telegram/verify_code', methods=['POST'])
@login_required
def verify_telegram_code():
    device_id = session.get('device_id', 'default')
    
    # Лимит на ВВОД КОДА на УСТРОЙСТВО: 10 раз в 5 минут
    if not check_rate_limit(current_user.id, '/api/telegram/verify_code', f"dev_{device_id}", limit=10, period=300):
        return jsonify({'success': False, 'error': 'Слишком много попыток с вашего устройства. Подождите 5 минут.'})
    
    # Фиксируем попытку ввода для устройства
    record_rate_limit_attempt(current_user.id, '/api/telegram/verify_code', f"dev_{device_id}")
    
    data = request.json
    code = data.get('code')
    password = data.get('password')
    
    # Ищем хеш именно для этого устройства
    auth_record = AuthCodeHash.query.filter_by(
        user_id=current_user.id, 
        device_id=device_id
    ).order_by(AuthCodeHash.created_at.desc()).first()
    
    if not auth_record:
        logger.warning(f"Данные авторизации не найдены для устройства: {device_id}")
        return jsonify({'success': False, 'error': 'Сессия истекла или не найдена. Запросите код заново.'})
        
    phone = auth_record.phone
    phone_code_hash = auth_record.phone_code_hash

    # Лимит на ВВОД КОДА для конкретного НОМЕРА: 5 раз в 5 минут
    if not check_rate_limit(current_user.id, '/api/telegram/verify_code', f"phone_{phone}", limit=5, period=300):
        return jsonify({'success': False, 'error': f'Слишком много неверных попыток для номера {phone}. Подождите 5 минут.'})

    # Фиксируем попытку ввода для номера
    record_rate_limit_attempt(current_user.id, '/api/telegram/verify_code', f"phone_{phone}")
    
    logger.log_request('/api/telegram/verify_code', 'POST', data={'code': code, 'phone': phone, 'has_password': bool(password)})
    logger.info(f"API запрос на проверку кода/пароля для: {phone}")
    
    if not (code or password) or not phone:
        logger.warning("Отсутствуют обязательные данные для проверки")
        logger.log_response('/api/telegram/verify_code', 400, 'Missing required data')
        return jsonify({'success': False, 'error': 'Missing required data'})
    
    try:
        manager = get_user_telegram_manager(current_user.id)
        result = manager.sign_in(phone, code, phone_code_hash, password=password)
        
        if result['success']:
            # Валидация владельца при первой привязке или перепривязке
            try:
                me = manager._run_async(manager.client.get_me(), timeout=20)
                # Обновляем отображаемое имя в сессии и базе
                tg_display_name = manager._get_display_name(me)
                current_user.telegram_username = tg_display_name
                db.session.commit()
            except Exception as e:
                logger.error(f"Ошибка при получении данных пользователя Telegram: {e}")
                # Если не удалось получить me, но sign_in успешен, продолжаем с минимальными данными
                return jsonify({'success': True, 'message': 'Авторизован, но данные профиля загружаются...'})
            
            # Позволяем пользователю перепривязывать аккаунт
            if current_user.telegram_id and current_user.telegram_id != me.id:
                logger.info(f"User {current_user.id} changing TG link from {current_user.telegram_id} to {me.id}")
            
            tg_display_name = f"@{me.username}" if me.username else f"{me.first_name} {me.last_name or ''}".strip()
            
            # Update session with current Telegram name for header display
            session['telegram_username'] = tg_display_name
            
            current_user.telegram_authorized = True
            current_user.telegram_id = me.id
            current_user.telegram_username = tg_display_name
            session['telegram_authorized'] = True
            
            # Очищаем временный хеш после успешного входа
            AuthCodeHash.query.filter_by(user_id=current_user.id, device_id=device_id).delete()
            
            db.session.commit()
            logger.info(f"Успешная авторизация в Telegram для: {phone}, ID: {me.id}")
            logger.log_response('/api/telegram/verify_code', 200, 'Авторизация успешна')
        elif result.get('need_password'):
            logger.info(f"Для пользователя {phone} требуется пароль 2FA")
            logger.log_response('/api/telegram/verify_code', 200, 'Need 2FA password')
            return jsonify({'success': False, 'error': 'Требуется пароль двухфакторной аутентификации', 'need_password': True})
        else:
            logger.error(f"Ошибка верификации: {result.get('error')}")
            logger.log_response('/api/telegram/verify_code', 401, result.get('error'))
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Исключение при верификации: {e}")
        logger.log_response('/api/telegram/verify_code', 500, str(e))
        return jsonify({'success': False, 'error': str(e)})


@app.route('/contacts')
@login_required
def contacts():
    """Страница контактов"""
    manager = get_user_telegram_manager(current_user.id)
    if not manager.is_authorized():
        logger.info(f"User {current_user.id} not authorized, redirecting to auth")
        return redirect(url_for('telegram_auth'))
    return render_template('contacts.html')


@app.route('/api/telegram/contacts')
@login_required
@telegram_auth_required
def get_contacts():
    logger.log_request('/api/telegram/contacts', 'GET')
    logger.info("API запрос на получение контактов")
    
    try:
        manager = get_user_telegram_manager(current_user.id)
        if not manager or not manager.is_authorized():
             return jsonify({'success': False, 'error': 'Telegram not authorized'})
        contacts = manager.get_contacts()
        logger.info(f"Контакты получены: {len(contacts)} шт")
        logger.log_response('/api/telegram/contacts', 200, f'Контактов: {len(contacts)}')
        return jsonify({'success': True, 'contacts': contacts})
    except Exception as e:
        logger.error(f"Ошибка получения контактов: {e}", exc_info=True)
        logger.log_response('/api/telegram/contacts', 500, str(e))
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/telegram/groups')
@login_required
@telegram_auth_required
def get_groups():
    logger.log_request('/api/telegram/groups', 'GET')
    logger.info("API запрос на получение групп")
    
    try:
        manager = get_user_telegram_manager(current_user.id)
        if not manager or not manager.is_authorized():
             return jsonify({'success': False, 'error': 'Telegram not authorized'})
        groups = manager.get_groups()
        logger.info(f"Группы получены: {len(groups)} шт")
        logger.log_response('/api/telegram/groups', 200, f'Групп: {len(groups)}')
        return jsonify({'success': True, 'groups': groups})
    except Exception as e:
        logger.error(f"Ошибка получения групп: {e}", exc_info=True)
        logger.log_response('/api/telegram/groups', 500, str(e))
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/telegram/channels')
@login_required
@telegram_auth_required
def get_channels():
    logger.log_request('/api/telegram/channels', 'GET')
    logger.info("API запрос на получение каналов")
    
    try:
        manager = get_user_telegram_manager(current_user.id)
        if not manager or not manager.is_authorized():
             return jsonify({'success': False, 'error': 'Telegram not authorized'})
        channels = manager.get_channels()
        logger.info(f"Каналы получены: {len(channels)} шт")
        logger.log_response('/api/telegram/channels', 200, f'Каналов: {len(channels)}')
        return jsonify({'success': True, 'channels': channels})
    except Exception as e:
        logger.error(f"Ошибка получения каналов: {e}", exc_info=True)
        logger.log_response('/api/telegram/channels', 500, str(e))
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/telegram/groups/<group_id>/topics')
@login_required
@telegram_auth_required
def get_group_topics(group_id):
    logger.log_request(f'/api/telegram/groups/{group_id}/topics', 'GET')
    logger.info(f"API запрос на получение топиков группы: {group_id}")
    
    try:
        manager = get_user_telegram_manager(current_user.id)
        # Используем исправленный метод, который возвращает словарь с флагом success
        result = manager.get_group_topics(group_id)
        
        if result.get('success'):
            topics = result.get('topics', [])
            logger.info(f"Топики получены: {len(topics)} шт")
            logger.log_response(f'/api/telegram/groups/{group_id}/topics', 200, f"Топиков: {len(topics)}")
            return jsonify({'success': True, 'topics': topics})
        else:
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"Ошибка получения топиков: {error_msg}")
            logger.log_response(f'/api/telegram/groups/{group_id}/topics', 500, error_msg)
            return jsonify({'success': False, 'error': error_msg, 'topics': []})
            
    except Exception as e:
        logger.error(f"Ошибка получения топиков: {e}")
        logger.log_response(f'/api/telegram/groups/{group_id}/topics', 500, str(e))
        return jsonify({'success': False, 'error': str(e), 'topics': []})




@app.route('/api/upload_image', methods=['POST'])
@login_required
@telegram_auth_required
def upload_image():
    logger.log_request('/api/upload_image', 'POST')
    
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No image file provided'})
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    # ПРОВЕРКА РАЗМЕРА ФАЙЛА (лимит 10МБ)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > 10 * 1024 * 1024:
        return jsonify({'success': False, 'error': 'Размер файла превышает 10МБ'})
    
    if file and allowed_file(file.filename):
        # Дополнительная проверка на MIME-тип через Pillow для безопасности
        try:
            from PIL import Image
            img = Image.open(file)
            # Проверка формата
            if img.format not in ['PNG', 'JPEG', 'GIF', 'WEBP']:
                 return jsonify({'success': False, 'error': 'Unsupported image format'})
            img.verify() # Проверка целостности
            file.seek(0)
            
            # Повторное открытие после verify (так как verify() закрывает файл или делает его негодным для дальнейшего чтения в PIL)
            img = Image.open(file)
            # Мы можем проверить размеры или другие параметры если нужно
            file.seek(0)
        except Exception:
            return jsonify({'success': False, 'error': 'Файл поврежден или не является допустимым изображением'})

        safe_name = secure_filename(file.filename)
        if not safe_name:
            safe_name = "image.png"
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        filename = f"{timestamp}{unique_id}_{safe_name}"
        
        # ПРОВЕРКА ИМЕНИ ФАЙЛА
        if not filename or '..' in filename or filename.startswith('/'):
             return jsonify({'success': False, 'error': 'Invalid filename'})
             
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        logger.info(f"Изображение загружено: {filepath}")
        return jsonify({'success': True, 'filepath': filepath, 'filename': filename})
    
    return jsonify({'success': False, 'error': 'Invalid file type'})

@app.route('/api/telegram/send_message', methods=['POST'])
@login_required
@telegram_auth_required
@csrf.exempt
def send_message():
    message_text = request.form.get('message') or (request.json.get('message') if request.is_json else None)
    recipient_ids = request.form.getlist('recipients[]') or (request.json.get('recipients', []) if request.is_json else [])
    idempotent_key = request.form.get('idempotent_key') or (request.json.get('idempotent_key') if request.is_json else None)
    
    logger.log_request('/api/telegram/send_message', 'POST', data={'recipients_count': len(recipient_ids), 'idempotent_key': idempotent_key})
    
    cached_response = check_idempotent_key(idempotent_key, '/api/telegram/send_message')
    if cached_response:
        response, status = cached_response if isinstance(cached_response, tuple) else (cached_response, 200)
        return jsonify(response), status
    
    if idempotent_key:
        mark_idempotent_processing(idempotent_key, '/api/telegram/send_message')
    
    recipients_data_str = request.form.get('recipients_data')
    recipients_data = []
    if recipients_data_str:
        try:
            recipients_data = json.loads(recipients_data_str)
        except json.JSONDecodeError:
            recipients_data = []
    
    image_paths = []
    if 'images[]' in request.files:
        files = request.files.getlist('images[]')
        for idx, file in enumerate(files):
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename or f"image_{idx}.png")
                import uuid
                unique_id = str(uuid.uuid4())[:8]
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = f"{timestamp}{idx}_{unique_id}_{filename}"
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(image_path)
                image_paths.append(image_path)
                logger.info(f"Изображение загружено: {image_path}")
    elif 'image' in request.files:
        file = request.files['image']
        if file and file.filename and allowed_file(file.filename):
            safe_name = secure_filename(file.filename)
            if not safe_name:
                safe_name = "image.png"
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + safe_name
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(image_path)
            image_paths.append(image_path)
            logger.info(f"Изображение загружено: {image_path}")
    
    image_position = request.form.get('image_position', 'top')
    
    logger.info(f"API запрос на массовую отправку: {len(recipient_ids)} получателей, {len(image_paths)} изображений, позиция: {image_position}")
    
    if not message_text or not recipient_ids:
        logger.warning("Отсутствуют обязательные данные для отправки")
        logger.log_response('/api/telegram/send_message', 400, 'Message and recipients required')
        error_response = {'success': False, 'error': 'Message and recipients required'}
        if idempotent_key:
            save_idempotent_response(idempotent_key, error_response)
        return jsonify(error_response), 400
    
    try:
        delay = config.get('messaging', {}).get('delay_between_messages', 2)
        min_delay_groups = config.get('messaging', {}).get('min_delay_for_groups', 5)
        
        logger.info(f"Начало отправки {len(recipient_ids)} сообщений...")
        
        manager = get_user_telegram_manager(current_user.id)
        if len(image_paths) > 1:
            results = manager.send_messages_bulk_with_images(
                recipient_ids, message_text, image_paths, delay=delay, min_delay_groups=min_delay_groups, recipients_data=recipients_data, image_position=image_position
            )
        elif len(image_paths) == 1:
            results = manager.send_messages_bulk_with_image(
                recipient_ids, message_text, image_paths[0], delay=delay, min_delay_groups=min_delay_groups, recipients_data=recipients_data, image_position=image_position
            )
        else:
            results = manager.send_messages_bulk(
                recipient_ids, message_text, delay=delay, min_delay_groups=min_delay_groups, recipients_data=recipients_data
            )
        
        logger.info("Сохранение результатов в базу данных...")
        image_paths_str = json.dumps(image_paths) if image_paths else None
        tg_username = session.get('telegram_username')
        
        for res in results:
            # Determine status based on success and potential blocking
            # Success is False if is_blocked is True
            is_blocked = res.get('is_blocked', False)
            success = res.get('success', False)
            
            status = 'sent'
            if not success or is_blocked:
                status = 'failed'
                
            log = MessageLog(
                user_id=current_user.id,
                recipient_id=str(res['entity_id']),
                recipient_name=res.get('entity_name', 'Unknown'),
                message_text=message_text,
                image_path=image_paths_str,
                status=status,
                error_message=res.get('error') if status == 'failed' else None,
                sent_at=res.get('sent_at') if res.get('sent_at') else datetime.utcnow(),
                telegram_username=tg_username
            )
            db.session.add(log)
        
        db.session.commit()
        logger.info("Результаты сохранены в БД")
        
        success_count = sum(1 for r in results if r['success'])
        logger.info(f"Итого отправлено: {success_count}/{len(results)}")
        logger.log_response('/api/telegram/send_message', 200, f'Успешно: {success_count}/{len(results)}')
        
        response_data = {
            'success': True,
            'sent': success_count,
            'total': len(results),
            'results': results
        }
        
        if idempotent_key:
            save_idempotent_response(idempotent_key, response_data)
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Критическая ошибка отправки сообщений: {e}")
        logger.log_response('/api/telegram/send_message', 500, str(e))
        db.session.rollback()
        error_response = {'success': False, 'error': str(e)}
        if idempotent_key:
            save_idempotent_response(idempotent_key, error_response)
        return jsonify(error_response), 500


@app.route('/scheduler')
@login_required
@telegram_auth_required
def scheduler_page():
    tasks = ScheduledTask.query.filter_by(user_id=current_user.id, is_active=True).order_by(ScheduledTask.created_at.desc()).all()
    return render_template('scheduler.html', tasks=tasks)


@app.route('/api/telegram/folders')
@login_required
@telegram_auth_required
def get_telegram_folders():
    """Эндпоинт для получения списка папок пользователя"""
    try:
        manager = get_user_telegram_manager(current_user.id)
        if not manager:
            return jsonify({'success': False, 'error': 'Telegram manager not initialized'})
        folders = manager.get_folders()
        return jsonify({'success': True, 'folders': folders})
    except Exception as e:
        logger.error(f"Ошибка API получения папок: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/telegram/folders/<int:folder_id>/chats')
@login_required
@telegram_auth_required
def get_telegram_folder_chats(folder_id):
    """Эндпоинt для получения чатов из конкретной папки"""
    try:
        manager = get_user_telegram_manager(current_user.id)
        chats = manager.get_folder_chats(folder_id)
        return jsonify({'success': True, 'chats': chats})
    except Exception as e:
        logger.error(f"Ошибка API получения чатов папки: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/settings')
@login_required
def settings():
    """Страница настроек"""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        current_config = json.load(f)
    
    return render_template('settings.html', config=current_config)


@app.route('/api/telegram/delete_session', methods=['POST'])
@login_required
def delete_telegram_session():
    """Эндпоинт для удаления текущей сессии Telegram"""
    logger.log_request('/api/telegram/delete_session', 'POST')
    try:
        user_id = current_user.id
        device_id = session.get('device_id')
        if not device_id:
            return jsonify({'success': False, 'error': 'Сессия не найдена'})
            
        session_name = f'session_user_{user_id}_{device_id}'
        
        # 1. Сбрасываем флаг авторизации в сессии Flask и в БД
        session['telegram_authorized'] = False
        current_user.telegram_authorized = False
        db.session.commit()
        
        # 2. Пытаемся корректно остановить менеджер, если он в памяти
        try:
            from telegram_client import _managers_cache, _managers_lock
            with _managers_lock:
                if session_name in _managers_cache:
                    manager = _managers_cache[session_name]
                    logger.info(f"Удаление сессии: принудительная остановка для {session_name}")
                    # disconnect() безопаснее чем logout() для кнопки "удалить сессию", 
                    # так как logout() может попытаться отправить запрос в TG API, что не нужно при удалении локальных файлов
                    try:
                        manager.disconnect()
                    except:
                        pass
                    del _managers_cache[session_name]
        except Exception as e:
            logger.warning(f"Ошибка при очистке менеджера из кэша: {e}")

        # 3. Удаляем файл сессии с диска
        session_base = os.path.join('sessions', session_name)
        deleted_count = 0
        for ext in ['', '.session', '.session-journal', '.session-wal', '.session-shm']:
            fpath = session_base + ext if ext else f"{session_base}.session"
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                    deleted_count += 1
                    logger.info(f"Файл {fpath} удален пользователем {user_id}")
                except Exception as e:
                    logger.error(f"Не удалось удалить файл {fpath}: {e}")

        return jsonify({'success': True, 'message': f'Сессия успешно удалена ({deleted_count} файлов). Пожалуйста, авторизуйтесь заново.'})
    except Exception as e:
        logger.error(f"Ошибка при удалении сессии: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/settings/cleanup_cache', methods=['POST'])
@login_required
def cleanup_cache_api():
    """Ручная очистка кэша изображений (только неиспользуемые и обработанные файлы)"""
    try:
        # Получаем все изображения, которые используются в ЛЮБЫХ задачах (активных или нет)
        # Мы оставляем оригиналы, если они могут понадобиться для истории
        all_tasks = ScheduledTask.query.all()
        used_files = set()
        for task in all_tasks:
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
        
        count = 0
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
             return jsonify({'success': True, 'message': 'Папка кэша пуста'})

        for f in os.listdir(upload_folder):
            # Если файл используется в какой-либо задаче - не трогаем его
            if f in used_files:
                continue
                
            file_path = os.path.join(upload_folder, f)
            if os.path.isfile(file_path):
                try:
                    os.remove(file_path)
                    count += 1
                except:
                    continue
        
        logger.info(f"Manual cleanup: removed {count} unused files from upload folder")
        return jsonify({'success': True, 'message': f'Очищено файлов: {count}'})
    except Exception as e:
        logger.error(f"Ошибка очистки кэша: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/settings/cleanup_tasks', methods=['POST'])
@login_required
def cleanup_tasks_api():
    """Ручная очистка выполненных задач текущего пользователя"""
    try:
        user_id = current_user.id
        
        # 1. Находим ID всех неактивных задач пользователя (завершенные или отмененные)
        inactive_tasks = ScheduledTask.query.filter_by(user_id=user_id, is_active=False).all()
        inactive_tasks_ids = [t.id for t in inactive_tasks]
        
        if not inactive_tasks_ids:
            # Даже если нет неактивных задач, пробуем удалить ручные логи
            manual_logs_deleted = MessageLog.query.filter(
                MessageLog.task_id.is_(None),
                MessageLog.user_id == user_id
            ).delete(synchronize_session=False)
            db.session.commit()
            
            if manual_logs_deleted > 0:
                return jsonify({'success': True, 'message': f'Задач нет, удалено ручных логов: {manual_logs_deleted}'})
            return jsonify({'success': True, 'message': 'Нет данных для удаления'})

        # 2. Удаляем связанные записи
        # Удаляем логи
        logs_deleted = MessageLog.query.filter(MessageLog.task_id.in_(inactive_tasks_ids)).delete(synchronize_session=False)
        
        # Удаляем временные слоты
        slots_deleted = ScheduledTimeSlot.query.filter(ScheduledTimeSlot.task_id.in_(inactive_tasks_ids)).delete(synchronize_session=False)
        
        # Удаляем сами задачи
        tasks_deleted = ScheduledTask.query.filter(ScheduledTask.id.in_(inactive_tasks_ids)).delete(synchronize_session=False)
        
        # 3. Удаляем ручные логи
        manual_logs_deleted = MessageLog.query.filter(
            MessageLog.task_id.is_(None),
            MessageLog.user_id == user_id
        ).delete(synchronize_session=False)
        
        db.session.commit()
        
        msg = f"Удалено задач: {tasks_deleted}, слотов: {slots_deleted}, записей журнала: {logs_deleted + manual_logs_deleted}"
        logger.info(f"Manual cleanup: {msg} for user {user_id}")
        return jsonify({'success': True, 'message': msg})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Ошибка ручной очистки: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/scheduler/create', methods=['POST'])
@login_required
@telegram_auth_required
def create_scheduled_task():
    message_text = request.form.get('message')
    recipient_ids_str = request.form.get('recipients')
    scheduled_times_str = request.form.get('scheduled_times')
    recipients_info_str = request.form.get('recipients_info')
    
    image_paths = []
    if 'images[]' in request.files:
        files = request.files.getlist('images[]')
        for idx, file in enumerate(files):
            if file and file.filename and allowed_file(file.filename):
                # Ensure the filename is safe and not empty
                safe_name = secure_filename(file.filename)
                if not safe_name:
                    safe_name = f"image_{idx}.png"
                import uuid
                unique_id = str(uuid.uuid4())[:8]
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = f"{timestamp}{idx}_{unique_id}_{safe_name}"
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(image_path)
                image_paths.append(image_path)
                logger.info(f"Изображение загружено для планировщика: {image_path}")
    elif 'image' in request.files:
        file = request.files['image']
        if file and file.filename and allowed_file(file.filename):
            safe_name = secure_filename(file.filename)
            if not safe_name:
                safe_name = "image.png"
            import uuid
            unique_id = str(uuid.uuid4())[:8]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = f"{timestamp}0_{unique_id}_{safe_name}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(image_path)
            image_paths.append(image_path)
            logger.info(f"Изображение загружено для планировщика: {image_path}")
    
    image_path_str = json.dumps(image_paths) if image_paths else None
    image_position = request.form.get('image_position', 'top')
    
    try:
        recipient_ids = json.loads(recipient_ids_str) if recipient_ids_str else []
        scheduled_times = json.loads(scheduled_times_str) if scheduled_times_str else []
        recipients_info = json.loads(recipients_info_str) if recipients_info_str else []
        
        MAX_RECIPIENTS_PER_TASK = 10000
        if len(recipient_ids) > MAX_RECIPIENTS_PER_TASK:
            logger.warning(f"Попытка создать задачу с {len(recipient_ids)} получателями (лимит: {MAX_RECIPIENTS_PER_TASK})")
            return jsonify({'success': False, 'error': f'Maximum {MAX_RECIPIENTS_PER_TASK} recipients per task allowed'})

        MAX_SLOTS_PER_TASK = 500
        if len(scheduled_times) > MAX_SLOTS_PER_TASK:
            logger.warning(f"Попытка создать задачу с {len(scheduled_times)} слотами (лимит: {MAX_SLOTS_PER_TASK})")
            return jsonify({'success': False, 'error': f'Maximum {MAX_SLOTS_PER_TASK} time slots per task allowed'})

        if len(recipient_ids) == 0:
            logger.warning("Попытка создать задачу с пустым списком получателей")
            return jsonify({'success': False, 'error': 'At least one recipient is required'})

        if len(scheduled_times) == 0:
            logger.warning("Попытка создать задачу с пустым списком времён")
            return jsonify({'success': False, 'error': 'At least one scheduled time is required'})
            
    except json.JSONDecodeError:
        return jsonify({'success': False, 'error': 'Invalid JSON data'})
    
    logger.log_request('/api/scheduler/create', 'POST', data={'recipients': len(recipient_ids), 'scheduled_times': len(scheduled_times)})
    logger.info(f"API запрос на создание задачи планировщика")
    logger.info(f"Параметры: Получателей: {len(recipient_ids)}, Слотов времени: {len(scheduled_times)}, Позиция изображений: {image_position}")
    
    if not all([message_text, recipient_ids, scheduled_times]):
        logger.warning("Отсутствуют обязательные поля для создания задачи")
        logger.log_response('/api/scheduler/create', 400, 'All fields are required')
        return jsonify({'success': False, 'error': 'All fields are required'})
    
    try:
        # Get offset from form data first, then cookie as fallback
        tz_offset_str = request.form.get('tz_offset')
        logger.info(f"Raw tz_offset from form: {tz_offset_str}")
        
        if tz_offset_str is not None:
            try:
                tz_offset = int(tz_offset_str)
                logger.info(f"Timezone offset used: {tz_offset} minutes (from form)")
            except:
                tz_offset = get_user_tz_offset_minutes()
                logger.info(f"Timezone offset used: {tz_offset} minutes (from cookie fallback)")
        else:
            tz_offset = get_user_tz_offset_minutes()
            logger.info(f"Timezone offset used: {tz_offset} minutes (from cookie)")
        
        utc_scheduled_times = []
        for dt_str in scheduled_times:
            # HTML5 datetime-local gives YYYY-MM-DDTHH:MM
            local_dt = datetime.strptime(dt_str, '%Y-%m-%dT%H:%M')
            # Standard Formula: UTC = Local - Offset (where offset is positive for East, like Moscow +180)
            # Example Moscow (UTC+3): Offset = 180. 20:45 - 180m = 17:45 UTC.
            utc_dt = local_dt - timedelta(minutes=tz_offset)
            # Store in DB-friendly format
            utc_scheduled_times.append(utc_dt.strftime('%Y-%m-%d %H:%M:%S'))
            logger.info(f"Time Sync Result: Local {dt_str} -> UTC {utc_dt} (Offset: {tz_offset}m)")
        
        # Получаем активную сессию для текущей задачи
        device_id = get_device_id()
        
        # Получаем текущую сессию для автоматического подхвата TelegramClient
        session_name = session.get('telegram_session_name')
        
        task = ScheduledTask()
        task.user_id=current_user.id
        task.message_text=message_text
        task.recipients=json.dumps(recipient_ids)
        task.recipients_info=json.dumps(recipients_info) if recipients_info else None
        task.image_path=image_path_str
        task.image_position=image_position if image_paths else 'top'
        task.scheduled_times=json.dumps(utc_scheduled_times)
        task.device_id=device_id
        task.session_name=session_name
        task.telegram_username=session.get('telegram_username', current_user.telegram_username)
        
        logger.info(f"Создание задачи в планировщике...")
        result = get_scheduler().add_task(task, utc_scheduled_times)
        
        # Пункт 3: Пробуждаем планировщик немедленно
        scheduler = get_scheduler()
        if scheduler and hasattr(scheduler, 'trigger_immediate_process'):
            scheduler.trigger_immediate_process()
        
        if result['success']:
            logger.info(f"Задача планировщика создана успешно. ID: {result.get('task_id')}")
            logger.log_scheduler_action("Создание задачи", task_id=result.get('task_id'), details=f"Получателей: {len(recipient_ids)}, Слотов: {len(scheduled_times)}")
        else:
            logger.error(f"Ошибка создания задачи: {result.get('error')}")
        
        logger.log_response('/api/scheduler/create', 200 if result['success'] else 500, result.get('error', 'Success'))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Исключение при создании задачи планировщика: {e}")
        logger.log_response('/api/scheduler/create', 500, str(e))
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/scheduler/tasks')
@login_required
@telegram_auth_required
def get_scheduled_tasks():
    try:
        db.session.expire_all()
        tasks = ScheduledTask.query.filter_by(user_id=current_user.id, is_active=True).order_by(ScheduledTask.created_at.desc()).all()
        all_tasks = ScheduledTask.query.filter_by(user_id=current_user.id).order_by(ScheduledTask.created_at.asc()).all()
        task_numbers = {task.id: i + 1 for i, task in enumerate(all_tasks)}
        result = []
        for task in tasks:
            slots = []
            for slot in task.time_slots.order_by(ScheduledTimeSlot.scheduled_datetime.asc()):
                slots.append({
                    'id': slot.id,
                    'datetime': slot.scheduled_datetime.isoformat(),
                    'status': slot.status,
                    'is_partial': slot.status == 'completed_with_errors',
                    'total': slot.total_recipients,
                    'processed': slot.processed_recipients,
                    'percentage': round((slot.processed_recipients / slot.total_recipients * 100), 1) if slot.total_recipients > 0 else 100
                })
            result.append({
                'id': task.id,
                'display_id': task_numbers.get(task.id, task.id),
                'message_text': task.message_text,
                'created_at': task.created_at.isoformat(),
                'has_image': bool(task.image_path),
                'telegram_account': task.telegram_username or 'Неизвестно',
                'slots': slots,
                'recipients_info': get_task_recipients_status(task.id)
            })
        return jsonify({'success': True, 'tasks': result})
    except Exception as e:
        logger.error(f"Error in get_scheduled_tasks: {e}")
        return jsonify({'success': False, 'error': str(e)})

def get_task_recipients_status(task_id):
    """Собирает актуальный статус по каждому получателю для задачи"""
    task = db.session.get(ScheduledTask, task_id)
    if not task:
        return []
    
    try:
        from models import SentMessage, ScheduledTimeSlot
        
        # 1. Получаем метаданные (имена) из recipients_info задачи
        recipients_meta = {}
        if task.recipients_info:
            try:
                meta_list = json.loads(task.recipients_info)
                for item in meta_list:
                    if isinstance(item, dict) and 'id' in item:
                        recipients_meta[str(item['id'])] = item.get('name') or item.get('title') or item.get('username')
            except:
                pass

        # 2. Получаем все записи из sent_messages для этой задачи
        # Используем join с ScheduledTimeSlot для фильтрации по задаче
        sent_messages = db.session.query(SentMessage).join(ScheduledTimeSlot).filter(
            ScheduledTimeSlot.task_id == task_id
        ).all()
        
        # Индексируем по recipient_id для быстрого поиска
        status_map = {sm.recipient_id: {'status': sm.status, 'error': sm.error_message} for sm in sent_messages}
        
        # 3. Определяем, отменена ли задача
        is_task_cancelled = task.was_cancelled
        
        # 4. Собираем итоговый список на основе исходного списка получателей
        recipients_ids = json.loads(task.recipients)
        
        result = []
        for r in recipients_ids:
            if isinstance(r, (str, int)):
                r_id = str(r)
            else:
                r_id = str(r.get('id'))
            
            info = status_map.get(r_id)
            if info:
                # Если запись в sent_messages есть - берем статус оттуда
                r_status = info['status']
                r_error = info['error']
                r_name = recipients_meta.get(r_id) or r_id
            else:
                # Если записи нет - статус зависит от отмены задачи
                r_status = 'cancelled' if is_task_cancelled else 'pending'
                r_error = None
                r_name = recipients_meta.get(r_id) or r_id
            
            result.append({
                'id': r_id,
                'name': r_name,
                'status': r_status,
                'error': r_error
            })
        return result
    except Exception as e:
        logger.error(f"Error gathering recipients status for task {task_id}: {e}")
        return []

@app.route('/api/scheduler/task/<int:task_id>/cancel', methods=['POST'])
@login_required
@telegram_auth_required
@csrf.exempt
def cancel_task(task_id):
    try:
        from sqlalchemy import text
        # 1️⃣ CANCEL must be atomic and idempotent
        sql_task = text("""
            UPDATE scheduled_tasks
            SET is_active = false, was_cancelled = true, cancelled_at = NOW()
            WHERE id = :task_id AND user_id = :user_id
            AND (is_active = true OR was_cancelled = false)
            RETURNING id
        """)
        result = db.session.execute(sql_task, {"task_id": task_id, "user_id": current_user.id})
        row = result.fetchone()

        if not row:
            return jsonify({"status": "already_cancelled"})
            
        # If it returned a row → task was active → then also cancel all slots
        sql_slots = text("""
            UPDATE scheduled_time_slots
            SET status = 'cancelled'
            WHERE task_id = :task_id AND status IN ('pending','executing')
        """)
        db.session.execute(sql_slots, {"task_id": task_id})
        db.session.commit()
        return jsonify({"status": "cancelled"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in cancel_task: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/scheduler/task/<int:task_id>/start', methods=['POST'])
@login_required
def start_task(task_id):
    try:
        from sqlalchemy import text
        # 2️⃣ START must be idempotent too
        sql_task = text("""
            UPDATE scheduled_tasks
            SET is_active = true, was_cancelled = false, cancelled_at = NULL
            WHERE id = :task_id AND user_id = :user_id AND is_active = false
            RETURNING id
        """)
        result = db.session.execute(sql_task, {"task_id": task_id, "user_id": current_user.id})
        row = result.fetchone()
        
        if not row:
            return jsonify({"status": "already_executing"})
            
        db.session.commit()
        # Trigger scheduler to pick up the task
        scheduler = get_scheduler()
        if scheduler:
            scheduler.trigger_immediate_process()
            
        return jsonify({"status": "started"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in start_task: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/scheduler/completed')
@login_required
@telegram_auth_required
def get_completed_tasks():
    try:
        tasks = ScheduledTask.query.filter(
            ScheduledTask.user_id == current_user.id,
            ((ScheduledTask.is_active == False) | (ScheduledTask.was_cancelled == True))
        ).order_by(ScheduledTask.created_at.desc()).limit(20).all()
        
        # Получаем порядковые номера для всех задач пользователя
        all_tasks_ordered = ScheduledTask.query.filter_by(user_id=current_user.id).order_by(ScheduledTask.created_at.asc()).all()
        task_numbers = {task.id: i + 1 for i, task in enumerate(all_tasks_ordered)}
        
        result = []
        for task in tasks:
            # Считаем статистику по слотам
            slots = task.time_slots.all()
            total_slots = len(slots)
            sent_slots = sum(1 for s in slots if s.status == 'completed')
            
            # Определяем время завершения (последний отправленный слот)
            completed_at = None
            if slots:
                sent_at_list = [s.sent_at for s in slots if s.sent_at]
                if sent_at_list:
                    completed_at = max(sent_at_list).isoformat()
            
            # Считаем успешные отправки из логов
            success_count = db.session.query(MessageLog).filter_by(task_id=task.id, status='sent').count()
            recipients = json.loads(task.recipients) if task.recipients else []
            recipients_count = len(recipients)
            
            # Определяем общий статус задачи
            status = 'completed'
            if task.was_cancelled:
                status = 'cancelled'
            elif any(s.status == 'failed' for s in slots):
                status = 'failed'
            elif any(s.status == 'completed_with_errors' for s in slots):
                status = 'completed_with_errors'
            elif any(s.status in ['pending', 'executing'] for s in slots):
                status = 'executing'

            result.append({
                'id': task.id,
                'global_order': task_numbers.get(task.id),
                'message_text': task.message_text,
                'created_at': task.created_at.isoformat(),
                'completed_at': completed_at,
                'was_cancelled': task.was_cancelled,
                'telegram_account': task.telegram_username or 'Неизвестно',
                'success_count': success_count,
                'recipients_count': recipients_count,
                'status': status,
                'times_sent': task.times_sent,
                'sent_slots': sent_slots,
                'total_slots': total_slots,
                'has_image': bool(task.image_path),
                'is_scheduled': True, # Это задачи из планировщика
                'recipients_info': get_task_recipients_status(task.id),
                'time_slots': [{
                    'id': s.id,
                    'datetime': s.scheduled_datetime.isoformat(),
                    'is_sent': s.status == 'completed',
                    'is_partial': s.status == 'completed_with_errors',
                    'status': s.status,
                    'has_error': s.status in ['failed', 'completed_with_errors'],
                    'sent_at': s.sent_at.isoformat() if s.sent_at else None
                } for s in slots]
            })
        return jsonify({'success': True, 'tasks': result})
    except Exception as e:
        logger.error(f"Ошибка получения выполненных задач: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/slot/<int:slot_id>/recipients-status')
@login_required
def get_slot_recipients_status(slot_id):
    """Получить детальную информацию о статусе отправки сообщений для конкретного слота"""
    try:
        from models import SentMessage
        
        # Получаем слот и проверяем права доступа
        slot = ScheduledTimeSlot.query.get(slot_id)
        if not slot:
            return jsonify({'success': False, 'error': 'Slot not found'}), 404
        
        # Проверяем, что слот принадлежит задаче текущего пользователя
        task = ScheduledTask.query.filter_by(id=slot.task_id, user_id=current_user.id).first()
        if not task:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Получаем информацию о слоте
        slot_info = {
            'id': slot.id,
            'task_id': slot.task_id,
            'scheduled_datetime': slot.scheduled_datetime.isoformat(),
            'status': slot.status,
            'total_recipients': slot.total_recipients,
            'processed_recipients': slot.processed_recipients,
            'percentage': int((slot.processed_recipients / slot.total_recipients * 100) if slot.total_recipients > 0 else 0)
        }
        
        # Получаем все SentMessage записи для этого слота
        sent_messages = SentMessage.query.filter_by(slot_id=slot_id).all()
        sent_map = {sm.recipient_id: sm for sm in sent_messages}
        
        # Получаем информацию о получателях из задачи
        recipients_info = {}
        if task.recipients_info:
            try:
                meta_list = json.loads(task.recipients_info)
                for item in meta_list:
                    if isinstance(item, dict) and 'id' in item:
                        recipients_info[str(item['id'])] = item.get('name') or item.get('title') or item.get('username') or str(item['id'])
            except:
                pass
        
        # Получаем список всех получателей
        recipients_list = []
        if task.recipients:
            try:
                recipients_ids = json.loads(task.recipients)
            except:
                recipients_ids = []
        else:
            recipients_ids = []
        
        # Формируем список получателей с их статусами
        for r in recipients_ids:
            if isinstance(r, (str, int)):
                r_id = str(r)
            elif isinstance(r, dict):
                r_id = str(r.get('id', 'unknown'))
            else:
                continue
            
            # Получаем имя получателя
            r_name = recipients_info.get(r_id, r_id)
            
            # Получаем статус из sent_messages
            sent_msg = sent_map.get(r_id)
            if sent_msg:
                status = sent_msg.status
                sent_at = sent_msg.sent_at.isoformat() if sent_msg.sent_at else None
                error_message = sent_msg.error_message
            else:
                # Если записи нет, статус зависит от статуса слота и задачи
                if task.was_cancelled or slot.status == 'cancelled':
                    status = 'cancelled'
                elif slot.status in ['pending', 'executing']:
                    status = 'pending'
                else:
                    status = 'pending'
                sent_at = None
                error_message = None
            
            recipients_list.append({
                'recipient_id': r_id,
                'name': r_name,
                'status': status,
                'sent_at': sent_at,
                'error_message': error_message
            })
        
        return jsonify({
            'success': True,
            'slot': slot_info,
            'recipients': recipients_list
        })
    except Exception as e:
        logger.error(f"Error getting slot recipients status: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scheduler/delete/<int:task_id>', methods=['DELETE'])
@login_required
@telegram_auth_required
@csrf.exempt
def delete_scheduled_task(task_id):
    try:
        # Проверка прав собственности: пользователь может удалять только свои задачи
        task = ScheduledTask.query.filter_by(id=task_id, user_id=current_user.id).first()
        if not task:
            return jsonify({'success': False, 'error': 'Task not found or access denied'}), 404
            
        from sqlalchemy import text
        
        # 1. Получаем все slot_id для этой задачи
        slot_ids = db.session.execute(
            text("SELECT id FROM scheduled_time_slots WHERE task_id = :task_id"),
            {"task_id": task_id}
        ).fetchall()
        slot_ids = [s[0] for s in slot_ids]
        
        # 2. Удаляем SentMessage для всех слотов этой задачи (было добавлено для исправления ForeignKeyViolation)
        if slot_ids:
            db.session.execute(
                text("DELETE FROM sent_messages WHERE slot_id = ANY(:slot_ids)"),
                {"slot_ids": slot_ids}
            )
        
        # 3. Удаляем MessageLog для слотов этой задачи
        db.session.execute(
            text("DELETE FROM message_logs WHERE slot_id IN (SELECT id FROM scheduled_time_slots WHERE task_id = :task_id)"),
            {"task_id": task_id}
        )
        
        # 4. Удаляем временные слоты
        ScheduledTimeSlot.query.filter_by(task_id=task_id).delete(synchronize_session=False)
        
        # 5. Удаляем из планировщика (если она там есть)
        get_scheduler().remove_task(task_id)
        
        # 6. Удаляем саму задачу
        db.session.delete(task)
        db.session.commit()
        
        logger.log_scheduler_action("Удаление задачи", task_id=task_id, details="Success")
        return jsonify({'success': True})
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting task {task_id}: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/scheduler/toggle/<int:task_id>', methods=['POST'])
@login_required
@telegram_auth_required
def toggle_scheduled_task(task_id):
    try:
        # Защита от перебора ID
        task = ScheduledTask.query.filter_by(id=task_id, user_id=current_user.id).first()
        if not task:
            return jsonify({'success': False, 'error': 'Task not found or access denied'}), 404

        is_active = request.form.get('is_active') == 'true'
        task.is_active = is_active
        db.session.commit()
        
        status_text = "активирована" if is_active else "деактивирована"
        logger.log_scheduler_action("Изменение статуса", task_id=task_id, details=f"Задача {status_text}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error toggling task {task_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/telegram/groups/<int:group_id>/v2/topics')
@login_required
@telegram_auth_required
def get_group_topics_v2(group_id):
    try:
        manager = get_user_telegram_manager(current_user.id)
        result = manager.get_group_topics(group_id)
        if isinstance(result, dict) and result.get('success'):
            return jsonify(result)
        elif isinstance(result, list):
            # Обработка случая, если метод вернул просто список (для обратной совместимости)
            return jsonify({'success': True, 'topics': result})
        else:
            error_msg = result.get('error', 'Unknown error') if isinstance(result, dict) else 'Failed to get topics'
            return jsonify({'success': False, 'error': error_msg}), 500
    except Exception as e:
        logger.error(f"Ошибка получения топиков V2: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/logs')
@login_required
def logs_page():
    # Use absolute path relative to current file to ensure correct file access
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_file_path = os.path.join(base_dir, 'logs', 'all_logs.txt')
    
    app_logger.debug(f"Reading logs from: {log_file_path}")
    
    logs_content = ""
    if os.path.exists(log_file_path):
        try:
            # Open with buffering=0 not supported for text mode, but we use standard open
            with open(log_file_path, 'r', encoding='utf-8') as f:
                # Читаем строки и фильтруем технический шум для отображения на сайте
                all_lines = f.readlines()
                filtered_lines = [
                    line for line in all_lines 
                    if "Добавлен контакт:" not in line 
                    and "Добавлена группа:" not in line 
                    and "Добавлен канал:" not in line
                ]
                # Ограничиваем количество строк для безопасности вывода
                logs_content = "".join(filtered_lines[-1000:])
        except Exception as e:
            logs_content = f"Ошибка чтения логов: {e}"
    else:
        logs_content = f"Файл логов не найден по пути: {log_file_path}"
    
    from markupsafe import escape
    return render_template('logs.html', logs_content=escape(logs_content))

def systemd_heartbeat():
    if "WATCHDOG_USEC" not in os.environ:
        return

    interval = int(os.environ["WATCHDOG_USEC"]) / 2 / 1_000_000
    while True:
        try:
            os.system("systemd-notify WATCHDOG=1")
        except Exception:
            pass
        time.sleep(interval)

threading.Thread(target=systemd_heartbeat, daemon=True).start()



@app.route("/health")
def health():
    return {
        "status": "ok",
        "service": "densite",
    }, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
