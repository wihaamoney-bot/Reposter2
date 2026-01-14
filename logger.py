import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler


class CustomLogger:
    """Кастомный логгер с записью в файлы по датам"""
    
    def _setup_handlers(self):
        """Инициализация или переинициализация обработчиков логов"""
        # Очищаем существующие обработчики
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)

        # Формат логов
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Файл для всех логов (legacy)
        all_logs_file = os.path.join(self.log_dir, 'all_logs.txt')
        all_handler = RotatingFileHandler(
            all_logs_file,
            maxBytes=10*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        all_handler.setLevel(logging.DEBUG)
        all_handler.setFormatter(formatter)
        self.logger.addHandler(all_handler)

        # Файл для отладочных логов (DEBUG+)
        debug_logs_file = os.path.join(self.log_dir, 'debug.txt')
        debug_handler = RotatingFileHandler(
            debug_logs_file,
            maxBytes=10*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(formatter)
        self.logger.addHandler(debug_handler)

        # Файл для ошибок (ERROR+)
        error_logs_file = os.path.join(self.log_dir, 'errors.txt')
        error_handler = RotatingFileHandler(
            error_logs_file,
            maxBytes=10*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        self.logger.addHandler(error_handler)

        # Файл для логов за сегодня
        today = datetime.now().strftime('%Y-%m-%d')
        daily_logs_file = os.path.join(self.log_dir, f'log_{today}.txt')
        daily_handler = RotatingFileHandler(
            daily_logs_file,
            maxBytes=10*1024*1024,
            backupCount=1,
            encoding='utf-8'
        )
        daily_handler.setLevel(logging.INFO)
        daily_handler.setFormatter(formatter)
        self.logger.addHandler(daily_handler)

        # Консольный вывод
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def __init__(self, name='telegram_sender', log_dir='logs'):
        self.name = name
        
        # Ensure log directory is absolute
        if not os.path.isabs(log_dir):
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), log_dir)
        self.log_dir = log_dir
        
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False  # Предотвращаем дублирование в консоли
        
        self._setup_handlers()

    def _ensure_dir(self):
        """Проверяет существование директории логов и файлов, пересоздает их при необходимости"""
        try:
            # 1. Проверяем наличие папки
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)

            # 2. Проверяем, живы ли файлы всех обработчиков
            need_reinit = False
            for handler in self.logger.handlers:
                if isinstance(handler, RotatingFileHandler):
                    # Проверяем, существует ли файл, на который смотрит обработчик
                    if not os.path.exists(handler.baseFilename):
                        need_reinit = True
                        break
            
            # 3. Если хоть один файл пропал, пересобираем обработчики
            if need_reinit:
                self._setup_handlers()
        except Exception:
            pass

    def _log(self, level, msg, *args, **kwargs):
        self._ensure_dir()
        exc_info = kwargs.pop('exc_info', None)
        stack_info = kwargs.pop('stack_info', None)
        extra = kwargs.pop('extra', None)
        self.logger.log(
            level,
            self._format_message(msg, kwargs),
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            extra=extra,
        )

    def debug(self, msg, *args, **kwargs):
        """Debug уровень"""
        self._log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        """Info уровень"""
        self._log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """Warning уровень"""
        self._log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """Error уровень"""
        self._log(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        """Critical уровень"""
        self._log(logging.CRITICAL, msg, *args, **kwargs)
    
    def _format_message(self, message, kwargs):
        """Форматирование сообщения с дополнительными данными"""
        if not kwargs:
            return message
            
        # Убираем exc_info и stack_info из формирования строки, так как они обрабатываются логгером отдельно
        extra_data = {k: v for k, v in kwargs.items() if k not in ('exc_info', 'stack_info', 'extra')}
        
        if extra_data:
            extra_info = ' | '.join([f"{k}={v}" for k, v in extra_data.items()])
            return f"{message} | {extra_info}"
        return message
    
    def log_request(self, endpoint, method='GET', data=None, user=None):
        """Логирование HTTP запроса"""
        msg = f"REQUEST: {method} {endpoint}"
        kwargs = {}
        if user:
            kwargs['user'] = user
        if data:
            kwargs['data'] = str(data)[:200]  # Ограничиваем длину
        self.info(msg, **kwargs)
    
    def log_response(self, endpoint, status_code, response_message=None):
        """Логирование HTTP ответа"""
        msg = f"RESPONSE: {endpoint} - Status: {status_code}"
        if response_message:
            self.info(msg, response=response_message)
        else:
            self.info(msg)
    
    def log_telegram_action(self, action, details=None, success=True):
        """Логирование действий с Telegram API"""
        level = 'SUCCESS' if success else 'FAILED'
        msg = f"TELEGRAM {level}: {action}"
        if details:
            self.info(msg, details=str(details))
        else:
            self.info(msg)
    
    def log_scheduler_action(self, action, task_id=None, details=None):
        """Логирование действий планировщика"""
        msg = f"SCHEDULER: {action}"
        kwargs = {}
        if task_id:
            kwargs['task_id'] = task_id
        if details:
            kwargs['details'] = details
        self.info(msg, **kwargs)


# Глобальный экземпляр логгера
app_logger = None


def init_logger(name='telegram_sender', log_dir='logs'):
    """Инициализация глобального логгера"""
    global app_logger
    if app_logger is None:
        app_logger = CustomLogger(name, log_dir)
    return app_logger


def get_logger(name='telegram_sender', log_dir='logs'):
    """Получить глобальный логгер"""
    global app_logger

    normalized_log_dir = log_dir
    if not os.path.isabs(normalized_log_dir):
        normalized_log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), normalized_log_dir)

    if app_logger is None:
        app_logger = CustomLogger(name, log_dir)
    else:
        current_log_dir = getattr(app_logger, 'log_dir', None)
        if getattr(app_logger, 'name', None) != name or current_log_dir != normalized_log_dir:
            app_logger = CustomLogger(name, log_dir)
    return app_logger
