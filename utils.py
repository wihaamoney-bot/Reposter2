import json
import os
import re
import secrets
from datetime import datetime, timedelta
from flask import request, session, current_app

def allowed_file(filename):
    """Check if file extension is allowed."""
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def validate_phone(phone):
    """
    Валидация номера телефона

    SECURITY: Prevents injection and validates phone format
    Format: +<10-15 digits>
    Examples: +1234567890, +123456789012345

    Args:
        phone: Phone number string

    Returns:
        bool: True if valid

    Raises:
        ValueError: If phone format is invalid
    """
    if not phone or not isinstance(phone, str):
        raise ValueError("Номер телефона обязателен")

    phone = phone.strip()

    # Проверяем формат: + followed by 10-15 digits
    pattern = r'^\+\d{10,15}$'
    if not re.match(pattern, phone):
        raise ValueError("Неверный формат номера телефона. Используйте формат: +XXXXXXXXXX (от 10 до 15 цифр)")

    return True


def validate_code(code):
    """
    Валидация кода подтверждения

    SECURITY: Validates Telegram 2FA code format
    Format: 5-6 digits only

    Args:
        code: Verification code string

    Returns:
        bool: True if valid

    Raises:
        ValueError: If code format is invalid
    """
    if not code or not isinstance(code, str):
        raise ValueError("Код подтверждения обязателен")

    code = code.strip()

    # Проверяем длину (5-6 символов)
    if len(code) < 5 or len(code) > 6:
        raise ValueError("Код должен содержать 5 или 6 цифр")

    # Проверяем, что это только цифры
    if not code.isdigit():
        raise ValueError("Код должен содержать только цифры")

    return True


def validate_2fa_password(password):
    """
    Валидация пароля 2FA

    SECURITY: Validates 2FA password input

    Args:
        password: 2FA password string

    Returns:
        bool: True if valid

    Raises:
        ValueError: If password is invalid
    """
    if password is None:
        return False  # Password is optional (only required if account has 2FA)

    if not isinstance(password, str):
        raise ValueError("Пароль должен быть строкой")

    password = password.strip()

    # Не допускаем пустой пароль (но None допустим для проверки наличия 2FA)
    if password == '':
        return False

    # Максимальная длина 256 символов
    if len(password) > 256:
        raise ValueError("Пароль слишком длинный (максимум 256 символов)")

    return True


def get_user_tz_offset_minutes():
    """Get user's timezone offset from cookie (in minutes)."""
    try:
        # Check if we are in a request context
        from flask import has_request_context
        if not has_request_context():
            return 0

        tz_offset = request.cookies.get('tz_offset')
        if tz_offset is not None:
            return int(tz_offset)

        # Fallback to a default if cookie is missing
        return 0
    except Exception as e:
        return 0


def local_to_utc(local_dt, tz_offset_minutes=None):
    """
    Convert local datetime to UTC using timezone offset from JS.
    We use offset in minutes where UTC+3 is +180 (standard).
    Formula: UTC = Local - Offset_Minutes
    Example Moscow: 20:45 - (+180 min) = 17:45 UTC (Correct)
    """
    if tz_offset_minutes is None:
        tz_offset_minutes = get_user_tz_offset_minutes()
    return local_dt - timedelta(minutes=tz_offset_minutes)


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


def get_device_id():
    """Get or create device_id for the current session/request."""
    device_id = session.get('device_id')
    if not device_id:
        device_id = request.cookies.get('device_id')
    if not device_id:
        device_id = secrets.token_hex(8)
        session['device_id'] = device_id
        session.modified = True
    return device_id
