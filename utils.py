import json
import os
import secrets
from datetime import datetime, timedelta
from flask import request, session, current_app

def allowed_file(filename):
    """Check if file extension is allowed."""
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

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
