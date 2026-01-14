from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model, UserMixin):
    """Модель пользователя для управления сессиями"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    telegram_authorized = db.Column(db.Boolean, default=False)
    telegram_phone = db.Column(db.String(20), nullable=True)
    telegram_username = db.Column(db.String(100), nullable=True)
    telegram_id = db.Column(db.BigInteger, nullable=True)
    phone_code_hash = db.Column(db.String(100), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class ScheduledTask(db.Model):
    """Модель для хранения запланированных задач отправки сообщений"""
    __tablename__ = 'scheduled_tasks'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    message_text = db.Column(db.Text, nullable=False)
    recipients = db.Column(db.Text, nullable=False)
    recipients_info = db.Column(db.Text, nullable=True)
    image_path = db.Column(db.String(500), nullable=True)
    image_position = db.Column(db.String(20), default='top')
    scheduled_times = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    was_cancelled = db.Column(db.Boolean, default=False, index=True)
    cancelled_at = db.Column(db.DateTime, nullable=True)
    times_sent = db.Column(db.Integer, default=0)
    session_name = db.Column(db.String(255), nullable=True)
    device_id = db.Column(db.String(50), nullable=True, default='default')
    telegram_username = db.Column(db.String(100), nullable=True)

    user = db.relationship('User', backref=db.backref('scheduled_tasks', lazy='dynamic'))

    def __repr__(self):
        return f'<ScheduledTask {self.id}: {self.message_text[:30]}...>'


class ScheduledTimeSlot(db.Model):
    """Модель для хранения конкретных времен отправки и прогресса выполнения слота"""
    __tablename__ = 'scheduled_time_slots'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scheduled_tasks.id'), nullable=False, index=True)
    scheduled_datetime = db.Column(db.DateTime, nullable=False, index=True)
    
    # Новые поля для прогресса и управления отменой на уровне слота
    # pending - ожидает выполнения
    # executing - слот в процессе отправки
    # completed - все сообщения отправлены успешно
    # completed_with_errors - отправлены с ошибками
    # cancelled - отменено
    # failed - критическая ошибка
    status = db.Column(db.String(30), default='pending', index=True) 
    total_recipients = db.Column(db.Integer, default=0)
    processed_recipients = db.Column(db.Integer, default=0)
    last_heartbeat = db.Column(db.DateTime, nullable=True)
    
    is_sent = db.Column(db.Boolean, default=False, index=True) # Оставляем для совместимости, но логика переходит на status
    sent_at = db.Column(db.DateTime, nullable=True)

    task = db.relationship('ScheduledTask', backref=db.backref('time_slots', lazy='dynamic'))

    def __repr__(self):
        return f'<ScheduledTimeSlot {self.id}: {self.scheduled_datetime} status={self.status}>'


class MessageLog(db.Model):
    """Логи отправленных сообщений"""
    __tablename__ = 'message_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scheduled_tasks.id'), nullable=True)
    slot_id = db.Column(db.Integer, db.ForeignKey('scheduled_time_slots.id'), nullable=True) # Привязка к конкретному слоту
    
    recipient_id = db.Column(db.String(100), nullable=False)
    recipient_name = db.Column(db.String(200))
    message_text = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(500), nullable=True)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(50), default='sent', index=True) # sent, failed, cancelled
    error_message = db.Column(db.Text)
    telegram_username = db.Column(db.String(100), nullable=True)

    user = db.relationship('User', backref=db.backref('message_logs', lazy='dynamic'))
    task = db.relationship('ScheduledTask', backref=db.backref('logs', lazy='dynamic'))
    slot = db.relationship('ScheduledTimeSlot', backref=db.backref('logs', lazy='dynamic'))

    def __repr__(self):
        return f'<MessageLog {self.id}: {self.recipient_name} at {self.sent_at}>'


class IdempotentRequest(db.Model):
    """Таблица для отслеживания идемпотентных ключей и контроля лимитов (Rate Limiting)"""
    __tablename__ = 'idempotent_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    idempotent_key = db.Column(db.String(255), nullable=False, unique=True, index=True)
    endpoint = db.Column(db.String(255), nullable=False)
    target_identifier = db.Column(db.String(255), nullable=True, index=True)
    response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_processing = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<IdempotentRequest {self.idempotent_key} target={self.target_identifier}>'


class AuthCodeHash(db.Model):
    """Таблица для временного хранения хешей кода подтверждения с привязкой к сессии"""
    __tablename__ = 'auth_code_hashes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    device_id = db.Column(db.String(50), nullable=False, index=True)
    phone = db.Column(db.String(20), nullable=False)
    phone_code_hash = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('auth_hashes', lazy='dynamic'))

    def __repr__(self):
        return f'<AuthCodeHash {self.device_id}: {self.phone}>'


class SentMessage(db.Model):
    """Таблица для предотвращения дублирования сообщений на уровне (слот, получатель)"""
    __tablename__ = 'sent_messages'

    id = db.Column(db.Integer, primary_key=True)
    slot_id = db.Column(db.Integer, db.ForeignKey('scheduled_time_slots.id'), nullable=False, index=True)
    recipient_id = db.Column(db.String(100), nullable=False, index=True)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Уникальный индекс для предотвращения дублей
    __table_args__ = (
        db.UniqueConstraint('slot_id', 'recipient_id', name='_slot_recipient_uc'),
    )

    slot = db.relationship('ScheduledTimeSlot', backref=db.backref('sent_messages', lazy='dynamic'))
    status = db.Column(db.String(20), default='sent') # sent, failed
    error_message = db.Column(db.Text)

    def __repr__(self):
        return f'<SentMessage slot={self.slot_id} recipient={self.recipient_id}>'
