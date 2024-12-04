from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin
from datetime import datetime
import uuid

db = SQLAlchemy()

# Tabla de asociación para roles de usuarios
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    """Modelo para definir roles de usuario."""
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))

    def __repr__(self):
        return f'<Role {self.name}>'

class User(db.Model, UserMixin):
    """Modelo para definir un usuario."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=True)  # Asumiendo que un nuevo usuario es activo por defecto
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

    def __repr__(self):
        return f'<User {self.username} (Email: {self.email})>'

class AccessLog(db.Model):
    """Modelo para registrar los accesos de los usuarios."""
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    door = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('access_logs', lazy=True))

    def __repr__(self):
        return f'<AccessLog {self.event} by User {self.user_id} at {self.timestamp}>'

class AccessRequest(db.Model):
    """Modelo para las solicitudes de acceso de los usuarios."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # Estado de la solicitud
    request_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Fecha de la solicitud
    location = db.Column(db.String(100), nullable=False)  # Ubicación solicitada (por ejemplo, qué puerta)
    reason = db.Column(db.String(255), nullable=False)  # Razón del acceso solicitado

    # Relación con el modelo de usuario
    user = db.relationship('User', backref='access_requests', lazy=True)

    def to_dict(self):
        """Convierte la solicitud de acceso a un diccionario."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'status': self.status,
            'request_time': self.request_time,
            'location': self.location,
            'reason': self.reason
        }

    def __repr__(self):
        return f'<AccessRequest {self.id} by User {self.user_id} - Status: {self.status}>'
