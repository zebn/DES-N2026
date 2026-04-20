from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from datetime import datetime
import uuid
from enum import Enum
import secrets

# ─────────────────────────────────────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────────────────────────────────────

db = SQLAlchemy()
ma = Marshmallow()

def generate_uuid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class UserRole(str, Enum):
    """Roles de usuario"""
    ADMIN = 'ADMIN'
    MANAGER = 'MANAGER'
    USER = 'USER'
    GUEST = 'GUEST'


class SecretType(str, Enum):
    """Tipos de secretos soportados"""
    PASSWORD = 'PASSWORD'
    API_KEY = 'API_KEY'
    CERTIFICATE = 'CERTIFICATE'
    SSH_KEY = 'SSH_KEY'
    NOTE = 'NOTE'
    DATABASE = 'DATABASE'
    ENV_VARIABLE = 'ENV_VARIABLE'
    IDENTITY = 'IDENTITY'


# ─────────────────────────────────────────────────────────────────────────────
# Modelos
# ─────────────────────────────────────────────────────────────────────────────

class User(db.Model):
    """Modelo de usuario con criptografía RSA-4096"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # Claves RSA-4096 (public en claro, private no se guarda en DB)
    public_key = db.Column(db.Text, nullable=False)  # PEM format

    # Datos opcionales
    full_name = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.Enum(UserRole), default=UserRole.USER, nullable=False)

    # Metadata de sesión
    last_login_at = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role.value,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'executed_at': self.executed_at.isoformat() if self.executed_at else None
        }

class FileShare(db.Model):
    """Modelo para compartir archivos entre usuarios"""
    __tablename__ = 'file_shares'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('secure_files.id'), nullable=False)
    shared_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Clave AES re-cifrada para el destinatario
    encrypted_aes_key_for_recipient = db.Column(db.Text, nullable=False)
    
    # Permisos
    can_read = db.Column(db.Boolean, default=True)
    can_download = db.Column(db.Boolean, default=False)
    can_share = db.Column(db.Boolean, default=False)
    
    # Timestamps
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    # Relaciones
    shared_by = db.relationship('User', foreign_keys=[shared_by_id], backref='files_shared')
    shared_with = db.relationship('User', foreign_keys=[shared_with_id], backref='files_received')

class FileAccessLog(db.Model):
    """Registro de accesos a archivos para auditoría"""
    __tablename__ = 'file_access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('secure_files.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Detalles del acceso
    access_type = db.Column(db.String(20), nullable=False)  # VIEW, DOWNLOAD, SHARE, DELETE
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.String(500))
    
    # Timestamp
    accessed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    user = db.relationship('User', backref='access_logs')

class AuditLog(db.Model):
    """Registro de auditoría general del sistema"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Detalles de la acción
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(36))  # String para soportar UUIDs de secretos
    details = db.Column(db.Text)  # JSON con detalles adicionales
    
    # Contexto
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.String(500))
    
    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relación
    user = db.relationship('User', backref='audit_logs')

    def to_dict(self):
        import json as _json
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': _json.loads(self.details) if self.details else None,
            'ip_address': self.ip_address,
            'success': self.success,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }


# ─── Nuevos modelos: Gestión de Secretos ─────────────────────────────────────

class Folder(db.Model):
    """Carpetas para organizar secretos jerárquicamente"""
    __tablename__ = 'folders'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.String(36), db.ForeignKey('folders.id'), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = db.relationship('User', backref=db.backref('folders', lazy='dynamic'))
    children = db.relationship('Folder', remote_side=[id], backref='parent')

    def to_dict(self):
        return {
            'id': self.id,
            'owner_id': self.owner_id,
            'name': self.name,
            'parent_id': self.parent_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class Secret(db.Model):
    """Modelo principal para secretos cifrados E2E"""
    __tablename__ = 'secrets'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Metadatos (en claro — no sensibles)
    title = db.Column(db.String(500), nullable=False)  # Cifrado en cliente
    url = db.Column(db.String(500), nullable=True)     # URL сайта/сервиса (опционально, в claro)
    secret_type = db.Column(db.Enum(SecretType), nullable=False)

    # Datos cifrados E2E (el servidor NUNCA ve el contenido)
    encrypted_data = db.Column(db.Text, nullable=False)          # JSON cifrado con AES-256-CTR, base64
    encrypted_aes_key = db.Column(db.Text, nullable=False)       # Clave AES cifrada con RSA-4096 del owner
    content_hash = db.Column(db.String(64), nullable=False)      # SHA-256 del plaintext
    digital_signature = db.Column(db.Text, nullable=False)       # RSA-PSS sobre content_hash

    # Organización
    tags = db.Column(db.Text, nullable=True)                     # JSON de etiquetas (cifrado en cliente)
    folder_id = db.Column(db.String(36), db.ForeignKey('folders.id'), nullable=True)

    # Versionado
    version = db.Column(db.Integer, default=1, nullable=False)

    # Caducidad y rotación
    expires_at = db.Column(db.DateTime, nullable=True)
    rotation_period_days = db.Column(db.Integer, nullable=True)
    last_rotated_at = db.Column(db.DateTime, nullable=True)

    # Soft delete
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relaciones
    owner = db.relationship('User', backref=db.backref('secrets', lazy='dynamic'))
    versions = db.relationship('SecretVersion', backref='secret', lazy='dynamic',
                               order_by='SecretVersion.version_number.desc()')
    access_logs = db.relationship('SecretAccessLog', backref='secret', lazy='dynamic')

    def to_dict(self, include_encrypted=False):
        """Convertir a dict. Por defecto NO incluye datos cifrados (listados)."""
        data = {
            'id': self.id,
            'owner_id': self.owner_id,
            'title': self.title,
            'url': self.url,
            'secret_type': self.secret_type.value,
            'tags': self.tags,
            'folder_id': self.folder_id,
            'version': self.version,
            'content_hash': self.content_hash,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'rotation_period_days': self.rotation_period_days,
            'last_rotated_at': self.last_rotated_at.isoformat() if self.last_rotated_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
        if include_encrypted:
            data['encrypted_data'] = self.encrypted_data
            data['encrypted_aes_key'] = self.encrypted_aes_key
            data['digital_signature'] = self.digital_signature
        return data
