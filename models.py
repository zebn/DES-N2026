from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import json

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    """Modelo de usuario con criptografía asimétrica"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Información personal
    nombre = db.Column(db.String(100), nullable=False)
    apellidos = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    telefono = db.Column(db.String(20))
    
    # Autenticación
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    
    # Autorización y roles
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    clearance_level = db.Column(db.String(20), default='CONFIDENTIAL')
    
    # Criptografía asimétrica (generada en cliente)
    public_key = db.Column(db.Text, nullable=False)
    private_key_encrypted = db.Column(db.Text, nullable=False)  # Cifrada con password
    key_derivation_params = db.Column(db.Text, nullable=False)  # JSON con parámetros
    
    # 2FA
    totp_secret = db.Column(db.String(32))
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    hotp_counter = db.Column(db.Integer, default=0)
    
    # Control de seguridad
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relaciones
    files = db.relationship('SecureFile', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    operations = db.relationship('SignedOperation', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password, salt):
        """Establecer hash de contraseña con sal"""
        import hashlib
        # Combinar password y salt usando hash para evitar límite de 72 bytes
        combined = hashlib.sha256((password + salt).encode()).hexdigest()
        self.password_hash = bcrypt.generate_password_hash(combined).decode('utf-8')
        self.salt = salt
    
    def check_password(self, password):
        """Verificar contraseña"""
        import hashlib
        combined = hashlib.sha256((password + self.salt).encode()).hexdigest()
        return bcrypt.check_password_hash(self.password_hash, combined)
    
    def is_locked(self):
        """Verificar si la cuenta está bloqueada"""
        if self.locked_until:
            return datetime.utcnow() < self.locked_until
        return False
    
    def get_derivation_params(self):
        """Obtener parámetros de derivación de clave como dict"""
        return json.loads(self.key_derivation_params)
    
    def has_clearance(self, required_level):
        """Verificar si el usuario tiene el nivel de autorización requerido"""
        levels = {'RESTRICTED': 1, 'CONFIDENTIAL': 2, 'SECRET': 3, 'TOP_SECRET': 4}
        user_level = levels.get(self.clearance_level, 0)
        required = levels.get(required_level, 4)
        return user_level >= required
    
    def to_dict(self):
        """Convertir a diccionario para JSON"""
        return {
            'id': self.id,
            'nombre': self.nombre,
            'apellidos': self.apellidos,
            'email': self.email,
            'telefono': self.telefono,
            'clearance_level': self.clearance_level,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'is_2fa_enabled': self.is_2fa_enabled,
            'public_key': self.public_key,
            'encrypted_private_key': self.private_key_encrypted,
            'key_derivation_params': self.key_derivation_params,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class SecureFile(db.Model):
    """Modelo para archivos cifrados"""
    __tablename__ = 'secure_files'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Información del archivo
    title = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    
    # Clasificación de seguridad
    classification_level = db.Column(db.String(20), nullable=False)
    compartments = db.Column(db.String(500))  # Compartimentos adicionales
    
    # Criptografía
    encrypted_content = db.Column(db.LargeBinary, nullable=False)  # Archivo cifrado
    encrypted_aes_key = db.Column(db.Text, nullable=False)  # Clave AES cifrada con RSA
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256 original
    encrypted_hash = db.Column(db.String(64), nullable=False)  # Hash del cifrado
    
    # Firma digital
    digital_signature = db.Column(db.Text, nullable=False)
    signature_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Control de integridad
    integrity_checks = db.Column(db.Integer, default=0)
    last_integrity_check = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime)  # Expiración automática
    
    # Relaciones
    access_logs = db.relationship('FileAccessLog', backref='file', lazy='dynamic', cascade='all, delete-orphan')
    shares = db.relationship('FileShare', backref='file', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convertir a diccionario para JSON"""
        return {
            'id': self.id,
            'title': self.title,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'classification_level': self.classification_level,
            'compartments': self.compartments,
            'encrypted_aes_key': self.encrypted_aes_key,  # Needed for sharing
            'file_hash': self.file_hash,
            'signature_timestamp': self.signature_timestamp.isoformat(),
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'owner': self.owner.nombre + ' ' + self.owner.apellidos
        }

class SignedOperation(db.Model):
    """Modelo para operaciones que requieren firma digital"""
    __tablename__ = 'signed_operations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Detalles de la operación
    operation_type = db.Column(db.String(50), nullable=False)  # UPLOAD, DOWNLOAD, DELETE, SHARE
    operation_data = db.Column(db.Text, nullable=False)  # JSON con datos
    operation_hash = db.Column(db.String(64), nullable=False)  # Hash de la operación
    
    # Firma digital
    digital_signature = db.Column(db.Text, nullable=False)
    signature_method = db.Column(db.String(20), default='RSA_PSS')  # RSA_PSS o HOTP
    hotp_value = db.Column(db.String(10))  # Solo si se usa HOTP
    
    # Estado
    is_executed = db.Column(db.Boolean, default=False)
    executed_at = db.Column(db.DateTime)
    is_verified = db.Column(db.Boolean, default=False)
    verification_notes = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def to_dict(self):
        """Convertir a diccionario para JSON"""
        return {
            'id': self.id,
            'operation_type': self.operation_type,
            'operation_hash': self.operation_hash,
            'signature_method': self.signature_method,
            'is_executed': self.is_executed,
            'is_verified': self.is_verified,
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
    resource_id = db.Column(db.Integer)
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
