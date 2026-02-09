import os
from datetime import timedelta
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

class Config:
    """Configuración base para la aplicación"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Debug: mostrar qué clave se está usando
    if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
        print(f"[DEBUG] SECRET_KEY cargado: {SECRET_KEY[:50]}..." if len(SECRET_KEY) > 50 else f"[DEBUG] SECRET_KEY: {SECRET_KEY}")
    
    # Base de datos
    # Heroku proporciona DATABASE_URL con "postgres://" pero SQLAlchemy necesita "postgresql://"
    database_url = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_DATABASE_URI = database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # JWT configuración
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.environ.get('JWT_ACCESS_TOKEN_HOURS', '1')))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.environ.get('JWT_REFRESH_TOKEN_DAYS', '30')))
    
    # Debug: mostrar qué clave JWT se está usando
    if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
        print(f"[DEBUG] JWT_SECRET_KEY cargado: {JWT_SECRET_KEY[:50]}..." if len(JWT_SECRET_KEY) > 50 else f"[DEBUG] JWT_SECRET_KEY: {JWT_SECRET_KEY}")
    
    # Configuración de criptografía
    PBKDF2_ITERATIONS = int(os.environ.get('PBKDF2_ITERATIONS', '200000'))
    RSA_KEY_SIZE = int(os.environ.get('RSA_KEY_SIZE', '4096'))
    AES_KEY_SIZE = int(os.environ.get('AES_KEY_SIZE', '256'))
    
    # Configuración de archivos
    MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE_MB', '100')) * 1024 * 1024
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff',
        'zip', 'rar', '7z', 'tar', 'gz',
        'mp4', 'avi', 'mov', 'wmv',
        'mp3', 'wav', 'flac'
    }
    
    # Niveles de clasificación
    CLASSIFICATION_LEVELS = {
        'RESTRICTED': 1,
        'CONFIDENTIAL': 2, 
        'SECRET': 3,
        'TOP_SECRET': 4
    }
    
    # Configuración 2FA
    TOTP_ISSUER = os.environ.get('TOTP_ISSUER', 'Proteccion_Informacion').replace('_', ' ')
    HOTP_WINDOW = int(os.environ.get('HOTP_WINDOW', '3'))
    
    # Configuración de seguridad
    BCRYPT_LOG_ROUNDS = int(os.environ.get('BCRYPT_LOG_ROUNDS', '12'))
    FAILED_LOGIN_LIMIT = int(os.environ.get('FAILED_LOGIN_LIMIT', '5'))
    ACCOUNT_LOCKOUT_TIME = timedelta(minutes=int(os.environ.get('ACCOUNT_LOCKOUT_MINUTES', '30')))
    
    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:4200,https://milcom.vercel.app').split(',')

class DevelopmentConfig(Config):
    """Configuración para desarrollo"""
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1', 'yes')
    
class ProductionConfig(Config):
    """Configuración para producción"""
    DEBUG = False
    # En producción usar variables de entorno obligatoriamente
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    def __init__(self):
        super().__init__()
        # Validar configuración crítica en producción
        if not self.SECRET_KEY or self.SECRET_KEY == 'dev-secret-key-change-in-production':
            raise ValueError("❌ ERROR: Debe configurar SECRET_KEY en producción con un valor seguro")
        if not self.JWT_SECRET_KEY or self.JWT_SECRET_KEY == self.SECRET_KEY:
            print("⚠️  ADVERTENCIA: Se recomienda usar JWT_SECRET_KEY diferente a SECRET_KEY")

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
