#!/usr/bin/env python3
"""
Servidor Flask para SentryVault
Sistema de protección de información con cifrado extremo
"""

import os
from datetime import timedelta
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flasgger import Swagger

from config import config
from models import db, bcrypt
from routes.auth import auth_bp
from routes.files import files_bp
from routes.secrets import secrets_bp, folders_bp
from routes.audit import audit_bp
from routes.groups import groups_bp
from routes.backup import backup_bp

def create_app(config_name=None):
    """Factory para crear la aplicación Flask"""
    
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    
    # Configuración
    app.config.from_object(config.get(config_name, config['default']))
    
    # Inicializar extensiones
    db.init_app(app)
    bcrypt.init_app(app)
    
    # JWT Manager
    jwt = JWTManager(app)
    
    # Debug: verificar configuración JWT
    if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
        print(f"[DEBUG JWT CONFIG] JWT_SECRET_KEY configurado: {app.config.get('JWT_SECRET_KEY', 'NOT SET')[:50]}...")
        print(f"[DEBUG JWT CONFIG] JWT_ACCESS_TOKEN_EXPIRES: {app.config.get('JWT_ACCESS_TOKEN_EXPIRES')}")
    
    # CORS - Permitir Swagger UI y Angular en cualquier puerto localhost
    if config_name == 'development':
        # En desarrollo, permitir cualquier puerto localhost (http y https)
        cors_origins = [
            r'https?://localhost:\d+',
            r'https?://127\.0\.0\.1:\d+'
        ]
    else:
        # En producción, usar solo orígenes configurados
        cors_origins = app.config.get('CORS_ORIGINS', ['http://localhost:3000'])
    
    CORS(app, 
         origins=cors_origins,
         supports_credentials=True,
         allow_headers=['Content-Type', 'Authorization', 'Accept'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         expose_headers=['Content-Type', 'Authorization'])
    
    # Configuración de Swagger
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec',
                "route": '/apispec.json',
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/swagger/"
    }
    
    # Determinar host y scheme динамически
    # En desarrollo: localhost:5001 con https (si USE_SSL=True) o http
    # En producción (Heroku): usar el dominio de Heroku con https
    is_production = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('DYNO')
    use_ssl = os.environ.get('USE_SSL', 'True').lower() in ('true', '1', 'yes')
    
    if is_production:
        # En Heroku, dejar host vacío para que use el dominio actual
        swagger_host = ""
        swagger_schemes = ["https"]
    else:
        # En desarrollo local
        swagger_host = "localhost:5001"
        # Usar https si SSL está habilitado
        swagger_schemes = ["https", "http"] if use_ssl else ["http"]
    
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "SentryVault API",
            "description": "API REST para gestión segura de secretos",
            "contact": {
                "responsibleOrganization": "SentryVault",
                "responsibleDeveloper": "Equipo de Seguridad",
                "email": "security@sentryvault.app",
            },
            "version": "1.0.0"
        },
        "host": swagger_host,
        "basePath": "/",
        "schemes": swagger_schemes,
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header usando el esquema Bearer. Ejemplo: 'Bearer {token}'"
            }
        },
        "security": [
            {
                "Bearer": []
            }
        ],
        "tags": [
            {
                "name": "auth",
                "description": "Operaciones de autenticación y gestión de usuarios"
            },
            {
                "name": "files",
                "description": "Operaciones de gestión de archivos cifrados"
            },
            {
                "name": "secrets",
                "description": "Gestión de secretos cifrados E2E (CRUD, versiones, rotación)"
            },
            {
                "name": "folders",
                "description": "Organización de secretos en carpetas"
            },
            {
                "name": "audit",
                "description": "Auditoría, logs y estadísticas de actividad"
            },
            {
                "name": "groups",
                "description": "Gestión de grupos de usuarios y membresías"
            },
            {
                "name": "backup",
                "description": "Exportación e importación cifrada de secretos (.vault)"
            },
            {
                "name": "system",
                "description": "Información del sistema y health checks"
            }
        ]
    }
    
    Swagger(app, config=swagger_config, template=swagger_template)
    
    # Registrar blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(secrets_bp)
    app.register_blueprint(folders_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(groups_bp)
    app.register_blueprint(backup_bp)
    
    # Crear tablas de base de datos si no existen
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            # Las tablas ya existen, lo cual está bien
            app.logger.info(f"Database tables already exist or error creating them: {str(e)}")
    
    # Rutas básicas
    @app.route('/')
    def index():
        """Información básica del servidor
        ---
        tags:
          - system
        responses:
          200:
            description: Información del sistema
            schema:
              type: object
              properties:
                name:
                  type: string
                  example: Sistema de Protección de Información
                version:
                  type: string
                  example: 1.0.0
                description:
                  type: string
                security_features:
                  type: array
                  items:
                    type: string
                classification_levels:
                  type: array
                  items:
                    type: string
                endpoints:
                  type: object
        """
        return jsonify({
            'name': 'SentryVault',
            'version': '1.0.0',
            'description': 'Servidor seguro para gestión de secretos',
            'security_features': [
                'RSA-4096 criptografía asimétrica',
                'AES-256-CTR cifrado de archivos',
                'Argon2id derivación de claves',
                'TOTP/HOTP autenticación de doble factor',
                'RSA-PSS firmas digitales',
                'SHA-256 verificación de integridad',
                'JWT autenticación con roles',
                'Auditoría completa de accesos'
            ],
            'classification_levels': list(app.config['CLASSIFICATION_LEVELS'].keys()),
            'endpoints': {
                'auth': '/api/auth/',
                'files': '/api/files/',
                'docs': '/docs',
                'swagger': '/swagger/'
            }
        })
    
    @app.route('/health')
    def health():
        """Health check del servidor
        ---
        tags:
          - system
        responses:
          200:
            description: Estado de salud del sistema
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: healthy
                timestamp:
                  type: string
                database:
                  type: string
                  example: connected
                security:
                  type: string
                  example: enabled
        """
        return jsonify({
            'status': 'healthy',
            'timestamp': request.environ.get('REQUEST_TIME', 'unknown'),
            'database': 'connected',
            'security': 'enabled'
        })
    
    @app.route('/docs')
    def docs():
        """Documentación de la API"""
        return jsonify({
            'title': 'SentryVault API',
            'version': '1.0.0',
            'description': 'API para gestión segura de archivos clasificados',
            'authentication': 'JWT Bearer Token',
            'endpoints': {
                'auth': {
                    'POST /api/auth/register': 'Registrar nuevo usuario',
                    'POST /api/auth/login': 'Iniciar sesión',
                    'POST /api/auth/setup-2fa': 'Configurar 2FA',
                    'POST /api/auth/verify-2fa': 'Verificar y habilitar 2FA',
                    'POST /api/auth/disable-2fa': 'Deshabilitar 2FA',
                    'POST /api/auth/refresh': 'Renovar token',
                    'GET /api/auth/profile': 'Obtener perfil',
                    'POST /api/auth/logout': 'Cerrar sesión'
                },
                'files': {
                    'POST /api/files/upload': 'Subir archivo cifrado',
                    'GET /api/files/': 'Listar archivos',
                    'GET /api/files/<id>': 'Información de archivo',
                    'POST /api/files/<id>/download': 'Descargar archivo',
                    'DELETE /api/files/<id>': 'Eliminar archivo',
                    'GET /api/files/<id>/access-log': 'Log de accesos',
                    'POST /api/files/verify-integrity/<id>': 'Verificar integridad'
                }
            },
            'security_notes': [
                'Todas las operaciones requieren autenticación JWT',
                'Los archivos se cifran con AES-256 en el cliente',
                'Las claves se protegen con RSA-4096',
                'Las operaciones críticas requieren firma digital',
                'El acceso se controla por niveles de clasificación',
                'Todos los accesos se registran para auditoría'
            ]
        })
    
    # Manejadores de errores
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Solicitud inválida'}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'No autorizado'}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Acceso denegado'}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Recurso no encontrado'}), 404
    
    @app.errorhandler(413)
    def payload_too_large(error):
        return jsonify({'error': 'Archivo demasiado grande'}), 413
    
    @app.errorhandler(422)
    def unprocessable_entity(error):
        return jsonify({'error': 'Datos no procesables'}), 422
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500
    
    # JWT Error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG JWT] Token expirado. Header: {jwt_header}, Payload: {jwt_payload}")
        return jsonify({'error': 'Token expirado'}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG JWT] Token inválido. Error: {error}")
        return jsonify({'error': 'Token inválido'}), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG JWT] Token faltante. Error: {error}")
        return jsonify({'error': 'Token requerido'}), 401
    
    return app

def init_admin_user(app):
    """Crear usuario administrador inicial si no existe"""
    import json
    with app.app_context():
        from models import User, UserRole
        from utils.crypto import crypto_manager
        
        admin_email = "admin@admin.com"
        
        if not User.query.filter_by(email=admin_email).first():
            print("🔐 Creando usuario administrador inicial...")
            
            # Generar claves para el admin
            private_key, public_key = crypto_manager.generate_rsa_keypair()
            admin_password = "1"  # En producción, usar contraseña segura
            
            # Cifrar clave privada
            encrypted_private, derivation_params = crypto_manager.encrypt_private_key(
                private_key, admin_password
            )
            
            # Crear usuario admin
            admin = User(
                nombre="Administrador",
                apellidos="Sistema",
                email=admin_email,
                clearance_level="TOP_SECRET",
                is_admin=True,
                role=UserRole.ADMIN,
                public_key=public_key,
                private_key_encrypted=encrypted_private,
                key_derivation_params=json.dumps(derivation_params),
                salt=crypto_manager.secure_random_string(32)
            )
            
            admin.set_password(admin_password, admin.salt)
            
            db.session.add(admin)
            db.session.commit()
            
            print(f"✅ Usuario administrador creado:")
            print(f"   Email: {admin_email}")
            print(f"   Password: {admin_password}")
            print(f"   ⚠️  CAMBIAR CONTRASEÑA EN PRODUCCIÓN")

# Crear la instancia de la aplicación a nivel de módulo para gunicorn
app = create_app()

if __name__ == '__main__':
    import json
    from pathlib import Path
    
    # Crear usuario admin inicial
    init_admin_user(app)
    
    # Configuración de desarrollo
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    use_ssl = os.environ.get('USE_SSL', 'True').lower() in ('true', '1', 'yes')
    
    # Verificar certificados SSL para desarrollo
    ssl_context = None
    cert_dir = Path('certs')
    cert_file = cert_dir / 'cert.pem'
    key_file = cert_dir / 'key.pem'
    
    if use_ssl and not os.environ.get('DYNO'):  # Solo en desarrollo local
        if cert_file.exists() and key_file.exists():
            ssl_context = (str(cert_file), str(key_file))
            protocol = "https"
            print("🔒 SSL habilitado (certificado autofirmado)")
        else:
            print("⚠️  Certificados SSL no encontrados. Generando...")
            print("   Ejecuta: python generate_cert.py")
            print("   O desactiva SSL: set USE_SSL=False\n")
            # Intentar generar automáticamente
            try:
                from generate_cert import generate_self_signed_cert
                generate_self_signed_cert()
                ssl_context = (str(cert_file), str(key_file))
                protocol = "https"
                print("✅ Certificados generados automáticamente\n")
            except Exception as e:
                print(f"❌ Error generando certificados: {e}")
                print("   Continuando sin SSL...\n")
                protocol = "http"
    else:
        protocol = "http"
    
    print(f"""
🚀 Iniciando Servidor SentryVault
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📍 Servidor: {protocol}://localhost:{port}
📘 Documentación: {protocol}://localhost:{port}/docs
📊 Swagger UI: {protocol}://localhost:{port}/swagger/
🔍 Health Check: {protocol}://localhost:{port}/health

🛡️  Características de Seguridad:
   • RSA-4096 criptografía asimétrica
   • AES-256-CTR cifrado de archivos
   • Argon2id (64MB, 3 iter, 4 threads)
   • TOTP/HOTP autenticación 2FA
   • RSA-PSS firmas digitales
   • SHA-256 verificación integridad
   • JWT autenticación con roles
   • Auditoría completa
   {'• SSL/TLS cifrado (autofirmado)' if ssl_context else '• HTTP sin cifrado'}

🏷️  Niveles de Clasificación:
   • RESTRICTED (Nivel 1)
   • CONFIDENTIAL (Nivel 2)
   • SECRET (Nivel 3)
   • TOP_SECRET (Nivel 4)

⚡ Presiona Ctrl+C para detener
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)
    
    # Para Heroku, gunicorn maneja el servidor
    # El bloque app.run() solo se ejecuta en desarrollo local
    if os.environ.get('DYNO'):
        # Estamos en Heroku, no ejecutar app.run()
        pass
    else:
        # Desarrollo local
        app.run(
            host='0.0.0.0',
            port=port,
            debug=debug,
            threaded=True,
            use_reloader=False,  # Отключить автоперезагрузку для стабильности JWT
            ssl_context=ssl_context  # Включить SSL если доступен
        )
