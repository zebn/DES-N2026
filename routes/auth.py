"""
Rutas de autenticación y gestión de usuarios
Incluye registro, login, 2FA y gestión de sesiones
"""

import json
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.exceptions import BadRequest
from sqlalchemy.exc import IntegrityError

from models import db, User, AuditLog
from utils.crypto import crypto_manager
from utils.totp import two_factor_auth

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

def get_current_user_id() -> int:
    """Helper para obtener user_id como int desde JWT identity (que es string)"""
    user_id_str = get_jwt_identity()
    return int(user_id_str)

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Registrar nuevo usuario con criptografía asimétrica generada en cliente
    ---
    tags:
      - auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - nombre
            - apellidos
            - email
            - password
            - public_key
            - encrypted_private_key
            - key_derivation_params
          properties:
            nombre:
              type: string
              example: Juan
            apellidos:
              type: string
              example: Pérez García
            email:
              type: string
              format: email
              example: juan.perez@protecci-n2025.mil
            password:
              type: string
              format: password
              example: SecurePass123!
            clearance_level:
              type: string
              enum: [RESTRICTED, CONFIDENTIAL, SECRET, TOP_SECRET]
              example: CONFIDENTIAL
            public_key:
              type: string
              description: Clave pública RSA en formato PEM
            encrypted_private_key:
              type: string
              description: Clave privada cifrada con AES
            key_derivation_params:
              type: object
              description: Parámetros para derivación de claves
    responses:
      201:
        description: Usuario registrado exitosamente
        schema:
          type: object
          properties:
            message:
              type: string
              example: Usuario registrado exitosamente
            user_id:
              type: integer
              example: 1
            totp_secret:
              type: string
              description: Secreto TOTP para 2FA
      400:
        description: Error en la validación de datos
        schema:
          type: object
          properties:
            error:
              type: string
              example: Campo requerido faltante
    """
    try:
        data = request.get_json()
        
        # Validar datos requeridos
        required_fields = ['nombre', 'apellidos', 'email', 'password', 'public_key', 
                          'encrypted_private_key', 'key_derivation_params']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        # Verificar si el usuario ya existe
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'El usuario ya existe'}), 400
        
        # Validar nivel de autorización
        clearance_level = data.get('clearance_level', 'CONFIDENTIAL')
        if clearance_level not in current_app.config['CLASSIFICATION_LEVELS']:
            return jsonify({'error': 'Nivel de autorización inválido'}), 400
        
        # Generar sal para la contraseña
        salt = crypto_manager.secure_random_string(32)
        
        # Generar secreto TOTP
        totp_secret = two_factor_auth.totp.generate_secret()
        
        # Crear usuario
        user = User(
            nombre=data['nombre'],
            apellidos=data['apellidos'],
            email=data['email'],
            telefono=data.get('telefono'),
            salt=salt,
            clearance_level=clearance_level,
            public_key=data['public_key'],
            private_key_encrypted=data['encrypted_private_key'],
            key_derivation_params=data['key_derivation_params'],
            totp_secret=totp_secret,
            is_admin=data.get('is_admin', False)
        )
        
        # Establecer contraseña con hash
        user.set_password(data['password'], salt)
        
        # Guardar en base de datos
        db.session.add(user)
        db.session.commit()
        
        # Registrar en auditoría
        log_entry = AuditLog(
            user_id=user.id,
            action='USER_REGISTER',
            resource_type='USER',
            resource_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'message': 'Usuario registrado exitosamente',
            'user_id': user.id,
            'email': user.email,
            'clearance_level': user.clearance_level,
            'public_key': user.public_key
        }), 201
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'El usuario ya existe'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error al registrar usuario: {str(e)}'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Autenticar usuario con contraseña y opcionalmente 2FA
    ---
    tags:
      - auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              format: email
              example: juan.perez@protecci-n2025.mil
            password:
              type: string
              format: password
              example: SecurePass123!
            totp_code:
              type: string
              description: Código TOTP si 2FA está habilitado
              example: "123456"
    responses:
      200:
        description: Login exitoso
        schema:
          type: object
          properties:
            message:
              type: string
              example: Login exitoso
            access_token:
              type: string
              description: JWT access token
            refresh_token:
              type: string
              description: JWT refresh token
            user:
              type: object
              properties:
                id:
                  type: integer
                email:
                  type: string
                clearance_level:
                  type: string
      401:
        description: Credenciales inválidas o 2FA requerido
        schema:
          type: object
          properties:
            error:
              type: string
            requires_2fa:
              type: boolean
    """
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email y contraseña requeridos'}), 400
        
        # Buscar usuario
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not user.is_active:
            # Registrar intento fallido
            log_entry = AuditLog(
                action='LOGIN_FAILED',
                resource_type='USER',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False,
                error_message='Usuario no encontrado o inactivo'
            )
            db.session.add(log_entry)
            db.session.commit()
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        # Verificar si la cuenta está bloqueada
        if user.is_locked():
            return jsonify({
                'error': 'Cuenta bloqueada temporalmente',
                'locked_until': user.locked_until.isoformat()
            }), 423
        
        # Verificar contraseña
        if not user.check_password(data['password']):
            # Incrementar intentos fallidos
            user.failed_login_attempts += 1
            
            if user.failed_login_attempts >= current_app.config.get('FAILED_LOGIN_LIMIT', 5):
                user.locked_until = datetime.utcnow() + current_app.config.get('ACCOUNT_LOCKOUT_TIME', timedelta(minutes=30))
            
            db.session.commit()
            
            # Registrar intento fallido
            log_entry = AuditLog(
                user_id=user.id,
                action='LOGIN_FAILED',
                resource_type='USER',
                resource_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False,
                error_message='Contraseña incorrecta'
            )
            db.session.add(log_entry)
            db.session.commit()
            
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        # Si tiene 2FA habilitado, requerir código TOTP
        if user.is_2fa_enabled:
            totp_code = data.get('totp_code')
            if not totp_code:
                return jsonify({
                    'error': '2FA requerido',
                    'requires_2fa': True
                }), 200
            
            if not two_factor_auth.verify_totp_login(user.totp_secret, totp_code):
                # Registrar intento fallido de 2FA
                log_entry = AuditLog(
                    user_id=user.id,
                    action='2FA_FAILED',
                    resource_type='USER',
                    resource_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=False,
                    error_message='Código 2FA inválido'
                )
                db.session.add(log_entry)
                db.session.commit()
                
                return jsonify({'error': 'Código 2FA inválido'}), 401
        
        # Login exitoso - resetear intentos fallidos
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        
        # Crear tokens JWT (identity debe ser string)
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                'email': user.email,
                'clearance_level': user.clearance_level,
                'is_admin': user.is_admin
            }
        )
        
        refresh_token = create_refresh_token(identity=str(user.id))
        
        # Debug: verificar token inmediatamente
        import os
        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG LOGIN] Token creado para user_id={user.id}, token={access_token[:50]}...")
        
        db.session.commit()
        
        # Registrar login exitoso
        log_entry = AuditLog(
            user_id=user.id,
            action='LOGIN_SUCCESS',
            resource_type='USER',
            resource_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'message': 'Login exitoso',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error en login: {str(e)}'}), 500

@auth_bp.route('/setup-2fa', methods=['POST'])
@jwt_required()
def setup_2fa():
    """
    Configurar autenticación de doble factor (TOTP)
    ---
    tags:
      - auth
    security:
      - Bearer: []
    responses:
      200:
        description: Configuración 2FA iniciada
        schema:
          type: object
          properties:
            message:
              type: string
              example: 2FA configurado. Escanea el código QR
            secret:
              type: string
              description: Secreto TOTP
            qr_code:
              type: string
              description: Código QR en base64
            uri:
              type: string
              description: URI para apps de autenticación
      400:
        description: 2FA ya está habilitado
      404:
        description: Usuario no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        if user.is_2fa_enabled:
            return jsonify({'error': '2FA ya está habilitado'}), 400
        
        # Generar nuevo secreto y QR
        secret, uri, qr_code = two_factor_auth.setup_totp_for_user(user.email)
        
        # Guardar secreto temporalmente (se confirmará con verify-2fa)
        user.totp_secret = secret
        db.session.commit()
        
        import base64
        qr_code_b64 = base64.b64encode(qr_code).decode('utf-8')
        
        return jsonify({
            'secret': secret,
            'qr_code': qr_code_b64,
            'setup_uri': uri,
            'message': 'Escanea el código QR con tu app de autenticación y confirma con verify-2fa'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error configurando 2FA: {str(e)}'}), 500

@auth_bp.route('/verify-2fa', methods=['POST'])
@jwt_required()
def verify_2fa():
    """
    Verificar y habilitar 2FA con código de confirmación
    ---
    tags:
      - auth
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - totp_code
          properties:
            totp_code:
              type: string
              description: Código TOTP de 6 dígitos
              example: "123456"
    responses:
      200:
        description: 2FA habilitado exitosamente
        schema:
          type: object
          properties:
            message:
              type: string
              example: 2FA habilitado exitosamente
      400:
        description: Código inválido o 2FA ya habilitado
      404:
        description: Usuario no encontrado
    """
    try:
        import os
        data = request.get_json()

        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG VERIFY-2FA] Data recibida: {data}")

        totp_code = data.get('totp_code')

        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG VERIFY-2FA] totp_code extraído: '{totp_code}'")

        if not totp_code:
            return jsonify({'error': 'Código TOTP requerido'}), 400
        
        user_id = get_current_user_id()
        user = User.query.get(user_id)

        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG VERIFY-2FA] Usuario ID: {user_id}")

        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404

        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG VERIFY-2FA] Usuario encontrado: {user.email}")
            print(f"[DEBUG VERIFY-2FA] 2FA ya habilitado: {user.is_2fa_enabled}")
            print(f"[DEBUG VERIFY-2FA] TOTP secret existe: {bool(user.totp_secret)}")

        if user.is_2fa_enabled:
            return jsonify({'error': '2FA ya está habilitado'}), 400

        # Verificar código
        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG VERIFY-2FA] Verificando código '{totp_code}' contra secreto")

        is_valid = two_factor_auth.verify_totp_setup(user.totp_secret, totp_code)

        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG VERIFY-2FA] Código válido: {is_valid}")

        if not is_valid:
            return jsonify({'error': 'Código TOTP inválido'}), 400
        
        # Habilitar 2FA
        user.is_2fa_enabled = True
        
        # Generar códigos de respaldo
        backup_codes = two_factor_auth.generate_backup_codes()
        
        db.session.commit()
        
        # Registrar en auditoría
        log_entry = AuditLog(
            user_id=user.id,
            action='2FA_ENABLED',
            resource_type='USER',
            resource_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'message': '2FA habilitado exitosamente',
            'backup_codes': backup_codes,
            'warning': 'Guarda estos códigos de respaldo en un lugar seguro'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error verificando 2FA: {str(e)}'}), 500

@auth_bp.route('/disable-2fa', methods=['POST'])
@jwt_required()
def disable_2fa():
    """
    Deshabilitar 2FA (requiere código actual)
    """
    try:
        data = request.get_json()
        totp_code = data.get('totp_code')
        
        if not totp_code:
            return jsonify({'error': 'Código TOTP requerido para deshabilitar 2FA'}), 400
        
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        if not user.is_2fa_enabled:
            return jsonify({'error': '2FA no está habilitado'}), 400
        
        # Verificar código actual
        if not two_factor_auth.verify_totp_login(user.totp_secret, totp_code):
            return jsonify({'error': 'Código TOTP inválido'}), 401
        
        # Deshabilitar 2FA
        user.is_2fa_enabled = False
        user.totp_secret = None
        
        db.session.commit()
        
        # Registrar en auditoría
        log_entry = AuditLog(
            user_id=user.id,
            action='2FA_DISABLED',
            resource_type='USER',
            resource_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'message': '2FA deshabilitado exitosamente'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error deshabilitando 2FA: {str(e)}'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Renovar token de acceso usando refresh token
    ---
    tags:
      - auth
    security:
      - Bearer: []
    parameters:
      - in: header
        name: Authorization
        required: true
        type: string
        description: Bearer {refresh_token}
    responses:
      200:
        description: Token renovado exitosamente
        schema:
          type: object
          properties:
            access_token:
              type: string
              description: Nuevo JWT access token
      404:
        description: Usuario no encontrado o inactivo
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'Usuario no encontrado o inactivo'}), 404
        
        # Crear nuevo access token (identity debe ser string)
        new_access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                'email': user.email,
                'clearance_level': user.clearance_level,
                'is_admin': user.is_admin
            }
        )
        
        return jsonify({'access_token': new_access_token}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error renovando token: {str(e)}'}), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """
    Obtener perfil del usuario actual
    ---
    tags:
      - auth
    security:
      - Bearer: []
    responses:
      200:
        description: Perfil del usuario
        schema:
          type: object
          properties:
            user:
              type: object
              properties:
                id:
                  type: integer
                  example: 1
                nombre:
                  type: string
                  example: Juan
                apellidos:
                  type: string
                  example: Pérez García
                email:
                  type: string
                  example: juan.perez@protecci-n2025.mil
                clearance_level:
                  type: string
                  example: CONFIDENTIAL
                is_2fa_enabled:
                  type: boolean
                  example: true
                is_active:
                  type: boolean
                  example: true
                created_at:
                  type: string
                  format: date-time
      404:
        description: Usuario no encontrado
    """
    try:
        import os
        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            from flask import request
            auth_header = request.headers.get('Authorization', '')
            print(f"[DEBUG PROFILE] Authorization header: {auth_header[:70]}...")
        
        user_id = get_current_user_id()
        
        if os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'):
            print(f"[DEBUG PROFILE] JWT identity extracted: user_id={user_id}")
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        return jsonify({'user': user.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo perfil: {str(e)}'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Cerrar sesión (invalidar token)
    ---
    tags:
      - auth
    security:
      - Bearer: []
    responses:
      200:
        description: Logout exitoso
        schema:
          type: object
          properties:
            message:
              type: string
              example: Logout exitoso
    """
    try:
        user_id = get_current_user_id()
        
        # Registrar logout en auditoría
        log_entry = AuditLog(
            user_id=user_id,
            action='LOGOUT',
            resource_type='USER',
            resource_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # En una implementación completa, aquí se invalidaría el token
        # Por ahora solo retornamos confirmación
        return jsonify({'message': 'Logout exitoso'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error en logout: {str(e)}'}), 500

@auth_bp.route('/users', methods=['GET'])
@jwt_required()
def list_users():
    """
    Listar todos los usuarios del sistema (solo administradores)
    ---
    tags:
      - admin
    security:
      - Bearer: []
    responses:
      200:
        description: Lista de usuarios
        schema:
          type: object
          properties:
            users:
              type: array
              items:
                type: object
      403:
        description: Acceso denegado (no es administrador)
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Verificar que sea administrador
        if not user.is_admin:
            return jsonify({'error': 'Acceso denegado: se requieren permisos de administrador'}), 403
        
        # Obtener todos los usuarios
        users = User.query.all()
        users_list = [u.to_dict() for u in users]
        
        return jsonify({'users': users_list}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error listando usuarios: {str(e)}'}), 500

@auth_bp.route('/users/<int:user_id>/activate', methods=['POST'])
@jwt_required()
def activate_user(user_id):
    """
    Activar usuario (solo administradores)
    ---
    tags:
      - admin
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: ID del usuario a activar
    responses:
      200:
        description: Usuario activado exitosamente
      403:
        description: Acceso denegado (no es administrador)
      404:
        description: Usuario no encontrado
    """
    try:
        admin_id = get_jwt_identity()
        admin = User.query.get(admin_id)
        
        if not admin:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Verificar que sea administrador
        if not admin.is_admin:
            return jsonify({'error': 'Acceso denegado: se requieren permisos de administrador'}), 403
        
        # Buscar el usuario a activar
        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Activar usuario
        target_user.is_active = True
        db.session.commit()
        
        # Registrar en auditoría
        log_entry = AuditLog(
            user_id=admin_id,
            action='ACTIVATE_USER',
            resource_type='USER',
            resource_id=user_id,
            details=f'Usuario {target_user.email} activado',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'message': f'Usuario {target_user.email} activado exitosamente'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error activando usuario: {str(e)}'}), 500

@auth_bp.route('/users/<int:user_id>/deactivate', methods=['POST'])
@jwt_required()
def deactivate_user(user_id):
    """
    Desactivar usuario (solo administradores)
    ---
    tags:
      - admin
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: ID del usuario a desactivar
    responses:
      200:
        description: Usuario desactivado exitosamente
      403:
        description: Acceso denegado (no es administrador)
      404:
        description: Usuario no encontrado
      400:
        description: No se puede desactivar a sí mismo
    """
    try:
        admin_id = get_jwt_identity()
        admin = User.query.get(admin_id)
        
        if not admin:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Verificar que sea administrador
        if not admin.is_admin:
            return jsonify({'error': 'Acceso denegado: se requieren permisos de administrador'}), 403
        
        # No permitir desactivarse a sí mismo
        if admin_id == user_id:
            return jsonify({'error': 'No puedes desactivar tu propia cuenta'}), 400
        
        # Buscar el usuario a desactivar
        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Desactivar usuario
        target_user.is_active = False
        db.session.commit()
        
        # Registrar en auditoría
        log_entry = AuditLog(
            user_id=admin_id,
            action='DEACTIVATE_USER',
            resource_type='USER',
            resource_id=user_id,
            details=f'Usuario {target_user.email} desactivado',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'message': f'Usuario {target_user.email} desactivado exitosamente'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error desactivando usuario: {str(e)}'}), 500


@auth_bp.route('/user/public-key', methods=['POST'])
@jwt_required()
def get_user_public_key():
    """
    Obtener clave pública de un usuario por email
    Este endpoint permite a cualquier usuario autenticado obtener la clave pública
    de otro usuario para compartir archivos de forma segura
    ---
    tags:
      - auth
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
          properties:
            email:
              type: string
              description: Email del usuario
              example: user@example.com
    responses:
      200:
        description: Clave pública obtenida exitosamente
        schema:
          type: object
          properties:
            email:
              type: string
            public_key:
              type: string
            is_active:
              type: boolean
            clearance_level:
              type: string
      400:
        description: Email no proporcionado
      404:
        description: Usuario no encontrado
    """
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email requerido'}), 400
        
        # Buscar usuario por email
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Retornar solo información pública necesaria para compartir archivos
        return jsonify({
            'email': user.email,
            'public_key': user.public_key,
            'is_active': user.is_active,
            'clearance_level': user.clearance_level
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Error obteniendo clave pública: {str(e)}'}), 500
