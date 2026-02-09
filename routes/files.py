"""
Rutas para gestión de archivos cifrados
Incluye subida, descarga, listado y compartir archivos
"""

import base64
import json
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from werkzeug.utils import secure_filename
from io import BytesIO

from models import db, User, SecureFile, FileAccessLog, AuditLog, SignedOperation, FileShare
from utils.crypto import crypto_manager, file_encryption
from utils.totp import two_factor_auth

files_bp = Blueprint('files', __name__, url_prefix='/api/files')

def get_current_user_id() -> int:
    """Helper para obtener user_id como int desde JWT identity (que es string)"""
    user_id_str = get_jwt_identity()
    return int(user_id_str)

def require_clearance(required_level):
    """Decorator para requerir nivel de autorización mínimo"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user_id = get_current_user_id()
            user = User.query.get(user_id)
            
            if not user or not user.has_clearance(required_level):
                return jsonify({
                    'error': f'Nivel de autorización {required_level} requerido'
                }), 403
            
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@files_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    """
    Subir archivo cifrado con firma digital
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - title
            - original_filename
            - file_size
            - mime_type
            - classification_level
            - encrypted_content
            - encrypted_aes_key
            - file_hash
            - digital_signature
          properties:
            title:
              type: string
              example: Reporte Confidencial Q4 2025
            original_filename:
              type: string
              example: reporte_q4.pdf
            file_size:
              type: integer
              example: 1048576
            mime_type:
              type: string
              example: application/pdf
            classification_level:
              type: string
              enum: [RESTRICTED, CONFIDENTIAL, SECRET, TOP_SECRET]
              example: CONFIDENTIAL
            encrypted_content:
              type: string
              description: Contenido del archivo cifrado en base64
            encrypted_aes_key:
              type: string
              description: Clave AES cifrada con RSA
            file_hash:
              type: string
              description: Hash SHA-256 del archivo original
            digital_signature:
              type: string
              description: Firma digital RSA-PSS del hash
            description:
              type: string
              example: Reporte trimestral de operaciones
    responses:
      201:
        description: Archivo subido exitosamente
        schema:
          type: object
          properties:
            message:
              type: string
              example: Archivo subido exitosamente
            file_id:
              type: integer
              example: 42
            file_hash:
              type: string
      400:
        description: Error en validación
      403:
        description: Sin autorización para este nivel de clasificación
      413:
        description: Archivo demasiado grande
    """
    try:
        data = request.get_json()
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Validar datos requeridos
        required_fields = ['title', 'original_filename', 'file_size', 'mime_type', 
                          'classification_level', 'encrypted_content', 'encrypted_aes_key', 
                          'file_hash', 'digital_signature']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400
        
        # Validar clasificación
        classification = data['classification_level']
        if classification not in current_app.config['CLASSIFICATION_LEVELS']:
            return jsonify({'error': 'Nivel de clasificación inválido'}), 400
        
        # Verificar autorización del usuario para este nivel
        if not user.has_clearance(classification):
            return jsonify({
                'error': f'No tiene autorización para clasificación {classification}'
            }), 403
        
        # Validar tamaño de archivo
        if data['file_size'] > current_app.config.get('MAX_FILE_SIZE', 100 * 1024 * 1024):
            return jsonify({'error': 'Archivo demasiado grande'}), 413
        
        # Verificar firma digital
        file_hash_bytes = data['file_hash'].encode()
        print(f"[DEBUG] Verificando firma digital:")
        print(f"  - Hash: {data['file_hash'][:32]}...")
        print(f"  - Hash bytes length: {len(file_hash_bytes)}")
        print(f"  - Signature length: {len(base64.b64decode(data['digital_signature']))}")
        print(f"  - Public key preview: {user.public_key[:50]}...")
        
        if not crypto_manager.verify_signature(
            file_hash_bytes, 
            data['digital_signature'], 
            user.public_key
        ):
            print(f"[ERROR] Firma digital inválida para usuario {user.id}")
            return jsonify({'error': 'Firma digital inválida'}), 400
        
        print(f"[DEBUG] Firma digital verificada correctamente")
        
        # Decodificar contenido cifrado
        try:
            encrypted_content = base64.b64decode(data['encrypted_content'])
        except Exception:
            return jsonify({'error': 'Contenido cifrado inválido'}), 400
        
        # Calcular hash del contenido cifrado
        encrypted_hash = crypto_manager.calculate_file_hash(encrypted_content)
        
        # Crear registro de archivo
        secure_file = SecureFile(
            user_id=user.id,
            title=data['title'],
            original_filename=secure_filename(data['original_filename']),
            file_size=data['file_size'],
            mime_type=data['mime_type'],
            classification_level=classification,
            compartments=data.get('compartments'),
            encrypted_content=encrypted_content,
            encrypted_aes_key=data['encrypted_aes_key'],
            file_hash=data['file_hash'],
            encrypted_hash=encrypted_hash,
            digital_signature=data['digital_signature'],
            expires_at=data.get('expires_at')
        )
        
        db.session.add(secure_file)
        db.session.commit()
        
        # Registrar acceso en log
        access_log = FileAccessLog(
            file_id=secure_file.id,
            user_id=user.id,
            access_type='UPLOAD',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(access_log)
        
        # Registrar en auditoría
        audit_log = AuditLog(
            user_id=user.id,
            action='FILE_UPLOAD',
            resource_type='FILE',
            resource_id=secure_file.id,
            details=json.dumps({
                'filename': secure_file.original_filename,
                'classification': classification,
                'size': data['file_size']
            }),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({
            'message': 'Archivo subido exitosamente',
            'file_id': secure_file.id,
            'file': secure_file.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error subiendo archivo: {str(e)}'}), 500

@files_bp.route('/', methods=['GET'])
@jwt_required()
def list_files():
    """
    Listar archivos del usuario con filtros opcionales
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: query
        name: classification
        type: string
        enum: [RESTRICTED, CONFIDENTIAL, SECRET, TOP_SECRET]
        description: Filtrar por nivel de clasificación
      - in: query
        name: limit
        type: integer
        default: 50
        description: Número máximo de resultados
      - in: query
        name: offset
        type: integer
        default: 0
        description: Offset para paginación
    responses:
      200:
        description: Lista de archivos
        schema:
          type: object
          properties:
            files:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  title:
                    type: string
                  original_filename:
                    type: string
                  file_size:
                    type: integer
                  mime_type:
                    type: string
                  classification_level:
                    type: string
                  created_at:
                    type: string
                    format: date-time
            total:
              type: integer
      403:
        description: Sin autorización para la clasificación solicitada
      404:
        description: Usuario no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Filtros opcionales
        classification = request.args.get('classification')
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Consulta base
        query = SecureFile.query.filter_by(user_id=user.id)
        
        # Aplicar filtros
        if classification:
            if not user.has_clearance(classification):
                return jsonify({'error': 'Sin autorización para esta clasificación'}), 403
            query = query.filter_by(classification_level=classification)
        
        # Solo archivos que el usuario puede ver según su nivel de autorización
        user_clearance_level = current_app.config['CLASSIFICATION_LEVELS'][user.clearance_level]
        allowed_classifications = [
            level for level, value in current_app.config['CLASSIFICATION_LEVELS'].items()
            if value <= user_clearance_level
        ]
        query = query.filter(SecureFile.classification_level.in_(allowed_classifications))
        
        # Aplicar paginación
        files = query.order_by(SecureFile.created_at.desc()).limit(limit).offset(offset).all()
        
        # Convertir a diccionario
        files_data = [file.to_dict() for file in files]
        
        return jsonify({
            'files': files_data,
            'count': len(files_data),
            'limit': limit,
            'offset': offset
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error listando archivos: {str(e)}'}), 500

@files_bp.route('/<int:file_id>', methods=['GET'])
@jwt_required()
def get_file_info(file_id):
    """
    Obtener información de un archivo específico
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        type: integer
        required: true
        description: ID del archivo
    responses:
      200:
        description: Información del archivo
        schema:
          type: object
          properties:
            file:
              type: object
              properties:
                id:
                  type: integer
                title:
                  type: string
                original_filename:
                  type: string
                file_size:
                  type: integer
                mime_type:
                  type: string
                classification_level:
                  type: string
                file_hash:
                  type: string
                created_at:
                  type: string
                  format: date-time
      403:
        description: Sin permisos o autorización
      404:
        description: Archivo o usuario no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Buscar archivo
        file = SecureFile.query.get(file_id)
        
        if not file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Verificar permisos
        if file.user_id != user.id:
            return jsonify({'error': 'Sin permisos para este archivo'}), 403
        
        # Verificar autorización de clasificación
        if not user.has_clearance(file.classification_level):
            return jsonify({'error': 'Sin autorización para esta clasificación'}), 403
        
        # Registrar acceso
        access_log = FileAccessLog(
            file_id=file.id,
            user_id=user.id,
            access_type='VIEW',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(access_log)
        db.session.commit()
        
        return jsonify({'file': file.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo archivo: {str(e)}'}), 500

@files_bp.route('/<int:file_id>/download', methods=['POST'])
@jwt_required()
def download_file(file_id):
    """
    Descargar archivo cifrado (requiere operación firmada)
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        type: integer
        required: true
        description: ID del archivo a descargar
      - in: body
        name: body
        schema:
          type: object
          properties:
            digital_signature:
              type: string
              description: Firma digital de la operación (opcional)
    responses:
      200:
        description: Archivo descargado exitosamente
        schema:
          type: object
          properties:
            file:
              type: object
              properties:
                id:
                  type: integer
                title:
                  type: string
                encrypted_content:
                  type: string
                  description: Contenido cifrado en base64
                encrypted_aes_key:
                  type: string
                file_hash:
                  type: string
                digital_signature:
                  type: string
      403:
        description: Sin permisos o autorización
      404:
        description: Archivo no encontrado
    """
    try:
        # Body JSON es opcional para descarga
        data = request.get_json(silent=True) or {}
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Buscar archivo
        file = SecureFile.query.get(file_id)
        
        if not file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Verificar permisos
        if file.user_id != user.id:
            return jsonify({'error': 'Sin permisos para este archivo'}), 403
        
        # Verificar autorización
        if not user.has_clearance(file.classification_level):
            return jsonify({'error': 'Sin autorización para esta clasificación'}), 403
        
        # TODO: Verificar operación firmada para descargas
        # En una implementación completa, aquí se verificaría que existe
        # una operación firmada válida para esta descarga
        
        # Preparar datos para descarga
        download_data = {
            'file_id': file.id,
            'title': file.title,
            'original_filename': file.original_filename,
            'file_size': file.file_size,
            'mime_type': file.mime_type,
            'classification_level': file.classification_level,
            'encrypted_content': base64.b64encode(file.encrypted_content).decode('utf-8'),
            'encrypted_aes_key': file.encrypted_aes_key,
            'file_hash': file.file_hash,
            'digital_signature': file.digital_signature,
            'signature_timestamp': file.signature_timestamp.isoformat()
        }
        
        # Registrar descarga
        access_log = FileAccessLog(
            file_id=file.id,
            user_id=user.id,
            access_type='DOWNLOAD',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(access_log)
        
        audit_log = AuditLog(
            user_id=user.id,
            action='FILE_DOWNLOAD',
            resource_type='FILE',
            resource_id=file.id,
            details=json.dumps({
                'filename': file.original_filename,
                'classification': file.classification_level
            }),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({
            'message': 'Archivo listo para descarga',
            'download_data': download_data
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error descargando archivo: {str(e)}'}), 500

@files_bp.route('/<int:file_id>', methods=['DELETE'])
@jwt_required()
def delete_file(file_id):
    """
    Eliminar archivo (requiere operación firmada)
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        type: integer
        required: true
        description: ID del archivo a eliminar
    responses:
      200:
        description: Archivo eliminado exitosamente
        schema:
          type: object
          properties:
            message:
              type: string
              example: Archivo eliminado exitosamente
      403:
        description: Sin permisos para eliminar este archivo
      404:
        description: Archivo no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Buscar archivo
        file = SecureFile.query.get(file_id)
        
        if not file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Verificar permisos
        if file.user_id != user.id and not user.is_admin:
            return jsonify({'error': 'Sin permisos para eliminar este archivo'}), 403
        
        # TODO: Verificar operación firmada para eliminación
        
        # Guardar info para auditoría antes de eliminar
        file_info = {
            'filename': file.original_filename,
            'classification': file.classification_level,
            'size': file.file_size
        }
        
        # Eliminar archivo
        db.session.delete(file)
        
        # Registrar eliminación
        audit_log = AuditLog(
            user_id=user.id,
            action='FILE_DELETE',
            resource_type='FILE',
            resource_id=file_id,
            details=json.dumps(file_info),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({'message': 'Archivo eliminado exitosamente'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error eliminando archivo: {str(e)}'}), 500

@files_bp.route('/<int:file_id>/access-log', methods=['GET'])
@jwt_required()
def get_file_access_log(file_id):
    """
    Obtener log de accesos a un archivo (solo propietarios y admins)
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        type: integer
        required: true
        description: ID del archivo
    responses:
      200:
        description: Log de accesos al archivo
        schema:
          type: object
          properties:
            file_id:
              type: integer
            logs:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  user_id:
                    type: integer
                  access_type:
                    type: string
                    enum: [UPLOAD, VIEW, DOWNLOAD, DELETE]
                  accessed_at:
                    type: string
                    format: date-time
                  ip_address:
                    type: string
                  success:
                    type: boolean
      403:
        description: Sin permisos para ver este log
      404:
        description: Archivo no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Buscar archivo
        file = SecureFile.query.get(file_id)
        
        if not file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Verificar permisos
        if file.user_id != user.id and not user.is_admin:
            return jsonify({'error': 'Sin permisos para ver el log de este archivo'}), 403
        
        # Obtener logs de acceso
        access_logs = FileAccessLog.query.filter_by(file_id=file_id).order_by(
            FileAccessLog.accessed_at.desc()
        ).limit(100).all()
        
        logs_data = []
        for log in access_logs:
            logs_data.append({
                'id': log.id,
                'user_id': log.user_id,
                'user_email': log.user.email if log.user else 'Usuario eliminado',
                'access_type': log.access_type,
                'ip_address': log.ip_address,
                'success': log.success,
                'accessed_at': log.accessed_at.isoformat(),
                'error_message': log.error_message
            })
        
        return jsonify({
            'file_id': file_id,
            'access_logs': logs_data,
            'count': len(logs_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error obteniendo log de accesos: {str(e)}'}), 500

@files_bp.route('/verify-integrity/<int:file_id>', methods=['POST'])
@jwt_required()
def verify_file_integrity(file_id):
    """
    Verificar integridad de un archivo
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        type: integer
        required: true
        description: ID del archivo a verificar
    responses:
      200:
        description: Resultado de la verificación de integridad
        schema:
          type: object
          properties:
            file_id:
              type: integer
            integrity_ok:
              type: boolean
              description: true si el archivo no ha sido modificado
            original_hash:
              type: string
              description: Hash original del archivo
            current_hash:
              type: string
              description: Hash actual del archivo
            message:
              type: string
      403:
        description: Sin permisos para verificar este archivo
      404:
        description: Archivo no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Buscar archivo
        file = SecureFile.query.get(file_id)
        
        if not file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Verificar permisos
        if file.user_id != user.id:
            return jsonify({'error': 'Sin permisos para este archivo'}), 403
        
        # Verificar hash del contenido cifrado
        current_hash = crypto_manager.calculate_file_hash(file.encrypted_content)
        integrity_ok = (current_hash == file.encrypted_hash)
        
        # Actualizar contador de verificaciones
        file.integrity_checks += 1
        file.last_integrity_check = datetime.utcnow()
        
        db.session.commit()
        
        # Registrar verificación
        audit_log = AuditLog(
            user_id=user.id,
            action='INTEGRITY_CHECK',
            resource_type='FILE',
            resource_id=file.id,
            details=json.dumps({
                'integrity_ok': integrity_ok,
                'expected_hash': file.encrypted_hash,
                'current_hash': current_hash
            }),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=integrity_ok
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({
            'file_id': file_id,
            'integrity_ok': integrity_ok,
            'last_check': file.last_integrity_check.isoformat(),
            'total_checks': file.integrity_checks,
            'message': 'Integridad verificada' if integrity_ok else 'ALERTA: Integridad comprometida'
        }), 200 if integrity_ok else 422
        
    except Exception as e:
        return jsonify({'error': f'Error verificando integridad: {str(e)}'}), 500


# ============================================================================
# FILE SHARING ENDPOINTS (Zero Trust Architecture)
# ============================================================================

@files_bp.route('/<int:file_id>/share', methods=['POST'])
@jwt_required()
def share_file(file_id):
    """
    Compartir archivo con otro usuario (Zero Trust - re-encriptación)
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        type: integer
        required: true
        description: ID del archivo a compartir
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - recipient_email
            - password
            - encrypted_aes_key_for_recipient
          properties:
            recipient_email:
              type: string
              example: recipient@example.com
            password:
              type: string
              description: Contraseña del usuario para descifrar su clave privada
            encrypted_aes_key_for_recipient:
              type: string
              description: Clave AES re-cifrada con la clave pública del destinatario
            can_download:
              type: boolean
              default: false
              description: Permitir descarga del archivo
            can_share:
              type: boolean
              default: false
              description: Permitir re-compartir el archivo
            expires_at:
              type: string
              format: date-time
              description: Fecha de expiración del acceso compartido
    responses:
      201:
        description: Archivo compartido exitosamente
        schema:
          type: object
          properties:
            message:
              type: string
            share_id:
              type: integer
            shared_with:
              type: string
            expires_at:
              type: string
              format: date-time
      400:
        description: Error en validación
      403:
        description: Sin permisos para compartir
      404:
        description: Archivo o destinatario no encontrado
    """
    try:
        data = request.get_json()
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Validar datos requeridos
        if not data.get('recipient_email'):
            return jsonify({'error': 'Email del destinatario requerido'}), 400
        
        if not data.get('password'):
            return jsonify({'error': 'Contraseña requerida para descifrar clave privada'}), 400
        
        if not data.get('encrypted_aes_key_for_recipient'):
            return jsonify({'error': 'Clave AES re-cifrada requerida'}), 400
        
        # Buscar archivo
        file = SecureFile.query.get(file_id)
        if not file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Verificar que el usuario es el propietario
        if file.user_id != user.id:
            return jsonify({'error': 'Solo el propietario puede compartir el archivo'}), 403
        
        # Buscar destinatario
        recipient = User.query.filter_by(email=data['recipient_email']).first()
        if not recipient:
            return jsonify({'error': 'Destinatario no encontrado'}), 404
        
        # No permitir compartir consigo mismo
        if recipient.id == user.id:
            return jsonify({'error': 'No puede compartir un archivo consigo mismo'}), 400
        
        # Verificar que el destinatario tiene autorización para este nivel de clasificación
        if not recipient.has_clearance(file.classification_level):
            return jsonify({
                'error': f'El destinatario no tiene autorización para clasificación {file.classification_level}'
            }), 403
        
        # Verificar que el destinatario está activo
        if not recipient.is_active:
            return jsonify({'error': 'El destinatario no está activo'}), 403
        
        # Verificar que no existe ya un share activo para este usuario
        existing_share = FileShare.query.filter_by(
            file_id=file_id,
            shared_with_id=recipient.id
        ).first()
        
        if existing_share:
            # Verificar si ya expiró
            if existing_share.expires_at and existing_share.expires_at < datetime.utcnow():
                # Eliminar el share expirado
                db.session.delete(existing_share)
                db.session.commit()
            else:
                return jsonify({'error': 'Ya existe un acceso compartido activo para este usuario'}), 400
        
        # Verificar contraseña del usuario (para validar que tiene acceso a su clave privada)
        if not user.check_password(data['password']):
            return jsonify({'error': 'Contraseña incorrecta'}), 401
        
        # Parsear fecha de expiración si se proporciona
        expires_at = None
        if data.get('expires_at'):
            try:
                expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
            except:
                return jsonify({'error': 'Formato de fecha inválido'}), 400
        
        # Crear registro de compartir
        file_share = FileShare(
            file_id=file_id,
            shared_by_id=user.id,
            shared_with_id=recipient.id,
            encrypted_aes_key_for_recipient=data['encrypted_aes_key_for_recipient'],
            can_read=True,  # Siempre permitir lectura
            can_download=data.get('can_download', False),
            can_share=data.get('can_share', False),
            expires_at=expires_at
        )
        
        db.session.add(file_share)
        
        # Registrar en log de acceso
        access_log = FileAccessLog(
            file_id=file_id,
            user_id=user.id,
            access_type='SHARE',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(access_log)
        
        # Registrar en auditoría
        audit_log = AuditLog(
            user_id=user.id,
            action='FILE_SHARE',
            resource_type='FILE',
            resource_id=file_id,
            details=json.dumps({
                'filename': file.original_filename,
                'shared_with': recipient.email,
                'can_download': data.get('can_download', False),
                'can_share': data.get('can_share', False),
                'expires_at': expires_at.isoformat() if expires_at else None
            }),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({
            'message': 'Archivo compartido exitosamente',
            'share_id': file_share.id,
            'shared_with': recipient.email,
            'can_download': file_share.can_download,
            'can_share': file_share.can_share,
            'expires_at': file_share.expires_at.isoformat() if file_share.expires_at else None
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error compartiendo archivo: {str(e)}'}), 500


@files_bp.route('/shared-with-me', methods=['GET'])
@jwt_required()
def list_shared_files():
    """
    Listar archivos compartidos conmigo
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: query
        name: limit
        type: integer
        default: 50
        description: Número máximo de resultados
      - in: query
        name: offset
        type: integer
        default: 0
        description: Offset para paginación
    responses:
      200:
        description: Lista de archivos compartidos
        schema:
          type: object
          properties:
            shared_files:
              type: array
              items:
                type: object
                properties:
                  share_id:
                    type: integer
                  file_id:
                    type: integer
                  title:
                    type: string
                  filename:
                    type: string
                  shared_by:
                    type: string
                    description: Email del usuario que compartió
                  shared_at:
                    type: string
                    format: date-time
                  expires_at:
                    type: string
                    format: date-time
                  can_download:
                    type: boolean
                  can_share:
                    type: boolean
            count:
              type: integer
      404:
        description: Usuario no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Filtros opcionales
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Consultar archivos compartidos conmigo
        shares = FileShare.query.filter_by(shared_with_id=user.id).order_by(
            FileShare.shared_at.desc()
        ).limit(limit).offset(offset).all()
        
        shared_files_data = []
        current_time = datetime.utcnow()
        
        for share in shares:
            # Verificar que no haya expirado
            if share.expires_at and share.expires_at < current_time:
                continue
            
            # Obtener información del archivo
            file = share.file
            if not file:
                continue
            
            # Verificar que el usuario tiene autorización para este nivel de clasificación
            if not user.has_clearance(file.classification_level):
                continue
            
            shared_files_data.append({
                'share_id': share.id,
                'file_id': file.id,
                'title': file.title,
                'filename': file.original_filename,
                'file_size': file.file_size,
                'mime_type': file.mime_type,
                'classification_level': file.classification_level,
                'shared_by': share.shared_by.email,
                'shared_at': share.shared_at.isoformat(),
                'expires_at': share.expires_at.isoformat() if share.expires_at else None,
                'can_download': share.can_download,
                'can_share': share.can_share
            })
        
        return jsonify({
            'shared_files': shared_files_data,
            'count': len(shared_files_data),
            'limit': limit,
            'offset': offset
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error listando archivos compartidos: {str(e)}'}), 500


@files_bp.route('/shared/<int:share_id>/download', methods=['POST'])
@jwt_required()
def download_shared_file(share_id):
    """
    Descargar archivo compartido con verificaciones Zero Trust
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: share_id
        type: integer
        required: true
        description: ID del share
      - in: body
        name: body
        schema:
          type: object
          properties:
            totp_code:
              type: string
              description: Código 2FA (si está habilitado)
    responses:
      200:
        description: Archivo descargado exitosamente
        schema:
          type: object
          properties:
            message:
              type: string
            download_data:
              type: object
              properties:
                file_id:
                  type: integer
                title:
                  type: string
                encrypted_content:
                  type: string
                  description: Contenido cifrado en base64
                encrypted_aes_key:
                  type: string
                  description: Clave AES re-cifrada para el destinatario
                file_hash:
                  type: string
                digital_signature:
                  type: string
      400:
        description: Error en validación
      403:
        description: Sin permisos o acceso denegado
      404:
        description: Share o archivo no encontrado
    """
    try:
        data = request.get_json(silent=True) or {}
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Buscar el share
        share = FileShare.query.get(share_id)
        if not share:
            return jsonify({'error': 'Acceso compartido no encontrado'}), 404
        
        # ZERO TRUST CHECK 1: Verificar que el share es para este usuario
        if share.shared_with_id != user.id:
            # Registrar intento de acceso no autorizado
            access_log = FileAccessLog(
                file_id=share.file_id,
                user_id=user.id,
                access_type='DOWNLOAD',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False,
                error_message='Intento de acceso a share de otro usuario'
            )
            db.session.add(access_log)
            db.session.commit()
            
            return jsonify({'error': 'Acceso denegado'}), 403
        
        # ZERO TRUST CHECK 2: Verificar que el share no ha expirado
        if share.expires_at and share.expires_at < datetime.utcnow():
            access_log = FileAccessLog(
                file_id=share.file_id,
                user_id=user.id,
                access_type='DOWNLOAD',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False,
                error_message='Acceso compartido expirado'
            )
            db.session.add(access_log)
            db.session.commit()
            
            return jsonify({'error': 'El acceso compartido ha expirado'}), 403
        
        # ZERO TRUST CHECK 3: Verificar permisos de descarga
        if not share.can_download:
            access_log = FileAccessLog(
                file_id=share.file_id,
                user_id=user.id,
                access_type='DOWNLOAD',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False,
                error_message='Sin permiso de descarga'
            )
            db.session.add(access_log)
            db.session.commit()
            
            return jsonify({'error': 'No tiene permiso de descarga para este archivo'}), 403
        
        # Obtener el archivo
        file = share.file
        if not file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # ZERO TRUST CHECK 4: Verificar autorización de clasificación del usuario
        if not user.has_clearance(file.classification_level):
            access_log = FileAccessLog(
                file_id=file.id,
                user_id=user.id,
                access_type='DOWNLOAD',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False,
                error_message=f'Sin autorización para clasificación {file.classification_level}'
            )
            db.session.add(access_log)
            db.session.commit()
            
            return jsonify({'error': 'Sin autorización para esta clasificación'}), 403
        
        # ZERO TRUST CHECK 5: Verificar que el usuario está activo
        if not user.is_active:
            access_log = FileAccessLog(
                file_id=file.id,
                user_id=user.id,
                access_type='DOWNLOAD',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=False,
                error_message='Usuario inactivo'
            )
            db.session.add(access_log)
            db.session.commit()
            
            return jsonify({'error': 'Usuario inactivo'}), 403
        
        # ZERO TRUST CHECK 6: Verificar 2FA si está habilitado
        if user.is_2fa_enabled:
            totp_code = data.get('totp_code')
            if not totp_code:
                return jsonify({'error': '2FA requerido: proporcione código TOTP'}), 400
            
            if not two_factor_auth.verify_totp(user.totp_secret, totp_code):
                access_log = FileAccessLog(
                    file_id=file.id,
                    user_id=user.id,
                    access_type='DOWNLOAD',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=False,
                    error_message='Código 2FA inválido'
                )
                db.session.add(access_log)
                db.session.commit()
                
                return jsonify({'error': 'Código 2FA inválido'}), 401
        
        # TODO: ZERO TRUST CHECK 7: Verificar restricciones de IP (si se implementa)
        # TODO: ZERO TRUST CHECK 8: Verificar geofencing (si se implementa)
        # TODO: ZERO TRUST CHECK 9: Verificar horarios permitidos (si se implementa)
        
        # Preparar datos de descarga con la clave AES re-cifrada
        download_data = {
            'file_id': file.id,
            'title': file.title,
            'original_filename': file.original_filename,
            'file_size': file.file_size,
            'mime_type': file.mime_type,
            'classification_level': file.classification_level,
            'encrypted_content': base64.b64encode(file.encrypted_content).decode('utf-8'),
            'encrypted_aes_key': share.encrypted_aes_key_for_recipient,  # Clave re-cifrada
            'file_hash': file.file_hash,
            'digital_signature': file.digital_signature,
            'shared_by': share.shared_by.email,
            'signature_timestamp': file.signature_timestamp.isoformat()
        }
        
        # Registrar descarga exitosa
        access_log = FileAccessLog(
            file_id=file.id,
            user_id=user.id,
            access_type='DOWNLOAD',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(access_log)
        
        audit_log = AuditLog(
            user_id=user.id,
            action='SHARED_FILE_DOWNLOAD',
            resource_type='FILE',
            resource_id=file.id,
            details=json.dumps({
                'share_id': share.id,
                'filename': file.original_filename,
                'classification': file.classification_level,
                'shared_by': share.shared_by.email
            }),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({
            'message': 'Archivo compartido listo para descarga',
            'download_data': download_data
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error descargando archivo compartido: {str(e)}'}), 500


@files_bp.route('/shared/<int:share_id>', methods=['DELETE'])
@jwt_required()
def revoke_share(share_id):
    """
    Revocar acceso compartido (solo el propietario del archivo)
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: share_id
        type: integer
        required: true
        description: ID del share a revocar
    responses:
      200:
        description: Acceso revocado exitosamente
        schema:
          type: object
          properties:
            message:
              type: string
      403:
        description: Sin permisos para revocar
      404:
        description: Share no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Buscar el share
        share = FileShare.query.get(share_id)
        if not share:
            return jsonify({'error': 'Acceso compartido no encontrado'}), 404
        
        # Verificar que el usuario es el propietario del archivo
        if share.shared_by_id != user.id and not user.is_admin:
            return jsonify({'error': 'Solo el propietario puede revocar el acceso'}), 403
        
        # Guardar info para auditoría
        share_info = {
            'file_id': share.file_id,
            'shared_with': share.shared_with.email,
            'shared_at': share.shared_at.isoformat()
        }
        
        # Eliminar el share
        db.session.delete(share)
        
        # Registrar revocación
        audit_log = AuditLog(
            user_id=user.id,
            action='SHARE_REVOKE',
            resource_type='FILE_SHARE',
            resource_id=share_id,
            details=json.dumps(share_info),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=True
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({'message': 'Acceso compartido revocado exitosamente'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error revocando acceso: {str(e)}'}), 500


@files_bp.route('/<int:file_id>/shares', methods=['GET'])
@jwt_required()
def list_file_shares(file_id):
    """
    Listar todos los shares de un archivo (solo propietario)
    ---
    tags:
      - files
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        type: integer
        required: true
        description: ID del archivo
    responses:
      200:
        description: Lista de shares del archivo
        schema:
          type: object
          properties:
            file_id:
              type: integer
            shares:
              type: array
              items:
                type: object
                properties:
                  share_id:
                    type: integer
                  shared_with:
                    type: string
                  shared_at:
                    type: string
                    format: date-time
                  expires_at:
                    type: string
                    format: date-time
                  can_download:
                    type: boolean
                  can_share:
                    type: boolean
      403:
        description: Sin permisos
      404:
        description: Archivo no encontrado
    """
    try:
        user_id = get_current_user_id()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Buscar archivo
        file = SecureFile.query.get(file_id)
        if not file:
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Verificar que el usuario es el propietario
        if file.user_id != user.id and not user.is_admin:
            return jsonify({'error': 'Solo el propietario puede ver los shares'}), 403
        
        # Obtener todos los shares del archivo
        shares = FileShare.query.filter_by(file_id=file_id).order_by(
            FileShare.shared_at.desc()
        ).all()
        
        shares_data = []
        for share in shares:
            shares_data.append({
                'share_id': share.id,
                'shared_with': share.shared_with.email,
                'shared_at': share.shared_at.isoformat(),
                'expires_at': share.expires_at.isoformat() if share.expires_at else None,
                'can_download': share.can_download,
                'can_share': share.can_share
            })
        
        return jsonify({
            'file_id': file_id,
            'filename': file.original_filename,
            'shares': shares_data,
            'count': len(shares_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error listando shares: {str(e)}'}), 500
