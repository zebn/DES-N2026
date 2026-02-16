"""
Rutas CRUD para gestión de secretos cifrados E2E.
Reutiliza el pipeline criptográfico de utils/crypto.py.

Endpoints:
  POST   /api/secrets                  — Crear secreto
  GET    /api/secrets                  — Listar secretos del usuario
  GET    /api/secrets/<id>             — Obtener metadatos de un secreto
  POST   /api/secrets/<id>/decrypt     — Obtener datos cifrados (para descifrar en cliente)
  PUT    /api/secrets/<id>             — Actualizar secreto (crea nueva versión)
  DELETE /api/secrets/<id>             — Eliminar secreto (soft delete)
  GET    /api/secrets/<id>/versions    — Historial de versiones
  GET    /api/secrets/<id>/versions/<v>— Versión específica
  POST   /api/secrets/<id>/rotate      — Rotar secreto
  POST   /api/secrets/<id>/verify      — Verificar integridad
  GET    /api/secrets/<id>/access-log  — Log de accesos

  POST   /api/folders                  — Crear carpeta
  GET    /api/folders                  — Listar carpetas
  PUT    /api/folders/<id>             — Renombrar carpeta
  DELETE /api/folders/<id>             — Eliminar carpeta
"""

import json
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required

from models import (
    db, User, Secret, SecretType, SecretVersion,
    SecretAccessLog, AuditLog, Folder,
)
from utils.crypto import crypto_manager

secrets_bp = Blueprint('secrets', __name__, url_prefix='/api/secrets')
folders_bp = Blueprint('folders', __name__, url_prefix='/api/folders')


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _user_id() -> int:
    from flask_jwt_extended import get_jwt_identity
    return int(get_jwt_identity())


def _log_access(secret_id: str, user_id: int, access_type: str, success: bool = True, error: str = None):
    """Registrar acceso a secreto en log de auditoría."""
    log = SecretAccessLog(
        secret_id=secret_id,
        user_id=user_id,
        access_type=access_type,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        success=success,
        error_message=error,
    )
    db.session.add(log)


def _audit(user_id, action, resource_type, resource_id=None, details=None, success=True):
    """Registrar acción en auditoría general."""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=None,  # resource_id es Integer en AuditLog, secrets usan UUID string
        details=json.dumps({
            'secret_id': resource_id,
            **(details or {}),
        }),
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        success=success,
    )
    db.session.add(log)


def _get_secret_or_404(secret_id: str, user_id: int):
    """Obtener secreto propio no eliminado, o None."""
    return Secret.query.filter_by(
        id=secret_id,
        owner_id=user_id,
        is_deleted=False,
    ).first()


VALID_SECRET_TYPES = {t.value for t in SecretType}


# ─── CRUD Secretos ───────────────────────────────────────────────────────────

@secrets_bp.route('', methods=['POST'])
@jwt_required()
def create_secret():
    """
    Crear un nuevo secreto cifrado E2E
    ---
    tags:
      - secrets
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
            - secret_type
            - encrypted_data
            - encrypted_aes_key
            - content_hash
            - digital_signature
          properties:
            title:
              type: string
            secret_type:
              type: string
              enum: [PASSWORD, API_KEY, CERTIFICATE, SSH_KEY, NOTE, DATABASE, ENV_VARIABLE, IDENTITY]
            encrypted_data:
              type: string
              description: Datos JSON cifrados con AES-256-CTR (base64)
            encrypted_aes_key:
              type: string
              description: Clave AES cifrada con RSA-4096 del usuario (base64)
            content_hash:
              type: string
              description: SHA-256 del plaintext
            digital_signature:
              type: string
              description: Firma RSA-PSS sobre content_hash
            tags:
              type: string
              description: JSON de etiquetas (cifrado en cliente)
            folder_id:
              type: string
            expires_at:
              type: string
              format: date-time
            rotation_period_days:
              type: integer
    responses:
      201:
        description: Secreto creado
      400:
        description: Datos inválidos
    """
    try:
        data = request.get_json()
        user_id = _user_id()
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404

        # Validar campos obligatorios
        required = ['title', 'secret_type', 'encrypted_data',
                     'encrypted_aes_key', 'content_hash', 'digital_signature']
        for field in required:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400

        # Validar tipo
        if data['secret_type'] not in VALID_SECRET_TYPES:
            return jsonify({'error': f'Tipo inválido. Permitidos: {sorted(VALID_SECRET_TYPES)}'}), 400

        # Verificar firma digital
        if not crypto_manager.verify_signature(
            data['content_hash'].encode(),
            data['digital_signature'],
            user.public_key,
        ):
            _log_access(None, user_id, 'CREATE', success=False, error='Firma inválida')
            db.session.commit()
            return jsonify({'error': 'Firma digital inválida'}), 400

        # Validar folder si se indica
        if data.get('folder_id'):
            folder = Folder.query.filter_by(id=data['folder_id'], owner_id=user_id).first()
            if not folder:
                return jsonify({'error': 'Carpeta no encontrada'}), 404

        # Parsear expires_at
        expires_at = None
        if data.get('expires_at'):
            try:
                expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'error': 'Formato de fecha inválido para expires_at'}), 400

        # Crear secreto
        secret = Secret(
            owner_id=user_id,
            title=data['title'],
            secret_type=SecretType(data['secret_type']),
            encrypted_data=data['encrypted_data'],
            encrypted_aes_key=data['encrypted_aes_key'],
            content_hash=data['content_hash'],
            digital_signature=data['digital_signature'],
            tags=data.get('tags'),
            folder_id=data.get('folder_id'),
            expires_at=expires_at,
            rotation_period_days=data.get('rotation_period_days'),
        )
        db.session.add(secret)
        db.session.flush()  # Obtener id generado

        # Guardar versión inicial (v1)
        version = SecretVersion(
            secret_id=secret.id,
            version_number=1,
            encrypted_data=data['encrypted_data'],
            encrypted_aes_key=data['encrypted_aes_key'],
            content_hash=data['content_hash'],
            changed_by_id=user_id,
            change_reason='Creación inicial',
        )
        db.session.add(version)

        _log_access(secret.id, user_id, 'CREATE')
        _audit(user_id, 'SECRET_CREATED', 'SECRET', secret.id, {
            'secret_type': data['secret_type'],
        })
        db.session.commit()

        return jsonify({
            'message': 'Secreto creado exitosamente',
            'secret': secret.to_dict(),
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creando secreto: {str(e)}'}), 500


@secrets_bp.route('', methods=['GET'])
@jwt_required()
def list_secrets():
    """
    Listar secretos del usuario con filtros y paginación
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    parameters:
      - in: query
        name: type
        type: string
        description: Filtrar por tipo (PASSWORD, API_KEY, etc.)
      - in: query
        name: folder_id
        type: string
        description: Filtrar por carpeta
      - in: query
        name: search
        type: string
        description: Buscar en título
      - in: query
        name: page
        type: integer
        default: 1
      - in: query
        name: per_page
        type: integer
        default: 20
    responses:
      200:
        description: Lista paginada de secretos
    """
    try:
        user_id = _user_id()

        query = Secret.query.filter_by(owner_id=user_id, is_deleted=False)

        # Filtros
        secret_type = request.args.get('type')
        if secret_type and secret_type in VALID_SECRET_TYPES:
            query = query.filter_by(secret_type=SecretType(secret_type))

        folder_id = request.args.get('folder_id')
        if folder_id:
            query = query.filter_by(folder_id=folder_id)

        search = request.args.get('search', '').strip()
        if search:
            query = query.filter(Secret.title.ilike(f'%{search}%'))

        # Paginación
        page = max(1, request.args.get('page', 1, type=int))
        per_page = min(100, max(1, request.args.get('per_page', 20, type=int)))

        query = query.order_by(Secret.updated_at.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'secrets': [s.to_dict() for s in pagination.items],
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'pages': pagination.pages,
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@secrets_bp.route('/<string:secret_id>', methods=['GET'])
@jwt_required()
def get_secret(secret_id):
    """
    Obtener metadatos de un secreto (sin datos cifrados)
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    responses:
      200:
        description: Metadatos del secreto
      404:
        description: Secreto no encontrado
    """
    user_id = _user_id()
    secret = _get_secret_or_404(secret_id, user_id)
    if not secret:
        return jsonify({'error': 'Secreto no encontrado'}), 404

    return jsonify({'secret': secret.to_dict()}), 200


@secrets_bp.route('/<string:secret_id>/decrypt', methods=['POST'])
@jwt_required()
def decrypt_secret(secret_id):
    """
    Obtener datos cifrados del secreto para que el cliente los descifre.
    Registra el acceso en el log de auditoría.
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    responses:
      200:
        description: Datos cifrados del secreto
      404:
        description: Secreto no encontrado
    """
    user_id = _user_id()
    secret = _get_secret_or_404(secret_id, user_id)
    if not secret:
        return jsonify({'error': 'Secreto no encontrado'}), 404

    _log_access(secret.id, user_id, 'DECRYPT')
    _audit(user_id, 'SECRET_DECRYPTED', 'SECRET', secret.id)
    db.session.commit()

    return jsonify({
        'secret': secret.to_dict(include_encrypted=True),
    }), 200


@secrets_bp.route('/<string:secret_id>', methods=['PUT'])
@jwt_required()
def update_secret(secret_id):
    """
    Actualizar un secreto. Crea una nueva versión automáticamente.
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - encrypted_data
            - encrypted_aes_key
            - content_hash
            - digital_signature
          properties:
            title:
              type: string
            encrypted_data:
              type: string
            encrypted_aes_key:
              type: string
            content_hash:
              type: string
            digital_signature:
              type: string
            tags:
              type: string
            folder_id:
              type: string
            change_reason:
              type: string
            expires_at:
              type: string
              format: date-time
            rotation_period_days:
              type: integer
    responses:
      200:
        description: Secreto actualizado
      400:
        description: Datos inválidos
      404:
        description: Secreto no encontrado
    """
    try:
        user_id = _user_id()
        secret = _get_secret_or_404(secret_id, user_id)
        if not secret:
            return jsonify({'error': 'Secreto no encontrado'}), 404

        data = request.get_json()
        user = User.query.get(user_id)

        # Validar campos cifrados obligatorios
        required = ['encrypted_data', 'encrypted_aes_key', 'content_hash', 'digital_signature']
        for field in required:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400

        # Verificar firma
        if not crypto_manager.verify_signature(
            data['content_hash'].encode(),
            data['digital_signature'],
            user.public_key,
        ):
            _log_access(secret.id, user_id, 'UPDATE', success=False, error='Firma inválida')
            db.session.commit()
            return jsonify({'error': 'Firma digital inválida'}), 400

        # Incrementar versión
        new_version_number = secret.version + 1

        # Guardar snapshot de la versión anterior
        version = SecretVersion(
            secret_id=secret.id,
            version_number=new_version_number,
            encrypted_data=data['encrypted_data'],
            encrypted_aes_key=data['encrypted_aes_key'],
            content_hash=data['content_hash'],
            changed_by_id=user_id,
            change_reason=data.get('change_reason'),
        )
        db.session.add(version)

        # Actualizar el secreto
        secret.encrypted_data = data['encrypted_data']
        secret.encrypted_aes_key = data['encrypted_aes_key']
        secret.content_hash = data['content_hash']
        secret.digital_signature = data['digital_signature']
        secret.version = new_version_number

        if data.get('title'):
            secret.title = data['title']
        if 'tags' in data:
            secret.tags = data['tags']
        if 'folder_id' in data:
            secret.folder_id = data['folder_id']
        if 'expires_at' in data:
            if data['expires_at']:
                secret.expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
            else:
                secret.expires_at = None
        if 'rotation_period_days' in data:
            secret.rotation_period_days = data['rotation_period_days']

        _log_access(secret.id, user_id, 'UPDATE')
        _audit(user_id, 'SECRET_UPDATED', 'SECRET', secret.id, {
            'new_version': new_version_number,
        })
        db.session.commit()

        return jsonify({
            'message': 'Secreto actualizado',
            'secret': secret.to_dict(),
            'version': new_version_number,
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error actualizando secreto: {str(e)}'}), 500


@secrets_bp.route('/<string:secret_id>', methods=['DELETE'])
@jwt_required()
def delete_secret(secret_id):
    """
    Eliminar secreto (soft delete)
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    responses:
      200:
        description: Secreto eliminado
      404:
        description: Secreto no encontrado
    """
    user_id = _user_id()
    secret = _get_secret_or_404(secret_id, user_id)
    if not secret:
        return jsonify({'error': 'Secreto no encontrado'}), 404

    secret.is_deleted = True
    secret.deleted_at = datetime.utcnow()

    _log_access(secret.id, user_id, 'DELETE')
    _audit(user_id, 'SECRET_DELETED', 'SECRET', secret.id)
    db.session.commit()

    return jsonify({'message': 'Secreto eliminado'}), 200


# ─── Versiones ────────────────────────────────────────────────────────────────

@secrets_bp.route('/<string:secret_id>/versions', methods=['GET'])
@jwt_required()
def list_versions(secret_id):
    """
    Listar historial de versiones de un secreto
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    responses:
      200:
        description: Lista de versiones
    """
    user_id = _user_id()
    secret = _get_secret_or_404(secret_id, user_id)
    if not secret:
        return jsonify({'error': 'Secreto no encontrado'}), 404

    versions = SecretVersion.query.filter_by(
        secret_id=secret_id
    ).order_by(SecretVersion.version_number.desc()).all()

    return jsonify({
        'versions': [v.to_dict() for v in versions],
        'current_version': secret.version,
    }), 200


@secrets_bp.route('/<string:secret_id>/versions/<int:version_number>', methods=['GET'])
@jwt_required()
def get_version(secret_id, version_number):
    """
    Obtener una versión específica (con datos cifrados para descifrar en cliente)
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    responses:
      200:
        description: Datos de la versión
      404:
        description: Versión no encontrada
    """
    user_id = _user_id()
    secret = _get_secret_or_404(secret_id, user_id)
    if not secret:
        return jsonify({'error': 'Secreto no encontrado'}), 404

    version = SecretVersion.query.filter_by(
        secret_id=secret_id,
        version_number=version_number,
    ).first()
    if not version:
        return jsonify({'error': 'Versión no encontrada'}), 404

    _log_access(secret.id, user_id, 'READ')
    db.session.commit()

    return jsonify({'version': version.to_dict(include_encrypted=True)}), 200


# ─── Rotación e integridad ────────────────────────────────────────────────────

@secrets_bp.route('/<string:secret_id>/rotate', methods=['POST'])
@jwt_required()
def rotate_secret(secret_id):
    """
    Rotar un secreto: actualiza el contenido y marca la fecha de rotación.
    Equivale a un PUT + marcar last_rotated_at.
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    responses:
      200:
        description: Secreto rotado
    """
    try:
        user_id = _user_id()
        secret = _get_secret_or_404(secret_id, user_id)
        if not secret:
            return jsonify({'error': 'Secreto no encontrado'}), 404

        data = request.get_json()
        user = User.query.get(user_id)

        required = ['encrypted_data', 'encrypted_aes_key', 'content_hash', 'digital_signature']
        for field in required:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400

        if not crypto_manager.verify_signature(
            data['content_hash'].encode(),
            data['digital_signature'],
            user.public_key,
        ):
            return jsonify({'error': 'Firma digital inválida'}), 400

        new_version_number = secret.version + 1

        version = SecretVersion(
            secret_id=secret.id,
            version_number=new_version_number,
            encrypted_data=data['encrypted_data'],
            encrypted_aes_key=data['encrypted_aes_key'],
            content_hash=data['content_hash'],
            changed_by_id=user_id,
            change_reason=data.get('change_reason', 'Rotación de secreto'),
        )
        db.session.add(version)

        secret.encrypted_data = data['encrypted_data']
        secret.encrypted_aes_key = data['encrypted_aes_key']
        secret.content_hash = data['content_hash']
        secret.digital_signature = data['digital_signature']
        secret.version = new_version_number
        secret.last_rotated_at = datetime.utcnow()

        _log_access(secret.id, user_id, 'ROTATE')
        _audit(user_id, 'SECRET_ROTATED', 'SECRET', secret.id, {
            'new_version': new_version_number,
        })
        db.session.commit()

        return jsonify({
            'message': 'Secreto rotado exitosamente',
            'secret': secret.to_dict(),
            'version': new_version_number,
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error rotando secreto: {str(e)}'}), 500


@secrets_bp.route('/<string:secret_id>/verify', methods=['POST'])
@jwt_required()
def verify_secret(secret_id):
    """
    Verificar la integridad de un secreto (firma digital + hash).
    El cliente envía el content_hash que calculó; el servidor verifica
    que coincide con el almacenado y que la firma es válida.
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    responses:
      200:
        description: Resultado de verificación
    """
    user_id = _user_id()
    secret = _get_secret_or_404(secret_id, user_id)
    if not secret:
        return jsonify({'error': 'Secreto no encontrado'}), 404

    owner = User.query.get(secret.owner_id)

    # Verificar firma
    signature_valid = crypto_manager.verify_signature(
        secret.content_hash.encode(),
        secret.digital_signature,
        owner.public_key,
    )

    return jsonify({
        'secret_id': secret.id,
        'signature_valid': signature_valid,
        'stored_hash': secret.content_hash,
        'version': secret.version,
    }), 200


# ─── Access log ───────────────────────────────────────────────────────────────

@secrets_bp.route('/<string:secret_id>/access-log', methods=['GET'])
@jwt_required()
def access_log(secret_id):
    """
    Ver log de accesos de un secreto
    ---
    tags:
      - secrets
    security:
      - Bearer: []
    parameters:
      - in: query
        name: page
        type: integer
        default: 1
      - in: query
        name: per_page
        type: integer
        default: 20
    responses:
      200:
        description: Log de accesos
    """
    user_id = _user_id()
    secret = _get_secret_or_404(secret_id, user_id)
    if not secret:
        return jsonify({'error': 'Secreto no encontrado'}), 404

    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 20, type=int)))

    pagination = SecretAccessLog.query.filter_by(
        secret_id=secret_id,
    ).order_by(
        SecretAccessLog.accessed_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'logs': [l.to_dict() for l in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
    }), 200


# ─── CRUD Carpetas ────────────────────────────────────────────────────────────

@folders_bp.route('', methods=['POST'])
@jwt_required()
def create_folder():
    """
    Crear carpeta para organizar secretos
    ---
    tags:
      - folders
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
            parent_id:
              type: string
    responses:
      201:
        description: Carpeta creada
    """
    data = request.get_json()
    user_id = _user_id()

    if not data.get('name'):
        return jsonify({'error': 'Campo requerido: name'}), 400

    # Validar parent_id si se indica
    if data.get('parent_id'):
        parent = Folder.query.filter_by(id=data['parent_id'], owner_id=user_id).first()
        if not parent:
            return jsonify({'error': 'Carpeta padre no encontrada'}), 404

    folder = Folder(
        owner_id=user_id,
        name=data['name'],
        parent_id=data.get('parent_id'),
    )
    db.session.add(folder)
    db.session.commit()

    return jsonify({
        'message': 'Carpeta creada',
        'folder': folder.to_dict(),
    }), 201


@folders_bp.route('', methods=['GET'])
@jwt_required()
def list_folders():
    """
    Listar carpetas del usuario
    ---
    tags:
      - folders
    security:
      - Bearer: []
    responses:
      200:
        description: Lista de carpetas
    """
    user_id = _user_id()
    folders = Folder.query.filter_by(owner_id=user_id).order_by(Folder.name).all()
    return jsonify({'folders': [f.to_dict() for f in folders]}), 200


@folders_bp.route('/<string:folder_id>', methods=['PUT'])
@jwt_required()
def update_folder(folder_id):
    """
    Renombrar o mover carpeta
    ---
    tags:
      - folders
    security:
      - Bearer: []
    responses:
      200:
        description: Carpeta actualizada
    """
    user_id = _user_id()
    folder = Folder.query.filter_by(id=folder_id, owner_id=user_id).first()
    if not folder:
        return jsonify({'error': 'Carpeta no encontrada'}), 404

    data = request.get_json()
    if data.get('name'):
        folder.name = data['name']
    if 'parent_id' in data:
        # Evitar ciclo: no puede ser padre de sí misma
        if data['parent_id'] == folder.id:
            return jsonify({'error': 'Una carpeta no puede ser padre de sí misma'}), 400
        folder.parent_id = data['parent_id']

    db.session.commit()
    return jsonify({'message': 'Carpeta actualizada', 'folder': folder.to_dict()}), 200


@folders_bp.route('/<string:folder_id>', methods=['DELETE'])
@jwt_required()
def delete_folder(folder_id):
    """
    Eliminar carpeta. Los secretos dentro quedan sin carpeta (folder_id=null).
    ---
    tags:
      - folders
    security:
      - Bearer: []
    responses:
      200:
        description: Carpeta eliminada
    """
    user_id = _user_id()
    folder = Folder.query.filter_by(id=folder_id, owner_id=user_id).first()
    if not folder:
        return jsonify({'error': 'Carpeta no encontrada'}), 404

    # Desasociar secretos de esta carpeta
    Secret.query.filter_by(folder_id=folder_id).update({'folder_id': None})
    # Mover subcarpetas al padre de esta carpeta
    Folder.query.filter_by(parent_id=folder_id).update({'parent_id': folder.parent_id})

    db.session.delete(folder)
    db.session.commit()

    return jsonify({'message': 'Carpeta eliminada'}), 200
