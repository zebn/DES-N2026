"""
RF07 — Backup y restauración de secretos.

El modelo de cifrado es de doble capa:
  - Capa interna (E2E): los secretos ya llegan cifrados con AES-256-CTR y su
    clave AES cifrada con la RSA-4096 del propietario.  El servidor NUNCA ve
    el plaintext.
  - Capa externa (backup): el paquete JSON con los secretos se cifra con una
    clave derivada de la contraseña de backup (Argon2id + AES-256-CTR).

Formato del archivo .vault (JSON):
  {
    "format_version": "1.0",
    "created_at": "<ISO8601>",
    "user_id": <int>,
    "user_email": "<str>",
    "scope": "personal" | "system",
    "kdf_params": {
      "algorithm": "Argon2id",
      "time_cost": 3,
      "memory_cost": 65536,
      "parallelism": 4,
      "salt": "<base64 32 bytes>",
      "hash_len": 32
    },
    "iv": "<base64 16 bytes>",           # nonce AES-CTR
    "encrypted_payload": "<base64>",     # AES-256-CTR( JSON payload )
    "payload_hash": "<SHA-256 hex>",     # SHA-256 del plaintext antes de cifrar
  }

Endpoints:
  POST /api/backup/export          — Exportar secretos propios (JWT + 2FA opcional)
  POST /api/backup/import          — Importar desde .vault      (JWT + 2FA opcional)
  POST /api/backup/system          — Backup completo (ADMIN)     (JWT + ADMIN + 2FA)
"""

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Blueprint, request, jsonify, Response
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import (
    db, User, Secret, SecretVersion, Folder, AuditLog, GroupMembership
)
from utils.decorators import require_role
from utils.totp import two_factor_auth

backup_bp = Blueprint('backup', __name__, url_prefix='/api/backup')

# ─── Constantes Argon2id ───────────────────────────────────────────────────

_ARGON2_TIME      = 3
_ARGON2_MEMORY    = 65536   # 64 MB
_ARGON2_PARALLEL  = 4
_ARGON2_HASH_LEN  = 32
_MIN_PASSWORD_LEN = 8
_MAX_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MB


# ─── Helpers criptográficos ────────────────────────────────────────────────

def _derive_backup_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave AES-256 a partir de la contraseña usando Argon2id."""
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=_ARGON2_TIME,
        memory_cost=_ARGON2_MEMORY,
        parallelism=_ARGON2_PARALLEL,
        hash_len=_ARGON2_HASH_LEN,
        type=Type.ID,
    )


def _encrypt_payload(payload_bytes: bytes, password: str) -> dict:
    """
    Cifra un bloque de bytes con Argon2id + AES-256-CTR.
    Devuelve el objeto JSON-serializable con todos los campos necesarios para
    descifrar, más el hash del plaintext para verificación de integridad.
    """
    salt = secrets.token_bytes(32)
    iv   = secrets.token_bytes(16)
    key  = _derive_backup_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc    = cipher.encryptor()
    ciphertext = enc.update(payload_bytes) + enc.finalize()

    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    return {
        'kdf_params': {
            'algorithm':   'Argon2id',
            'time_cost':   _ARGON2_TIME,
            'memory_cost': _ARGON2_MEMORY,
            'parallelism': _ARGON2_PARALLEL,
            'salt':        base64.b64encode(salt).decode(),
            'hash_len':    _ARGON2_HASH_LEN,
        },
        'iv':                base64.b64encode(iv).decode(),
        'encrypted_payload': base64.b64encode(ciphertext).decode(),
        'payload_hash':      payload_hash,
    }


def _decrypt_payload(vault: dict, password: str) -> bytes:
    """
    Descifra un vault.  Lanza ValueError si la contraseña es incorrecta o
    el payload está corrompido.
    """
    kdf      = vault['kdf_params']
    salt     = base64.b64decode(kdf['salt'])
    iv       = base64.b64decode(vault['iv'])
    ct       = base64.b64decode(vault['encrypted_payload'])

    key = _derive_backup_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    dec    = cipher.decryptor()
    plaintext = dec.update(ct) + dec.finalize()

    # Verificar integridad
    actual_hash = hashlib.sha256(plaintext).hexdigest()
    if actual_hash != vault.get('payload_hash'):
        raise ValueError('Contraseña incorrecta o archivo corrupto (hash no coincide)')

    return plaintext


def _verify_2fa_if_enabled(user: User, data: dict) -> str | None:
    """
    Si el usuario tiene 2FA activo exige totp_code en el body.
    Devuelve un mensaje de error o None si está OK.
    """
    if not user.is_2fa_enabled:
        return None
    totp_code = (data.get('totp_code') or '').strip()
    if not totp_code:
        return 'El código 2FA es obligatorio para esta operación'
    if not two_factor_auth.verify_totp_login(user.totp_secret, totp_code):
        return 'Código 2FA inválido'
    return None


def _audit(user_id: int, action: str, details: dict = None, success: bool = True,
           error: str = None):
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type='BACKUP',
        details=json.dumps(details) if details else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
        success=success,
        error_message=error,
    )
    db.session.add(log)


def _collect_user_secrets(user_id: int) -> list:
    """Recoge todos los secretos activos de un usuario incluyendo datos cifrados."""
    secrets_q = (
        Secret.query
        .filter_by(owner_id=user_id, is_deleted=False)
        .all()
    )
    return [s.to_dict(include_encrypted=True) for s in secrets_q]


def _collect_user_folders(user_id: int) -> list:
    folders = Folder.query.filter_by(owner_id=user_id).all()
    return [f.to_dict() for f in folders]


# ─── Endpoints ────────────────────────────────────────────────────────────────

@backup_bp.route('/export', methods=['POST'])
@jwt_required()
def export_backup():
    """Exportar los secretos propios a un archivo .vault cifrado.
    ---
    tags: [backup]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [backup_password]
          properties:
            backup_password:
              type: string
              description: Contraseña para cifrar el archivo .vault (mín. 8 caracteres)
            totp_code:
              type: string
              description: Código TOTP (requerido si 2FA está activo)
            include_versions:
              type: boolean
              default: false
              description: Incluir historial de versiones de cada secreto
    responses:
      200:
        description: Archivo .vault (application/json) con los secretos cifrados
      400:
        description: Datos inválidos
      401:
        description: No autenticado o código 2FA inválido
    """
    uid  = int(get_jwt_identity())
    user = User.query.get(uid)
    if not user or not user.is_active:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    data = request.get_json(silent=True) or {}

    # Validar 2FA
    err_2fa = _verify_2fa_if_enabled(user, data)
    if err_2fa:
        _audit(uid, 'BACKUP_EXPORT_FAILED', success=False, error=err_2fa)
        db.session.commit()
        return jsonify({'error': err_2fa}), 401

    # Validar contraseña de backup
    backup_password = data.get('backup_password', '')
    if not backup_password or len(backup_password) < _MIN_PASSWORD_LEN:
        return jsonify({
            'error': f'backup_password es obligatoria y debe tener al menos {_MIN_PASSWORD_LEN} caracteres'
        }), 400

    include_versions = bool(data.get('include_versions', False))

    # Construir payload
    secrets_data = _collect_user_secrets(uid)

    if include_versions:
        for s in secrets_data:
            versions = (
                SecretVersion.query
                .filter_by(secret_id=s['id'])
                .order_by(SecretVersion.version_number.desc())
                .all()
            )
            s['_versions'] = [v.to_dict(include_encrypted=True) for v in versions]

    payload = {
        'secrets': secrets_data,
        'folders': _collect_user_folders(uid),
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode('utf-8')

    # Cifrar con Argon2id + AES-256-CTR
    envelope = _encrypt_payload(payload_bytes, backup_password)

    vault = {
        'format_version': '1.0',
        'created_at':      datetime.now(timezone.utc).isoformat(),
        'user_id':         uid,
        'user_email':      user.email,
        'scope':           'personal',
        'secret_count':    len(secrets_data),
        **envelope,
    }

    _audit(uid, 'BACKUP_EXPORTED', {
        'secret_count': len(secrets_data),
        'include_versions': include_versions,
    })
    db.session.commit()

    return Response(
        json.dumps(vault, ensure_ascii=False),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename="backup_{uid}_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.vault"'
        }
    )


@backup_bp.route('/import', methods=['POST'])
@jwt_required()
def import_backup():
    """Importar secretos desde un archivo .vault.
    ---
    tags: [backup]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [vault, backup_password]
          properties:
            vault:
              type: object
              description: Contenido del archivo .vault (JSON)
            backup_password:
              type: string
              description: Contraseña con la que fue cifrado el .vault
            totp_code:
              type: string
              description: Código TOTP (requerido si 2FA está activo)
            merge:
              type: boolean
              default: true
              description: >
                true  → omite secretos cuyo ID ya existe (conserva el actual).
                false → sobreescribe secretos existentes con los del backup.
    responses:
      200:
        description: Secretos importados correctamente
      400:
        description: Datos inválidos, contraseña incorrecta o .vault corrupto
      401:
        description: No autenticado o código 2FA inválido
    """
    uid  = int(get_jwt_identity())
    user = User.query.get(uid)
    if not user or not user.is_active:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    data = request.get_json(silent=True) or {}

    # Validar 2FA
    err_2fa = _verify_2fa_if_enabled(user, data)
    if err_2fa:
        _audit(uid, 'BACKUP_IMPORT_FAILED', success=False, error=err_2fa)
        db.session.commit()
        return jsonify({'error': err_2fa}), 401

    vault           = data.get('vault')
    backup_password = data.get('backup_password', '')
    merge           = bool(data.get('merge', True))

    if not vault or not isinstance(vault, dict):
        return jsonify({'error': 'vault es obligatorio y debe ser un objeto JSON'}), 400
    if not backup_password:
        return jsonify({'error': 'backup_password es obligatoria'}), 400

    # Validar tamaño aproximado
    vault_str = json.dumps(vault)
    if len(vault_str.encode()) > _MAX_IMPORT_BYTES:
        return jsonify({'error': 'El archivo .vault supera el límite de 50 MB'}), 400

    # Descifrar y verificar integridad
    try:
        plaintext = _decrypt_payload(vault, backup_password)
    except (KeyError, ValueError) as exc:
        _audit(uid, 'BACKUP_IMPORT_FAILED', success=False, error=str(exc))
        db.session.commit()
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        _audit(uid, 'BACKUP_IMPORT_FAILED', success=False, error='Error al descifrar')
        db.session.commit()
        return jsonify({'error': 'Error al descifrar el archivo .vault'}), 400

    try:
        payload = json.loads(plaintext.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return jsonify({'error': 'Payload del .vault no es JSON válido'}), 400

    imported   = 0
    skipped    = 0
    overwritten = 0
    errors     = []

    # Importar carpetas primero (sin sobreescribir las existentes)
    folder_id_map: dict[str, str] = {}  # old_id -> new_or_same_id
    for f_data in payload.get('folders', []):
        old_id = f_data.get('id')
        if not old_id:
            continue
        existing = Folder.query.filter_by(id=old_id, owner_id=uid).first()
        if existing:
            folder_id_map[old_id] = old_id
            continue
        folder = Folder(
            id=old_id,
            owner_id=uid,
            name=f_data.get('name', 'Sin nombre'),
            parent_id=None,  # padres se restauran en segundo paso
        )
        db.session.add(folder)
        folder_id_map[old_id] = old_id

    # Segundo paso: asignar parent_id a las carpetas
    for f_data in payload.get('folders', []):
        old_id    = f_data.get('id')
        parent_id = f_data.get('parent_id')
        if old_id and parent_id and parent_id in folder_id_map:
            folder = Folder.query.filter_by(id=old_id, owner_id=uid).first()
            if folder:
                folder.parent_id = folder_id_map[parent_id]

    # Importar secretos
    for s_data in payload.get('secrets', []):
        secret_id = s_data.get('id')
        if not secret_id:
            errors.append('Secreto sin ID omitido')
            continue

        required = ['title', 'secret_type', 'encrypted_data',
                    'encrypted_aes_key', 'content_hash', 'digital_signature']
        missing  = [k for k in required if not s_data.get(k)]
        if missing:
            errors.append(f'Secreto {secret_id}: campos requeridos faltantes {missing}')
            continue

        existing = Secret.query.get(secret_id)

        if existing:
            if existing.owner_id != uid:
                # No permitir sobreescribir secretos de otro usuario
                errors.append(f'Secreto {secret_id}: pertenece a otro usuario, omitido')
                skipped += 1
                continue

            if merge:
                skipped += 1
                continue

            # Modo reemplazo: actualizar campos cifrados
            existing.encrypted_data     = s_data['encrypted_data']
            existing.encrypted_aes_key  = s_data['encrypted_aes_key']
            existing.content_hash       = s_data['content_hash']
            existing.digital_signature  = s_data['digital_signature']
            existing.title              = s_data.get('title', existing.title)
            existing.is_deleted         = False
            existing.deleted_at         = None
            existing.updated_at         = datetime.utcnow()
            overwritten += 1
            continue

        # Secreto nuevo
        try:
            from models import SecretType as ST
            secret_type = ST(s_data['secret_type'])
        except ValueError:
            errors.append(f'Secreto {secret_id}: tipo inválido "{s_data["secret_type"]}"')
            continue

        # Resolver folder_id (puede no existir en el nuevo contexto)
        folder_id = s_data.get('folder_id')
        if folder_id and folder_id not in folder_id_map:
            folder_id = None

        new_secret = Secret(
            id                  = secret_id,
            owner_id            = uid,
            title               = s_data['title'],
            secret_type         = secret_type,
            encrypted_data      = s_data['encrypted_data'],
            encrypted_aes_key   = s_data['encrypted_aes_key'],
            content_hash        = s_data['content_hash'],
            digital_signature   = s_data['digital_signature'],
            tags                = s_data.get('tags'),
            url                 = s_data.get('url'),
            folder_id           = folder_id,
            version             = s_data.get('version', 1),
            expires_at          = (
                datetime.fromisoformat(s_data['expires_at'])
                if s_data.get('expires_at') else None
            ),
            rotation_period_days = s_data.get('rotation_period_days'),
        )
        db.session.add(new_secret)
        imported += 1

    _audit(uid, 'BACKUP_IMPORTED', {
        'imported':    imported,
        'skipped':     skipped,
        'overwritten': overwritten,
        'errors':      len(errors),
        'merge':       merge,
    })

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify({'error': f'Error al guardar: {str(exc)}'}), 500

    return jsonify({
        'message':     'Importación completada',
        'imported':    imported,
        'skipped':     skipped,
        'overwritten': overwritten,
        'errors':      errors if errors else None,
    }), 200


@backup_bp.route('/system', methods=['POST'])
@jwt_required()
@require_role('ADMIN')
def system_backup():
    """Backup completo del sistema (solo ADMIN). Exporta todos los secretos de todos los usuarios.
    ---
    tags: [backup]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [backup_password]
          properties:
            backup_password:
              type: string
              description: Contraseña para cifrar el .vault del sistema
            totp_code:
              type: string
              description: Código TOTP (requerido si 2FA está activo)
    responses:
      200:
        description: Archivo .vault con todos los secretos del sistema
      401:
        description: No autenticado o código 2FA inválido
      403:
        description: Se requiere rol ADMIN
    """
    uid  = int(get_jwt_identity())
    user = User.query.get(uid)

    data = request.get_json(silent=True) or {}

    # 2FA requerido para backup de sistema
    if user.is_2fa_enabled:
        err_2fa = _verify_2fa_if_enabled(user, data)
        if err_2fa:
            _audit(uid, 'SYSTEM_BACKUP_FAILED', success=False, error=err_2fa)
            db.session.commit()
            return jsonify({'error': err_2fa}), 401
    # Si 2FA no está activo en ADMIN, seguimos (edge case; en producción debería ser obligatorio)

    backup_password = data.get('backup_password', '')
    if not backup_password or len(backup_password) < _MIN_PASSWORD_LEN:
        return jsonify({
            'error': f'backup_password obligatoria, mínimo {_MIN_PASSWORD_LEN} caracteres'
        }), 400

    # Recoger todos los usuarios activos y sus secretos
    users_data = []
    all_users  = User.query.filter_by(is_active=True).all()
    total_secrets = 0

    for u in all_users:
        user_secrets  = _collect_user_secrets(u.id)
        user_folders  = _collect_user_folders(u.id)
        total_secrets += len(user_secrets)
        users_data.append({
            'user': {
                'id':        u.id,
                'email':     u.email,
                'nombre':    u.nombre,
                'apellidos': u.apellidos,
                'role':      u.role.value,
                'public_key': u.public_key,
            },
            'secrets': user_secrets,
            'folders': user_folders,
        })

    payload = {
        'users':          users_data,
        'exported_by':    uid,
        'exported_at':    datetime.now(timezone.utc).isoformat(),
        'total_secrets':  total_secrets,
        'total_users':    len(users_data),
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode('utf-8')

    envelope = _encrypt_payload(payload_bytes, backup_password)

    vault = {
        'format_version': '1.0',
        'created_at':      datetime.now(timezone.utc).isoformat(),
        'exported_by_id':  uid,
        'scope':           'system',
        'total_users':     len(users_data),
        'total_secrets':   total_secrets,
        **envelope,
    }

    _audit(uid, 'SYSTEM_BACKUP_CREATED', {
        'total_users':    len(users_data),
        'total_secrets':  total_secrets,
    })
    db.session.commit()

    return Response(
        json.dumps(vault, ensure_ascii=False),
        mimetype='application/json',
        headers={
            'Content-Disposition': (
                f'attachment; filename="system_backup_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.vault"'
            )
        }
    )
