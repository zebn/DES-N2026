"""
Endpoints de auditoría y logging.
RF06 — Sistema de auditorías.

Permite a ADMIN y AUDITOR consultar logs globales, por usuario y por secreto.
Los usuarios normales solo pueden consultar sus propios logs.
"""

import json
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import db, AuditLog, SecretAccessLog, Secret, User
from utils.decorators import require_role

audit_bp = Blueprint('audit', __name__, url_prefix='/api/audit')


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _user_id() -> int:
    return int(get_jwt_identity())


def _get_user():
    return User.query.get(_user_id())


def _paginate_args():
    """Extraer parámetros de paginación del query string."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    return page, per_page


# ─── GET /api/audit/logs — Logs globales (ADMIN, AUDITOR) ────────────────────

@audit_bp.route('/logs', methods=['GET'])
@jwt_required()
@require_role('ADMIN', 'AUDITOR')
def get_global_logs():
    """
    Listar logs de auditoría globales con filtros y paginación
    ---
    tags:
      - audit
    security:
      - Bearer: []
    parameters:
      - in: query
        name: action
        type: string
        description: Filtrar por tipo de acción (LOGIN_SUCCESS, SECRET_CREATED, etc.)
      - in: query
        name: resource_type
        type: string
        description: Filtrar por tipo de recurso (USER, SECRET, GROUP)
      - in: query
        name: user_id
        type: integer
        description: Filtrar por usuario específico
      - in: query
        name: success
        type: boolean
        description: Filtrar por resultado (true/false)
      - in: query
        name: from_date
        type: string
        format: date-time
        description: Fecha inicio (ISO 8601)
      - in: query
        name: to_date
        type: string
        format: date-time
        description: Fecha fin (ISO 8601)
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
        description: Lista paginada de logs
      403:
        description: Sin permisos
    """
    page, per_page = _paginate_args()
    query = AuditLog.query

    # Filtros opcionales
    action = request.args.get('action')
    if action:
        query = query.filter(AuditLog.action == action)

    resource_type = request.args.get('resource_type')
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    user_id_filter = request.args.get('user_id', type=int)
    if user_id_filter:
        query = query.filter(AuditLog.user_id == user_id_filter)

    success_filter = request.args.get('success')
    if success_filter is not None:
        query = query.filter(AuditLog.success == (success_filter.lower() == 'true'))

    from_date = request.args.get('from_date')
    if from_date:
        try:
            dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp >= dt)
        except ValueError:
            pass

    to_date = request.args.get('to_date')
    if to_date:
        try:
            dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp <= dt)
        except ValueError:
            pass

    # Ordenar por más reciente primero y paginar
    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'logs': [log.to_dict() for log in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': per_page,
        'pages': pagination.pages,
    }), 200


# ─── GET /api/audit/logs/user/<id> — Logs de un usuario ──────────────────────

@audit_bp.route('/logs/user/<int:target_user_id>', methods=['GET'])
@jwt_required()
def get_user_logs(target_user_id):
    """
    Listar logs de un usuario específico.
    ADMIN/AUDITOR pueden ver los de cualquiera; los demás solo los propios.
    ---
    tags:
      - audit
    security:
      - Bearer: []
    parameters:
      - in: path
        name: target_user_id
        type: integer
        required: true
      - in: query
        name: action
        type: string
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
        description: Logs del usuario
      403:
        description: Sin permisos
    """
    user = _get_user()
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    # Verificar permisos
    if user.id != target_user_id and not user.has_role('ADMIN', 'AUDITOR'):
        return jsonify({'error': 'No tiene permisos para ver logs de otro usuario'}), 403

    page, per_page = _paginate_args()
    query = AuditLog.query.filter(AuditLog.user_id == target_user_id)

    action = request.args.get('action')
    if action:
        query = query.filter(AuditLog.action == action)

    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'logs': [log.to_dict() for log in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': per_page,
        'pages': pagination.pages,
    }), 200


# ─── GET /api/audit/logs/secret/<id> — Logs de un secreto ────────────────────

@audit_bp.route('/logs/secret/<string:secret_id>', methods=['GET'])
@jwt_required()
def get_secret_logs(secret_id):
    """
    Listar logs de acceso a un secreto específico.
    Solo el propietario, ADMIN o AUDITOR pueden verlos.
    ---
    tags:
      - audit
    security:
      - Bearer: []
    parameters:
      - in: path
        name: secret_id
        type: string
        required: true
      - in: query
        name: access_type
        type: string
        description: Filtrar por tipo de acceso (CREATE, READ, UPDATE, DELETE, DECRYPT, SHARE, ROTATE)
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
        description: Logs de acceso al secreto
      403:
        description: Sin permisos
      404:
        description: Secreto no encontrado
    """
    user = _get_user()
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    # Verificar que el secreto existe
    secret = Secret.query.get(secret_id)
    if not secret:
        return jsonify({'error': 'Secreto no encontrado'}), 404

    # Solo propietario, ADMIN o AUDITOR
    if secret.owner_id != user.id and not user.has_role('ADMIN', 'AUDITOR'):
        return jsonify({'error': 'No tiene permisos para ver logs de este secreto'}), 403

    page, per_page = _paginate_args()
    query = SecretAccessLog.query.filter(SecretAccessLog.secret_id == secret_id)

    access_type = request.args.get('access_type')
    if access_type:
        query = query.filter(SecretAccessLog.access_type == access_type)

    pagination = query.order_by(SecretAccessLog.accessed_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'logs': [log.to_dict() for log in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': per_page,
        'pages': pagination.pages,
    }), 200


# ─── GET /api/audit/logs/me — Logs propios del usuario autenticado ───────────

@audit_bp.route('/logs/me', methods=['GET'])
@jwt_required()
def get_my_logs():
    """
    Listar logs propios del usuario autenticado
    ---
    tags:
      - audit
    security:
      - Bearer: []
    parameters:
      - in: query
        name: action
        type: string
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
        description: Logs propios
    """
    user_id = _user_id()
    page, per_page = _paginate_args()

    query = AuditLog.query.filter(AuditLog.user_id == user_id)

    action = request.args.get('action')
    if action:
        query = query.filter(AuditLog.action == action)

    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'logs': [log.to_dict() for log in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': per_page,
        'pages': pagination.pages,
    }), 200


# ─── GET /api/audit/stats — Estadísticas de actividad (ADMIN, AUDITOR) ───────

@audit_bp.route('/stats', methods=['GET'])
@jwt_required()
@require_role('ADMIN', 'AUDITOR')
def get_audit_stats():
    """
    Estadísticas de actividad del sistema
    ---
    tags:
      - audit
    security:
      - Bearer: []
    parameters:
      - in: query
        name: days
        type: integer
        default: 30
        description: Número de días para las estadísticas
    responses:
      200:
        description: Estadísticas de actividad
    """
    days = request.args.get('days', 30, type=int)
    since = datetime.utcnow() - timedelta(days=days)

    # Total de eventos
    total_events = AuditLog.query.filter(AuditLog.timestamp >= since).count()

    # Eventos fallidos
    failed_events = AuditLog.query.filter(
        AuditLog.timestamp >= since,
        AuditLog.success == False  # noqa: E712
    ).count()

    # Conteo por acción
    action_counts = (
        db.session.query(AuditLog.action, db.func.count(AuditLog.id))
        .filter(AuditLog.timestamp >= since)
        .group_by(AuditLog.action)
        .all()
    )

    # Conteo por tipo de recurso
    resource_counts = (
        db.session.query(AuditLog.resource_type, db.func.count(AuditLog.id))
        .filter(AuditLog.timestamp >= since, AuditLog.resource_type.isnot(None))
        .group_by(AuditLog.resource_type)
        .all()
    )

    # Usuarios más activos
    top_users = (
        db.session.query(AuditLog.user_id, db.func.count(AuditLog.id).label('count'))
        .filter(AuditLog.timestamp >= since, AuditLog.user_id.isnot(None))
        .group_by(AuditLog.user_id)
        .order_by(db.text('count DESC'))
        .limit(10)
        .all()
    )

    # Accesos a secretos en el periodo
    secret_access_count = SecretAccessLog.query.filter(
        SecretAccessLog.accessed_at >= since
    ).count()

    return jsonify({
        'period_days': days,
        'since': since.isoformat(),
        'total_events': total_events,
        'failed_events': failed_events,
        'success_rate': round((total_events - failed_events) / max(total_events, 1) * 100, 1),
        'by_action': {action: count for action, count in action_counts},
        'by_resource_type': {rt: count for rt, count in resource_counts},
        'top_active_users': [{'user_id': uid, 'event_count': cnt} for uid, cnt in top_users],
        'secret_access_count': secret_access_count,
    }), 200


# ─── POST /api/audit/export — Exportar logs (ADMIN) ──────────────────────────

@audit_bp.route('/export', methods=['POST'])
@jwt_required()
@require_role('ADMIN')
def export_logs():
    """
    Exportar logs de auditoría en formato JSON
    ---
    tags:
      - audit
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            from_date:
              type: string
              format: date-time
            to_date:
              type: string
              format: date-time
            resource_type:
              type: string
            max_records:
              type: integer
              default: 10000
    responses:
      200:
        description: Logs exportados en JSON
    """
    data = request.get_json() or {}

    query = AuditLog.query

    from_date = data.get('from_date')
    if from_date:
        try:
            dt = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp >= dt)
        except ValueError:
            pass

    to_date = data.get('to_date')
    if to_date:
        try:
            dt = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp <= dt)
        except ValueError:
            pass

    resource_type = data.get('resource_type')
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    max_records = min(data.get('max_records', 10000), 50000)

    logs = query.order_by(AuditLog.timestamp.desc()).limit(max_records).all()

    # Registrar la exportación en auditoría
    export_log = AuditLog(
        user_id=_user_id(),
        action='AUDIT_EXPORTED',
        resource_type='AUDIT',
        details=json.dumps({'records_exported': len(logs)}),
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        success=True,
    )
    db.session.add(export_log)
    db.session.commit()

    return jsonify({
        'exported_at': datetime.utcnow().isoformat(),
        'total_records': len(logs),
        'logs': [log.to_dict() for log in logs],
    }), 200
