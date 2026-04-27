"""
Rutas CRUD para gestión de grupos de usuarios (RF03).

Endpoints:
  POST   /api/groups                              — Crear grupo (ADMIN, MANAGER)
  GET    /api/groups                              — Listar grupos del usuario
  GET    /api/groups/<id>                         — Detalle del grupo (miembros)
  PUT    /api/groups/<id>                         — Actualizar grupo (OWNER/ADMIN de grupo)
  DELETE /api/groups/<id>                         — Eliminar grupo (OWNER de grupo)
  POST   /api/groups/<id>/members                 — Añadir miembro (OWNER/ADMIN de grupo)
  DELETE /api/groups/<id>/members/<user_id>       — Eliminar miembro (OWNER/ADMIN de grupo)
  PUT    /api/groups/<id>/members/<user_id>/role  — Cambiar rol de miembro (OWNER de grupo)
"""

import json
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy.exc import IntegrityError

from models import db, User, Group, GroupMembership, GroupRole, AuditLog
from utils.decorators import require_role, require_group_role

groups_bp = Blueprint('groups', __name__, url_prefix='/api/groups')


# ─── Helpers ──────────────────────────────────────────────────────────────────

VALID_GROUP_ROLES = {r.value for r in GroupRole}


def _user_id() -> int:
    return int(get_jwt_identity())


def _audit(user_id, action, group_id=None, details=None, success=True):
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type='GROUP',
        resource_id=str(group_id) if group_id else None,
        details=json.dumps(details) if details else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        success=success,
    )
    db.session.add(log)


def _count_owners(group_id: str) -> int:
    return GroupMembership.query.filter_by(
        group_id=group_id, role_in_group=GroupRole.OWNER
    ).count()


# ─── CRUD Grupos ─────────────────────────────────────────────────────────────

@groups_bp.route('', methods=['POST'])
@jwt_required()
@require_role('ADMIN', 'MANAGER')
def create_group():
    """Crear un nuevo grupo. El creador queda como OWNER.
    ---
    tags: [groups]
    security: [{Bearer: []}]
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [name]
          properties:
            name: {type: string}
            description: {type: string}
    responses:
      201: {description: Grupo creado}
      400: {description: Datos inválidos}
      403: {description: Rol insuficiente}
    """
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'El nombre del grupo es obligatorio'}), 400
    if len(name) > 100:
        return jsonify({'error': 'Nombre demasiado largo (máx 100)'}), 400

    description = data.get('description')
    uid = _user_id()

    group = Group(name=name, description=description, created_by_id=uid)
    db.session.add(group)
    db.session.flush()

    membership = GroupMembership(
        group_id=group.id,
        user_id=uid,
        role_in_group=GroupRole.OWNER,
        added_by_id=uid,
    )
    db.session.add(membership)

    _audit(uid, 'GROUP_CREATED', group.id, {'name': name})
    db.session.commit()

    return jsonify({'group': group.to_dict(include_members=True)}), 201


@groups_bp.route('', methods=['GET'])
@jwt_required()
def list_groups():
    """Listar grupos en los que participa el usuario (paginado).
    ---
    tags: [groups]
    security: [{Bearer: []}]
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
      200: {description: Lista de grupos}
    """
    uid = _user_id()
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 20, type=int)))

    query = (
        Group.query
        .join(GroupMembership, GroupMembership.group_id == Group.id)
        .filter(GroupMembership.user_id == uid)
        .order_by(Group.created_at.desc())
    )
    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'groups': [g.to_dict() for g in paginated.items],
        'page': paginated.page,
        'per_page': paginated.per_page,
        'total': paginated.total,
        'pages': paginated.pages,
    }), 200


@groups_bp.route('/<group_id>', methods=['GET'])
@jwt_required()
@require_group_role('OWNER', 'ADMIN', 'MEMBER', 'READONLY')
def get_group(group_id):
    """Obtener detalle de un grupo (incluye miembros).
    ---
    tags: [groups]
    security: [{Bearer: []}]
    parameters:
      - in: path
        name: group_id
        required: true
        type: string
    responses:
      200: {description: Grupo con miembros}
      404: {description: Grupo no encontrado o no es miembro}
    """
    group = Group.query.get(group_id)
    return jsonify({'group': group.to_dict(include_members=True)}), 200


@groups_bp.route('/<group_id>', methods=['PUT'])
@jwt_required()
@require_group_role('OWNER', 'ADMIN')
def update_group(group_id):
    """Actualizar nombre/descripción del grupo.
    ---
    tags: [groups]
    security: [{Bearer: []}]
    parameters:
      - in: path
        name: group_id
        required: true
        type: string
      - in: body
        name: body
        schema:
          type: object
          properties:
            name: {type: string}
            description: {type: string}
    responses:
      200: {description: Grupo actualizado}
      403: {description: Sin permisos en el grupo}
      404: {description: Grupo no encontrado}
    """
    data = request.get_json() or {}
    group = Group.query.get(group_id)

    changes = {}
    if 'name' in data:
        name = (data['name'] or '').strip()
        if not name:
            return jsonify({'error': 'El nombre no puede estar vacío'}), 400
        if len(name) > 100:
            return jsonify({'error': 'Nombre demasiado largo (máx 100)'}), 400
        changes['name'] = {'old': group.name, 'new': name}
        group.name = name

    if 'description' in data:
        changes['description'] = {'old': group.description, 'new': data['description']}
        group.description = data['description']

    if changes:
        _audit(_user_id(), 'GROUP_UPDATED', group_id, changes)

    db.session.commit()
    return jsonify({'group': group.to_dict()}), 200


@groups_bp.route('/<group_id>', methods=['DELETE'])
@jwt_required()
@require_group_role('OWNER')
def delete_group(group_id):
    """Eliminar un grupo (solo OWNER). Las membresías caen en cascada.
    ---
    tags: [groups]
    security: [{Bearer: []}]
    parameters:
      - in: path
        name: group_id
        required: true
        type: string
    responses:
      200: {description: Grupo eliminado}
      403: {description: Sin permisos en el grupo}
      404: {description: Grupo no encontrado}
    """
    group = Group.query.get(group_id)
    name = group.name
    uid = _user_id()

    db.session.delete(group)
    _audit(uid, 'GROUP_DELETED', group_id, {'name': name})
    db.session.commit()

    return jsonify({'message': f'Grupo "{name}" eliminado'}), 200


# ─── Miembros ────────────────────────────────────────────────────────────────

@groups_bp.route('/<group_id>/members', methods=['POST'])
@jwt_required()
@require_group_role('OWNER', 'ADMIN')
def add_member(group_id):
    """Añadir un miembro al grupo.
    ---
    tags: [groups]
    security: [{Bearer: []}]
    parameters:
      - in: path
        name: group_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [user_id]
          properties:
            user_id: {type: integer}
            role_in_group:
              type: string
              enum: [OWNER, ADMIN, MEMBER, READONLY]
              default: MEMBER
    responses:
      201: {description: Miembro añadido}
      400: {description: Datos inválidos o ya es miembro}
      404: {description: Grupo o usuario no encontrado}
    """
    data = request.get_json() or {}
    target_user_id = data.get('user_id')
    if target_user_id is None:
        return jsonify({'error': 'user_id es obligatorio'}), 400

    role_str = (data.get('role_in_group') or 'MEMBER').upper()
    if role_str not in VALID_GROUP_ROLES:
        return jsonify({
            'error': 'Rol inválido',
            'valid_roles': sorted(VALID_GROUP_ROLES),
        }), 400

    target = User.query.get(target_user_id)
    if not target or not target.is_active:
        return jsonify({'error': 'Usuario no encontrado o inactivo'}), 404

    if GroupMembership.query.filter_by(group_id=group_id, user_id=target_user_id).first():
        return jsonify({'error': 'El usuario ya es miembro del grupo'}), 400

    membership = GroupMembership(
        group_id=group_id,
        user_id=target_user_id,
        role_in_group=GroupRole(role_str),
        added_by_id=_user_id(),
    )
    db.session.add(membership)

    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'No se pudo añadir el miembro'}), 400

    _audit(_user_id(), 'MEMBER_ADDED', group_id, {
        'user_id': target_user_id, 'role_in_group': role_str,
    })
    db.session.commit()

    return jsonify({'membership': membership.to_dict()}), 201


@groups_bp.route('/<group_id>/members/<int:user_id>', methods=['DELETE'])
@jwt_required()
@require_group_role('OWNER', 'ADMIN')
def remove_member(group_id, user_id):
    """Eliminar un miembro del grupo.
    ---
    tags: [groups]
    security: [{Bearer: []}]
    parameters:
      - in: path
        name: group_id
        required: true
        type: string
      - in: path
        name: user_id
        required: true
        type: integer
    responses:
      200: {description: Miembro eliminado}
      400: {description: No se puede eliminar al último OWNER}
      404: {description: Membresía no encontrada}
    """
    membership = GroupMembership.query.filter_by(
        group_id=group_id, user_id=user_id
    ).first()
    if not membership:
        return jsonify({'error': 'Membresía no encontrada'}), 404

    if membership.role_in_group == GroupRole.OWNER and _count_owners(group_id) <= 1:
        return jsonify({'error': 'No se puede eliminar al único OWNER del grupo'}), 400

    db.session.delete(membership)
    _audit(_user_id(), 'MEMBER_REMOVED', group_id, {'user_id': user_id})
    db.session.commit()

    return jsonify({'message': 'Miembro eliminado'}), 200


@groups_bp.route('/<group_id>/members/<int:user_id>/role', methods=['PUT'])
@jwt_required()
@require_group_role('OWNER')
def change_member_role(group_id, user_id):
    """Cambiar el rol de un miembro del grupo (solo OWNER).
    ---
    tags: [groups]
    security: [{Bearer: []}]
    parameters:
      - in: path
        name: group_id
        required: true
        type: string
      - in: path
        name: user_id
        required: true
        type: integer
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [role_in_group]
          properties:
            role_in_group:
              type: string
              enum: [OWNER, ADMIN, MEMBER, READONLY]
    responses:
      200: {description: Rol actualizado}
      400: {description: Rol inválido o degradación del último OWNER}
      404: {description: Membresía no encontrada}
    """
    data = request.get_json() or {}
    new_role = (data.get('role_in_group') or '').upper()
    if new_role not in VALID_GROUP_ROLES:
        return jsonify({
            'error': 'Rol inválido',
            'valid_roles': sorted(VALID_GROUP_ROLES),
        }), 400

    membership = GroupMembership.query.filter_by(
        group_id=group_id, user_id=user_id
    ).first()
    if not membership:
        return jsonify({'error': 'Membresía no encontrada'}), 404

    old_role = membership.role_in_group.value
    if old_role == new_role:
        return jsonify({'membership': membership.to_dict()}), 200

    if (membership.role_in_group == GroupRole.OWNER
            and new_role != 'OWNER'
            and _count_owners(group_id) <= 1):
        return jsonify({'error': 'No se puede degradar al único OWNER del grupo'}), 400

    membership.role_in_group = GroupRole(new_role)
    _audit(_user_id(), 'MEMBER_ROLE_CHANGED', group_id, {
        'user_id': user_id, 'old_role': old_role, 'new_role': new_role,
    })
    db.session.commit()

    return jsonify({'membership': membership.to_dict()}), 200


@groups_bp.route('/<group_id>/public-keys', methods=['GET'])
@jwt_required()
@require_group_role('OWNER', 'ADMIN', 'MEMBER', 'READONLY')
def list_member_public_keys(group_id):
    """Listar claves públicas RSA de los miembros del grupo.

    Necesario para que el cliente pueda re-cifrar la clave AES de un secreto
    al compartir con el grupo (RF04). Solo accesible por miembros del grupo.
    ---
    tags: [groups]
    security: [{Bearer: []}]
    parameters:
      - in: path
        name: group_id
        required: true
        type: string
    responses:
      200: {description: Claves públicas de los miembros activos}
      403: {description: No es miembro del grupo}
      404: {description: Grupo no encontrado}
    """
    memberships = (
        GroupMembership.query
        .filter_by(group_id=group_id)
        .join(User, User.id == GroupMembership.user_id)
        .filter(User.is_active.is_(True))
        .all()
    )
    return jsonify({
        'group_id': group_id,
        'members': [{
            'user_id': m.user_id,
            'email': m.user.email,
            'nombre': m.user.nombre,
            'apellidos': m.user.apellidos,
            'role_in_group': m.role_in_group.value,
            'public_key': m.user.public_key,
        } for m in memberships],
    }), 200
