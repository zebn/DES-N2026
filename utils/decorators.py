"""
Decoradores de autorización y auditoría reutilizables.
Sistema RBAC con roles: ADMIN, MANAGER, USER, AUDITOR.
"""

import functools
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity

from models import db, User, AuditLog


def get_current_user_id() -> int:
    """Helper: obtener user_id como int desde JWT identity (string)."""
    return int(get_jwt_identity())


def require_role(*allowed_roles: str):
    """
    Decorador que restringe el acceso a usuarios con uno de los roles indicados.

    Uso:
        @require_role('ADMIN', 'MANAGER')
        def mi_endpoint():
            ...

    Los roles válidos son: ADMIN, MANAGER, USER, AUDITOR.
    Comprueba el campo `role` (Enum UserRole) del modelo User.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user_id = get_current_user_id()
            user = User.query.get(user_id)

            if not user or not user.is_active:
                return jsonify({'error': 'Usuario no encontrado o desactivado'}), 403

            if not user.has_role(*allowed_roles):
                return jsonify({
                    'error': 'No tiene permisos para esta acción',
                    'required_roles': list(allowed_roles),
                    'current_role': user.role.value,
                }), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def audit_action(action: str, resource_type: str = None):
    """
    Decorador que registra automáticamente un AuditLog tras ejecutar el endpoint.

    Uso:
        @audit_action('SECRET_CREATED', 'SECRET')
        def create_secret():
            ...
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            response = fn(*args, **kwargs)

            # Extraer código de estado
            status_code = response[1] if isinstance(response, tuple) else 200
            success = 200 <= status_code < 400

            try:
                user_id = get_current_user_id()
            except Exception:
                user_id = None

            log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                success=success,
            )
            db.session.add(log)
            db.session.commit()

            return response
        return wrapper
    return decorator
