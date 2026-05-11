# Sistema RBAC — Control de Acceso Basado en Roles

## Proyecto DES-N2026

**Implementado en:** `feature/rbac-roles`
**Fecha:** 2026-02-23
**Requisito PRD:** RF02 — Sistema de roles RBAC

---

## 1. Resumen

El sistema RBAC (Role-Based Access Control) reemplaza el modelo anterior basado en `is_admin` + `clearance_level` (niveles de clasificación militar) por un sistema de **4 roles organizacionales** más adecuado para la gestión de identidades y secretos.

### Antes vs. Después

| Aspecto | Antes | Después |
|---------|-------|---------|
| Modelo de roles | `is_admin` (bool) + `clearance_level` (RESTRICTED..TOP_SECRET) | `role` (Enum: ADMIN, MANAGER, USER, AUDITOR) |
| Decorador | `@require_clearance('SECRET')` | `@require_role('ADMIN', 'MANAGER')` |
| JWT claims | `is_admin`, `clearance_level` | `role`, `is_admin` (legacy) |
| Verificación | `user.is_admin` / `user.has_clearance()` | `user.has_role('ADMIN')` |

---

## 2. Roles definidos

| Rol | Descripción | Permisos principales |
|-----|-------------|---------------------|
| **ADMIN** | Administrador del sistema | CRUD usuarios, CRUD grupos, auditorías globales, gestionar roles, backup/restore, CRUD secretos propios |
| **MANAGER** | Gestor de equipos | Crear grupos, gestionar miembros de sus grupos, compartir secretos con sus grupos, CRUD secretos propios, auditorías de sus grupos |
| **USER** | Usuario estándar | CRUD secretos propios, compartir con usuarios/grupos donde participa, auditorías propias |
| **AUDITOR** | Auditor (solo lectura) | Lectura de auditorías y logs (sin acceso a secretos), informes de actividad |

---

## 3. Implementación técnica

### 3.1 Modelo de datos (`models.py`)

```python
class UserRole(enum.Enum):
    ADMIN = 'ADMIN'
    MANAGER = 'MANAGER'
    USER = 'USER'
    AUDITOR = 'AUDITOR'

class User(db.Model):
    # Campo RBAC principal
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.USER)

    # Campos legacy (se mantienen para compatibilidad)
    is_admin = db.Column(db.Boolean, default=False)
    clearance_level = db.Column(db.String(20), default='CONFIDENTIAL')
```

**Métodos añadidos al modelo User:**

| Método | Descripción |
|--------|-------------|
| `has_role(*roles)` | Verifica si el usuario tiene uno de los roles indicados (strings) |
| `is_admin_role` | Property: `True` si `role == ADMIN` |

### 3.2 Decorador `@require_role()` (`utils/decorators.py`)

```python
from utils.decorators import require_role

@app.route('/admin-only')
@jwt_required()
@require_role('ADMIN')
def admin_endpoint():
    ...

@app.route('/managers-too')
@jwt_required()
@require_role('ADMIN', 'MANAGER')
def manager_endpoint():
    ...
```

**Comportamiento:**
- Extrae el `user_id` del JWT
- Verifica que el usuario exista y esté activo
- Comprueba `user.role.value` contra los roles permitidos
- Retorna 403 con `required_roles` y `current_role` si no tiene permisos

### 3.3 JWT Claims

El token JWT ahora incluye el campo `role`:

```json
{
  "sub": "1",
  "email": "admin@example.com",
  "role": "ADMIN",
  "clearance_level": "CONFIDENTIAL",
  "is_admin": true
}
```

### 3.4 Compatibilidad legacy

Los campos `is_admin` y `clearance_level` se **mantienen** en la base de datos para:
- No romper frontend existente que use `is_admin`
- Mantener compatibilidad con `routes/files.py` durante la transición
- `is_admin` se sincroniza automáticamente: `is_admin = (role == ADMIN)`

---

## 4. Endpoints API

### 4.1 Listar roles disponibles

```
GET /api/auth/roles
Authorization: Bearer <token>
```

**Respuesta:**
```json
{
  "roles": {
    "ADMIN": {
      "description": "Administrador del sistema",
      "permissions": ["CRUD usuarios", "CRUD grupos", ...]
    },
    "MANAGER": { ... },
    "USER": { ... },
    "AUDITOR": { ... }
  }
}
```

### 4.2 Cambiar rol de usuario

```
PUT /api/auth/users/:id/role
Authorization: Bearer <token>   (requiere rol ADMIN)
Content-Type: application/json

{
  "role": "MANAGER"
}
```

**Respuesta exitosa (200):**
```json
{
  "message": "Rol de user@example.com cambiado de USER a MANAGER",
  "user": { ... }
}
```

**Restricciones:**
- Solo usuarios con rol `ADMIN` pueden cambiar roles
- Un admin no puede cambiar su propio rol (previene quedarse sin admins)
- Se registra en auditoría: acción `ROLE_CHANGED`

---

## 5. Archivos modificados

| Archivo | Cambio |
|---------|--------|
| `models.py` | Enum `UserRole`, campo `role`, métodos `has_role()` y `is_admin_role` |
| `utils/decorators.py` | `@require_role()` usa campo `role` real (no mapeo provisional) |
| `routes/auth.py` | Registro acepta `role`, JWT incluye `role`, endpoints `/roles` y `/users/:id/role` |
| `routes/files.py` | `is_admin` → `has_role('ADMIN')` en verificaciones de permisos |
| `config.py` | Constantes `RBAC_ROLES` y `DEFAULT_ROLE` |
| `migrate_roles.py` | Script de migración de BD (añade columna `role`, migra `is_admin`) |

---

## 6. Migración de base de datos

Para bases de datos existentes, ejecutar:

```bash
python migrate_roles.py
```

**Qué hace:**
1. Añade columna `role` a tabla `users` (si no existe)
2. Migra `is_admin=True` → `role='ADMIN'`
3. Asigna `role='USER'` a usuarios sin rol
4. Muestra resumen de roles asignados

El script es **idempotente** — se puede ejecutar múltiples veces sin problema.

---

## 7. Uso en endpoints existentes y nuevos

### Verificación directa (en endpoints sin decorador):
```python
user = User.query.get(user_id)
if not user.has_role('ADMIN'):
    return jsonify({'error': 'Se requiere rol ADMIN'}), 403
```

### Con decorador (recomendado):
```python
@auth_bp.route('/users', methods=['GET'])
@jwt_required()
@require_role('ADMIN')          # ← solo ADMIN
def list_users():
    ...
```

### En el frontend (Angular):
```typescript
// El JWT decodificado incluye 'role'
const token = this.jwtHelper.decodeToken(accessToken);
const userRole = token.role;  // 'ADMIN' | 'MANAGER' | 'USER' | 'AUDITOR'
```
