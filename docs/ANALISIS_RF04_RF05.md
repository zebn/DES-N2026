# Análisis de avance del proyecto SentryVault — DES-N2026

**Fecha:** 2026-05-04
**Rama de referencia:** `develop` tras merge de PRs #13 (RF04), #15 (cobertura), #16 (RF05)

Este documento responde a dos preguntas:

1. ¿Qué requisitos del PRD siguen pendientes una vez integrados RF04 y RF05?
2. ¿Qué se ha construido exactamente en las ramas `feature/secret-sharing` (RF04) y `feature/sessions-rf05` (RF05)?

---

## 1. Estado de los requisitos funcionales (vs. PRD §3)

| RF | Prioridad | Estado | Resumen |
|----|-----------|--------|---------|
| **RF01** — Gestión de secretos (CRUD) | Crítica | ✅ Completo | Modelos `Secret`, `SecretVersion`, `Folder`, `SecretAccessLog`. CRUD + versiones + rotate + verify + access-log. Frontend con list/create/detail. |
| **RF02** — Sistema de roles RBAC | Crítica | ✅ Funcional | Enum `UserRole`, `@require_role`, `GET /api/auth/roles`, `PUT /api/auth/users/:id/role`. Pendiente cosmético: eliminar `clearance_level` legacy. |
| **RF03** — Gestión de grupos | Alta | ✅ Completo | Modelos `Group`/`GroupMembership`, CRUD, miembros con roles, frontend con 4 componentes, tests. |
| **RF04** — Compartición de secretos | Alta | ✅ Completo | Modelo `SecretShare`, 5 endpoints, re-cifrado Zero Knowledge por miembro de grupo, frontend `secret-share-dialog` + `shared-with-me`. **Análisis en §2.** |
| **RF05** — Gestión de sesiones | Alta | ✅ Completo | Modelo `Session`, blocklist JWT, listado y revocación individual/masiva, vista en perfil, eventos de auditoría. **Análisis en §3.** |
| **RF06** — Sistema de auditorías | Alta | ✅ Funcional | `AuditLog` + `SecretAccessLog`, endpoints logs/user/secret/stats/export, frontend con `audit-log` y `audit-stats`. Eventos `SESSION_CREATED`/`SESSION_REVOKED` ya emitidos por RF05. |
| **RF07** — Backup y restauración | Media | ✅ Funcional | Endpoints export/import/system con Argon2id+AES, 2FA requerido, frontend con 4 componentes. |

### 1.1 Pendientes funcionales

A nivel de RF del PRD, **no quedan bloqueadores funcionales**. Lo que queda son detalles cosméticos y mejoras NFR:

| Item | Tipo | Acción |
|------|------|--------|
| Campo `clearance_level` en `User` | Limpieza RBAC (RF02) | Marcar deprecado y/o eliminar; el PRD §3.2.2 lo indica explícitamente. Actualmente se conserva "para compatibilidad" pero ya no tiene efecto funcional. |
| Componentes `secret-edit/` y `secret-versions/` separados | Layout RF01 | El PRD §5.2 los lista como módulos propios; en `develop` la edición y el historial viven dentro del `secret-detail-dialog`. Funcionalmente equivalente, decisión arquitectónica. |
| Verificación de firma del paquete `.vault` | RF07 | Confirmar que el import valida la firma de integridad y soporta merge/reemplazo según PRD §3.7.1. |

### 1.2 Pendientes no funcionales (PRD §4-5)

Aquí sí hay deuda técnica relevante:

| RNF | Estado | Acción |
|-----|--------|--------|
| **Migraciones con Alembic** (PRD §5.2) | ❌ Ausente | No existe `migrations/` ni `alembic` en `requirements.txt`. Hay 5 scripts ad-hoc (`migrate_roles.py`, `migrate_groups.py`, `migrate_add_url_field.py`, `migrate_secret_shares.py`, `migrate_sessions.py`). **Es la deuda más importante**: el esquema solo se sincroniza por `db.create_all()` y los scripts ad-hoc son frágiles. |
| **Cobertura de tests ≥70%** (RNF03) | 🟡 Parcial | El PR #15 elevó la cobertura de backend; falta confirmar el porcentaje exacto, formalizar `pytest-cov` en CI y añadir `tests/test_sharing.py` específico (RF04 se cubre dentro de `test_secrets.py`). |
| **Linting flake8 / eslint** (RNF03) | ❌ Ausente | Ningún `.flake8`, `setup.cfg` ni `.eslintrc` configurado. |
| **Limpieza de código legacy** (PRD §7.4) | ❌ Pendiente | Siguen vivos: `routes/files.py`, `cliente2/src/app/features/files/`, `cliente2/src/app/core/services/file.service.ts`, carpeta `cliente/` (cliente CLI legacy). |
| **CI/CD básico** | ❌ Ausente | Sin workflows de GitHub Actions detectados. |

### 1.3 Recomendación de orden

1. **Alembic** y portado de los 5 `migrate_*.py` a versiones Alembic. Sin esto, cualquier cambio de esquema futuro es un riesgo.
2. **Limpieza de legacy** (`routes/files.py`, `features/files/`, `cliente/`, `clearance_level`).
3. **CI/CD**: workflow que ejecute `pytest --cov` y reporte cobertura, más linting.
4. **`tests/test_sharing.py`** específico para RF04.

---

## 2. RF04 — Compartición de secretos (`feature/secret-sharing`, PR #13)

**Objetivo del PRD §3.4:** permitir compartir un secreto con un usuario o un grupo manteniendo el modelo Zero Knowledge (el servidor nunca ve la clave AES en claro). Reutiliza la lógica de `FileShare` pero adaptada a secretos.

### 2.1 Modelo de datos: `SecretShare`

Definido en [`models.py`](../models.py) (clase `SecretShare`):

| Campo | Tipo | Notas |
|-------|------|-------|
| `id` | UUID (string 36) | PK generada en cliente o servidor |
| `secret_id` | FK → `secrets.id` | `ON DELETE CASCADE` |
| `shared_by_id` | FK → `users.id` | Quién compartió |
| `shared_with_user_id` | FK → `users.id` | Destinatario final (siempre un usuario individual) |
| `shared_with_group_id` | FK → `groups.id` | `ON DELETE SET NULL`. Marca la compartición como originada en un grupo (provenance) cuando aplica |
| `encrypted_aes_key_for_recipient` | Text | Clave AES re-cifrada con la `public_key` RSA-4096 del destinatario |
| `can_read` / `can_edit` / `can_share` | Booleans | Permisos granulares (defaults: True/False/False) |
| `shared_at` / `expires_at` / `is_revoked` / `revoked_at` | Datetime/Bool | Lifecycle del share |

**Decisión clave:** una fila por destinatario final. Cuando se comparte con un grupo de N miembros, se crean N filas con el mismo `shared_with_group_id` y un `encrypted_aes_key_for_recipient` distinto en cada una (re-cifrado individual con la `public_key` de cada miembro). Esto preserva el modelo Zero Knowledge: el servidor nunca tiene la clave AES en claro.

**Constraints:**
- Índices en `secret_id`, `shared_with_user_id`, `shared_with_group_id`.
- `UNIQUE (secret_id, shared_with_user_id, shared_with_group_id)` evita duplicados.

### 2.2 Endpoints (en [`routes/secrets.py`](../routes/secrets.py))

| Método | Ruta | Función | Descripción |
|--------|------|---------|-------------|
| `POST` | `/api/secrets/<id>/share` | `share_secret` | Comparte con uno o varios usuarios (lista) o con un grupo. Acepta los `encrypted_aes_key_for_recipient` ya re-cifrados por el cliente y persiste una fila por destinatario. |
| `GET` | `/api/secrets/shared-with-me` | `list_shared_with_me` | Lista los secretos compartidos con el usuario autenticado, con metadatos del `Secret` y la `encrypted_aes_key` específica. |
| `GET` | `/api/secrets/<id>/shares` | `list_shares` | Lista las comparticiones activas de un secreto (solo el propietario). |
| `DELETE` | `/api/secrets/shares/<share_id>` | `revoke_share` | Revoca una compartición (propietario o admin). |
| `POST` | `/api/secrets/shares/<share_id>/access` | `access_shared_secret` | Acceso explícito a un secreto compartido con verificaciones Zero Trust (sesión activa, share no revocado, no expirado). Devuelve `encrypted_data`, `encrypted_aes_key_for_recipient`, `digital_signature` para descifrado en cliente. |

Helper interno `_get_shareable_secret()` valida que el solicitante tiene permiso de `can_share` antes de crear nuevas comparticiones.

### 2.3 Flujo de compartición con grupo (Zero Knowledge)

```
1. Propietario solicita compartir secreto S con grupo G.
2. Cliente pide GET /api/groups/<G> y obtiene la lista de miembros + sus public_keys.
3. Cliente descifra la clave AES de S con su private_key.
4. Para cada miembro M:
   a. Cliente cifra la clave AES con la public_key RSA de M (RSA-OAEP).
   b. Construye un payload { user_id: M, encrypted_aes_key: ... }.
5. Cliente envía POST /api/secrets/<S>/share con la lista de payloads + group_id.
6. Servidor crea N filas SecretShare. La clave AES nunca abandona el cliente en claro.
```

### 2.4 Frontend

| Componente | Archivo | Función |
|------------|---------|---------|
| `secret-share-dialog` | [`cliente2/.../secrets/secret-share-dialog/secret-share-dialog.component.ts`](../cliente2/src/app/features/secrets/secret-share-dialog/secret-share-dialog.component.ts) | Diálogo modal con dos pestañas (usuarios / grupos), búsqueda incremental, selección múltiple, configuración de permisos `can_read`/`can_edit`/`can_share` y caducidad. Dispara el re-cifrado vía `CryptoService` antes de llamar al backend. |
| `shared-with-me` | [`cliente2/.../secrets/shared-with-me/shared-with-me.component.ts`](../cliente2/src/app/features/secrets/shared-with-me/shared-with-me.component.ts) | Vista de listado de secretos compartidos conmigo, con descifrado on-demand (igual que la bóveda propia, pero usando `encrypted_aes_key_for_recipient` en lugar de la clave AES propia). |
| `SecretsService` | [`cliente2/.../core/services/secrets.service.ts`](../cliente2/src/app/core/services/secrets.service.ts) | +105 líneas: `shareSecret`, `listSharedWithMe`, `listShares`, `revokeShare`, `accessSharedSecret`. |
| `GroupsService` | [`cliente2/.../core/services/groups.service.ts`](../cliente2/src/app/core/services/groups.service.ts) | +14 líneas: helper `getMembersWithPublicKeys` para el flujo de re-cifrado. |

### 2.5 Auditoría e integridad

- Cada operación emite un `AuditLog` con acciones `SECRET_SHARED`, `SHARE_REVOKED`, `SHARED_SECRET_ACCESSED`.
- El `digital_signature` original del secreto (RSA-PSS) se mantiene; el destinatario verifica firma en cliente tras descifrar, igual que el propietario.

### 2.6 Tests

Cobertura dentro de [`tests/test_secrets.py`](../tests/test_secrets.py) (no se creó suite específica; recomendado `test_sharing.py` para RNF03).

### 2.7 Métricas del PR #13

- 14 archivos modificados, **+1 354 / -47** líneas.
- 1 script ad-hoc `migrate_secret_shares.py`.

---

## 3. RF05 — Gestión de sesiones (`feature/sessions-rf05`, PR #16)

**Objetivo del PRD §3.5:** dar tracking y revocación a los JWT emitidos. Cada login deja una fila en `Session`; el usuario puede listar y revocar sesiones desde el perfil; el blocklist rechaza tokens revocados o expirados. Cubre además los eventos de auditoría de sesión que faltaban para RF06.

### 3.1 Modelo de datos: `Session`

Definido en [`models.py`](../models.py) (clase `Session`):

| Campo | Tipo | Notas |
|-------|------|-------|
| `id` | UUID (string 36) | PK |
| `user_id` | FK → `users.id` | `ON DELETE CASCADE` |
| `token_jti` | VARCHAR(64), unique | Claim `jti` del JWT — pieza contra la que valida el blocklist |
| `ip_address` | VARCHAR(45) | IPv6-friendly |
| `user_agent` | VARCHAR(500) | Cabecera completa para forensia |
| `device_info` | VARCHAR(255) | Heurística simple parseando UA (`SentryVault Desktop`, `Chrome en macOS`, etc.) |
| `created_at`, `last_activity`, `expires_at` | Datetime | `last_activity` se refresca en cada request |
| `is_revoked`, `revoked_at`, `revoked_reason` | Bool/Datetime/String | `reason ∈ {logout, manual, revoke_all, expired}` |

**Helpers del modelo:**
- `revoke(reason)` — marca revocada de forma idempotente.
- `is_expired()` — comparación con `expires_at`.
- `parse_device_info(ua)` — heurística sin dependencias externas (RNF: minimización de dependencias).
- `to_dict(current_jti)` — serializa marcando `is_current` cuando el `jti` coincide con el de la sesión que invoca.

### 3.2 Integración JWT en [`app.py`](../app.py)

```python
@jwt.token_in_blocklist_loader
def is_token_revoked(jwt_header, jwt_payload):
    if jwt_payload.get('type') == 'refresh':
        return False
    jti = jwt_payload.get('jti')
    session = Session.query.filter_by(token_jti=jti).first()
    if session is None:
        return False                       # tokens previos a RF05 → permitidos
    if session.is_revoked:
        return True
    if session.is_expired():
        session.revoke(reason='expired')   # auto-marcado en el primer toque
        db.session.commit()
        return True
    session.last_activity = datetime.utcnow()
    db.session.commit()
    return False
```

**Decisión clave:** el callback hace doble función — bloqueo + refresco de `last_activity`. Esto evita un middleware aparte y se ejecuta una sola vez por request gracias a Flask-JWT-Extended.

`@jwt.revoked_token_loader` devuelve 401 con mensaje claro `"Sesión revocada o expirada"`.

### 3.3 Endpoints (en [`routes/auth.py`](../routes/auth.py))

| Método | Ruta | Función | Descripción |
|--------|------|---------|-------------|
| `GET` | `/api/auth/sessions` | `list_sessions` | Lista las sesiones del usuario. Soporta `?include_revoked=true`. Marca cuál es la sesión actual mediante el `jti` del request. |
| `DELETE` | `/api/auth/sessions/<id>` | `revoke_session` | Revoca una sesión concreta (el usuario solo puede tocar las suyas → 404 en intento cruzado). |
| `DELETE` | `/api/auth/sessions` | `revoke_all_sessions` | Revoca todas las sesiones del usuario **excepto la actual**. |

**Hooks en endpoints existentes:**
- `POST /api/auth/login`: tras crear `access_token` se decodifica con `decode_token()` para extraer `jti`/`exp` y se persiste la `Session`. Emite `SESSION_CREATED` en `AuditLog`.
- `POST /api/auth/refresh`: cada renovación crea una `Session` para el nuevo access_token (el refresh token no se trackea — su `jti` no aparece en `Session`).
- `POST /api/auth/logout`: revoca la `Session` asociada al `jti` actual con `reason='logout'` y emite `SESSION_REVOKED`.

### 3.4 Frontend

| Pieza | Archivo | Función |
|-------|---------|---------|
| `SessionsService` | [`cliente2/.../core/services/sessions.service.ts`](../cliente2/src/app/core/services/sessions.service.ts) | `list(includeRevoked)`, `revoke(id)`, `revokeAll()`. |
| Sección **Sesiones activas** en perfil | [`cliente2/.../profile/profile.component.ts`](../cliente2/src/app/features/profile/profile.component.ts) | Tarjetas por sesión con icono según `device_info`, IP, `last_activity`, fecha de creación y expiración. Botones de revocación individual y masiva (con `ConfirmDialog`). Marca explícitamente la sesión actual. |
| Módulo de perfil | [`cliente2/.../profile/profile.module.ts`](../cliente2/src/app/features/profile/profile.module.ts) | Añade `MatTableModule`. |

### 3.5 Auditoría (cierra gap de RF06)

Eventos emitidos:

| Acción | Cuándo | Detalles |
|--------|--------|----------|
| `SESSION_CREATED` | Login exitoso | `resource_id = session.id`, `details = {device_info}` |
| `SESSION_REVOKED` | Logout, revocación manual o masiva, expiración detectada por blocklist | `details = {reason}` |

Estos eventos faltaban en `develop` y son requisitos del PRD §3.6.1.

### 3.6 Tests — [`tests/test_sessions.py`](../tests/test_sessions.py)

10 tests organizados en 5 clases:

| Clase | Casos cubiertos |
|-------|-----------------|
| `TestSessionLifecycle` | Login crea fila `Session`; emite `SESSION_CREATED`; logout marca revocada con `reason='logout'`. |
| `TestTokenBlocklist` | Token revocado devuelve 401 en endpoint autenticado posterior. |
| `TestSessionsEndpoints` | Listado solo activas por defecto; revocación individual de una sesión ajena propia (otro dispositivo); revocación masiva preserva la actual; un usuario no puede revocar la sesión de otro (404). |
| `TestLastActivity` | `last_activity` avanza en cada request. |
| `TestSessionToDict` | Marcado `is_current` correcto. |

**Resultado**: 64/64 tests del proyecto en verde, sin regresiones.

### 3.7 Migración

[`migrate_sessions.py`](../migrate_sessions.py) — script idempotente que detecta el dialecto (SQLite vs PostgreSQL/MySQL) y crea la tabla `sessions` con sus índices. Sigue el patrón establecido por `migrate_secret_shares.py` y los demás migrate_*.py existentes.

### 3.8 Métricas del PR #16

- 8 archivos modificados, **+898 / -20** líneas.
- 0 nuevas dependencias (usa `decode_token` de `flask_jwt_extended` ya presente).

---

## 4. Conclusión

Tras la integración de los PRs #13 (RF04) y #16 (RF05), **los 7 RFs del PRD están funcionalmente cubiertos**. El esfuerzo restante se concentra en deuda técnica (Alembic, limpieza de legacy, CI/CD, linting) y pulido cosmético, pero no en funcionalidad.

La arquitectura criptográfica original del proyecto (RSA-4096, AES-256-CTR, Argon2id, RSA-PSS) se ha reutilizado intacta en RF04 y se ha extendido a `Session` solo para tracking — no se ha tocado ninguna primitiva ni se ha introducido criptografía propia, manteniendo el principio de minimización del PRD §9.3.

El modelo Zero Knowledge se preserva en compartición de grupos mediante el re-cifrado por miembro en cliente, y en sesiones mediante el bloqueo basado en `jti` sin que el servidor necesite firmar/verificar nada extra.
