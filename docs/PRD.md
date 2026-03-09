# PRD: Sistema de Gestion Segura de Identidades y Secretos

## Proyecto DES-N2026 — Desarrollo de Aplicaciones Seguras 2026

**Version:** 1.0
**Fecha:** 2026-02-09
**Estado:** Borrador

---

## 1. Resumen ejecutivo

Este documento define los requisitos de producto para transformar la plataforma existente **Sentryvault** (sistema de intercambio seguro de documentos clasificados) en un **sistema de gestion segura de identidades y secretos** para organizaciones.

El proyecto actual ya implementa una arquitectura cliente/servidor robusta con cifrado end-to-end (RSA-4096, AES-256-CTR), autenticacion multifactor (TOTP), gestion de roles por niveles de clasificacion, comparticion de archivos cifrados y auditorias completas. La estrategia consiste en **reutilizar esta base criptografica y arquitectonica** para pivotar el dominio funcional: de "gestion de documentos clasificados" a "gestion de identidades y secretos digitales" (contrasenas, credenciales API, certificados, tokens, notas seguras, etc.).

### Alcance del cambio

| Aspecto | Estado actual | Estado objetivo |
|---------|--------------|----------------|
| Dominio funcional | Ficheros clasificados militares | Identidades y secretos organizacionales |
| Entidades principales | SecureFile (archivos binarios) | Secret (credenciales, API keys, notas seguras, certificados) + Identity (identidades de servicio/usuario) |
| Organizacion de acceso | Niveles de clasificacion (RESTRICTED..TOP_SECRET) | Roles organizacionales (Admin, Manager, User, Auditor) + Grupos/Equipos |
| Comparticion | Por usuario individual | Por usuario y por grupo |
| Backend | Flask + SQLite/PostgreSQL | Flask + SQLite/PostgreSQL (se mantiene) |
| Frontend | Angular 17 + Electron | Angular 17 + Electron (se mantiene) |
| Criptografia | RSA-4096, AES-256-CTR, Argon2id, RSA-PSS | Se mantiene intacta, se extiende a nuevas entidades |

---

## 2. Contexto y motivacion

### 2.1 Requisitos academicos (del enunciado del proyecto)

El documento de la asignatura DAS-2026 establece los siguientes requisitos obligatorios:

**Aspectos a incorporar:**
1. Arquitectura cliente/servidor
2. Autenticacion y gestion de sesion seguras
3. Trafico y almacenamiento seguros (cifrado)
4. Gestion de identidades y/o secretos (crear, editar, borrar, etc.)
5. Roles o diferentes niveles de acceso a la informacion
6. Posibilidad de compartir identidades y/o secretos entre usuarios o grupos
7. Justificacion de herramientas desde el punto de vista de la seguridad

**Aspectos a considerar y evaluar:**
1. Sistemas de backup y logging de eventos
2. Infraestructura adecuada y escalabilidad del sistema
3. Tecnicas de ingenieria del software
4. Minimizacion de dependencias externas, sencillez de diseno e implementacion

### 2.2 Analisis GAP: codigo existente vs. requisitos

| Requisito | Cubierto por codigo actual | Accion necesaria |
|-----------|---------------------------|------------------|
| Arquitectura cliente/servidor | SI — Flask API + Angular/Electron | Minima: renombrar contexto |
| Autenticacion segura | SI — Bcrypt + JWT + 2FA (TOTP) | Minima: anadir gestion de sesiones activas |
| Gestion de sesion | PARCIAL — JWT con access/refresh tokens | Anadir: tabla de sesiones, revocacion, listado de sesiones activas |
| Trafico cifrado | SI — HTTPS/TLS, cifrado E2E | Ninguna |
| Almacenamiento cifrado | SI — AES-256-CTR + RSA-4096 | Adaptar: de ficheros binarios a secretos estructurados |
| Gestion de identidades/secretos CRUD | NO — Solo upload/download de ficheros | **NUEVO**: Modelo Secret con CRUD completo, tipos de secreto, versionado |
| Roles de acceso | PARCIAL — is_admin + clearance_level | Refactorizar: sistema RBAC (Admin, Manager, User, Auditor) |
| Comparticion entre usuarios | SI — FileShare con permisos granulares | Extender: mantener logica, adaptar a secretos |
| Comparticion entre grupos | NO | **NUEVO**: Modelo Group, membresías, comparticion grupal |
| Backup | NO | **NUEVO**: Sistema de exportacion/importacion cifrada |
| Logging de eventos | SI — AuditLog + FileAccessLog | Extender: adaptar a operaciones de secretos |
| Escalabilidad | PARCIAL — PostgreSQL + Gunicorn | Mejorar: migraciones con Alembic, pool de conexiones |
| Ingenieria del software | PARCIAL — Blueprints, servicios | Mejorar: tests automatizados, CI/CD basico |
| Minimizacion de dependencias | ACEPTABLE | Revisar: eliminar dependencias no utilizadas |

---

## 3. Requisitos funcionales

### 3.1 RF01 — Gestion de secretos (CRUD)

**Prioridad:** CRITICA
**Reutiliza:** Capa criptografica existente (`utils/crypto.py`), modelo de cifrado E2E
**Reemplaza:** El concepto de `SecureFile` como entidad principal

#### 3.1.1 Tipos de secreto soportados

| Tipo | Campos especificos | Icono UI |
|------|-------------------|----------|
| `PASSWORD` | url, username, password, notes | Candado |
| `API_KEY` | service_name, api_key, api_secret, endpoint | Llave |
| `CERTIFICATE` | certificate_pem, private_key_pem, chain_pem, expiry_date, issuer | Certificado |
| `SSH_KEY` | public_key, private_key, passphrase, hostname | Terminal |
| `NOTE` | content (texto libre cifrado) | Nota |
| `DATABASE` | host, port, db_name, username, password, connection_string | Base datos |
| `ENV_VARIABLE` | key, value, environment (dev/staging/prod) | Variable |
| `IDENTITY` | provider, username, email, access_token, refresh_token, metadata | Identidad |

#### 3.1.2 Modelo de datos: `Secret`

```
Secret:
  - id: UUID (primary key)
  - owner_id: FK -> User
  - title: String (cifrado)
  - secret_type: Enum (PASSWORD, API_KEY, CERTIFICATE, SSH_KEY, NOTE, DATABASE, ENV_VARIABLE, IDENTITY)
  - encrypted_data: Text (JSON cifrado con AES-256-CTR)
  - encrypted_aes_key: Text (clave AES cifrada con RSA del propietario)
  - tags: JSON (lista de etiquetas, cifradas)
  - folder_id: FK -> Folder (nullable, organizacion)
  - version: Integer (control de versiones)
  - digital_signature: Text (RSA-PSS sobre el hash del contenido)
  - content_hash: String (SHA-256 para integridad)
  - expires_at: DateTime (nullable, caducidad del secreto)
  - rotation_period_days: Integer (nullable, periodo de rotacion sugerido)
  - last_rotated_at: DateTime (nullable)
  - created_at: DateTime
  - updated_at: DateTime
```

#### 3.1.3 Modelo de datos: `SecretVersion`

```
SecretVersion:
  - id: UUID
  - secret_id: FK -> Secret
  - version_number: Integer
  - encrypted_data: Text (JSON cifrado)
  - encrypted_aes_key: Text
  - content_hash: String
  - changed_by_id: FK -> User
  - change_reason: String (nullable)
  - created_at: DateTime
```

#### 3.1.4 Modelo de datos: `Folder`

```
Folder:
  - id: UUID
  - owner_id: FK -> User
  - name: String
  - parent_id: FK -> Folder (nullable, para jerarquia)
  - created_at: DateTime
```

#### 3.1.5 Endpoints API de secretos

| Metodo | Ruta | Descripcion | Auth |
|--------|------|-------------|------|
| POST | `/api/secrets` | Crear secreto | JWT |
| GET | `/api/secrets` | Listar secretos del usuario (con filtros) | JWT |
| GET | `/api/secrets/:id` | Obtener metadatos de un secreto | JWT |
| POST | `/api/secrets/:id/decrypt` | Descargar secreto descifrado | JWT + 2FA opcional |
| PUT | `/api/secrets/:id` | Actualizar secreto (crea nueva version) | JWT |
| DELETE | `/api/secrets/:id` | Eliminar secreto (soft delete) | JWT |
| GET | `/api/secrets/:id/versions` | Listar historial de versiones | JWT |
| GET | `/api/secrets/:id/versions/:v` | Obtener version especifica | JWT |
| POST | `/api/secrets/:id/rotate` | Rotar secreto (nueva version + marcar rotacion) | JWT |
| POST | `/api/secrets/:id/verify` | Verificar integridad del secreto | JWT |
| GET | `/api/secrets/:id/access-log` | Ver log de accesos al secreto | JWT |

#### 3.1.6 Flujo de cifrado de secretos

Se reutiliza el pipeline criptografico existente, adaptado a datos estructurados:

```
CREAR SECRETO:
1. Cliente estructura los campos del secreto en un objeto JSON
2. Cliente serializa JSON -> plaintext bytes
3. Cliente calcula SHA-256(plaintext) -> content_hash
4. Cliente genera clave AES-256 aleatoria
5. Cliente genera nonce/IV 128-bit aleatorio
6. Cliente cifra: AES-256-CTR(plaintext, aes_key, iv) -> encrypted_data
7. Cliente cifra la clave AES con la public_key RSA-4096 del propietario (OAEP) -> encrypted_aes_key
8. Cliente firma: RSA-PSS(content_hash, private_key) -> digital_signature
9. Cliente envia: encrypted_data, encrypted_aes_key, content_hash, digital_signature, metadatos

LEER SECRETO:
1. Servidor retorna: encrypted_data, encrypted_aes_key, content_hash, digital_signature
2. Cliente descifra clave AES con su private_key RSA
3. Cliente extrae IV (primeros 16 bytes)
4. Cliente descifra: AES-256-CTR(encrypted_data, aes_key, iv) -> plaintext
5. Cliente verifica: SHA-256(plaintext) == content_hash
6. Cliente verifica firma RSA-PSS con la public_key del firmante
7. Cliente parsea JSON -> muestra campos del secreto en UI
```

**Reutilizacion directa** de: `CryptoManager.generate_aes_key()`, `CryptoManager.encrypt_file()`, `CryptoManager.encrypt_aes_key()`, `CryptoManager.sign_data()`, `CryptoManager.verify_signature()` y los equivalentes en `CryptoService` de Angular.

### 3.2 RF02 — Sistema de roles RBAC

**Prioridad:** CRITICA
**Reutiliza:** Campo `is_admin` y `clearance_level` existentes
**Reemplaza:** Sistema de niveles de clasificacion militar

#### 3.2.1 Roles definidos

| Rol | Permisos |
|-----|----------|
| `ADMIN` | CRUD usuarios, CRUD grupos, ver auditorias globales, gestionar roles, backup/restore, CRUD secretos propios |
| `MANAGER` | Crear grupos, gestionar miembros de sus grupos, compartir secretos con sus grupos, CRUD secretos propios, ver auditorias de sus grupos |
| `USER` | CRUD secretos propios, compartir secretos con usuarios/grupos donde participa, ver auditorias propias |
| `AUDITOR` | Solo lectura de auditorias y logs (sin acceso a secretos), generar informes de actividad |

#### 3.2.2 Cambios en modelo `User`

```
User (cambios sobre modelo existente):
  - role: Enum(ADMIN, MANAGER, USER, AUDITOR)  # Reemplaza is_admin + clearance_level
  - Eliminar: clearance_level (se reemplaza por role)
  - Mantener: is_admin (derivado: role == ADMIN)
  - Mantener: todo lo demas (password_hash, totp, keys, etc.)
```

#### 3.2.3 Endpoint de gestion de roles

| Metodo | Ruta | Descripcion | Auth |
|--------|------|-------------|------|
| PUT | `/api/auth/users/:id/role` | Cambiar rol de usuario | JWT (ADMIN) |
| GET | `/api/auth/roles` | Listar roles disponibles y permisos | JWT |

#### 3.2.4 Decorador de autorizacion

Refactorizar el decorador `@require_clearance()` existente a un nuevo `@require_role()`:

```python
@require_role('ADMIN', 'MANAGER')  # Permite acceso a ADMIN y MANAGER
def manage_group():
    ...
```

### 3.3 RF03 — Gestion de grupos

**Prioridad:** ALTA
**Reutiliza:** Logica de comparticion de `FileShare`
**Estado actual:** No existe

#### 3.3.1 Modelo de datos: `Group`

```
Group:
  - id: UUID
  - name: String
  - description: String (nullable)
  - created_by_id: FK -> User
  - created_at: DateTime
  - updated_at: DateTime
```

#### 3.3.2 Modelo de datos: `GroupMembership`

```
GroupMembership:
  - id: UUID
  - group_id: FK -> Group
  - user_id: FK -> User
  - role_in_group: Enum(OWNER, ADMIN, MEMBER, READONLY)
  - added_by_id: FK -> User
  - joined_at: DateTime
```

#### 3.3.3 Endpoints API de grupos

| Metodo | Ruta | Descripcion | Auth |
|--------|------|-------------|------|
| POST | `/api/groups` | Crear grupo | JWT (ADMIN, MANAGER) |
| GET | `/api/groups` | Listar grupos del usuario | JWT |
| GET | `/api/groups/:id` | Detalle de grupo | JWT (miembro) |
| PUT | `/api/groups/:id` | Actualizar grupo | JWT (owner/admin del grupo) |
| DELETE | `/api/groups/:id` | Eliminar grupo | JWT (owner) |
| POST | `/api/groups/:id/members` | Anadir miembro | JWT (owner/admin del grupo) |
| DELETE | `/api/groups/:id/members/:uid` | Eliminar miembro | JWT (owner/admin del grupo) |
| PUT | `/api/groups/:id/members/:uid/role` | Cambiar rol en grupo | JWT (owner) |

### 3.4 RF04 — Comparticion de secretos

**Prioridad:** ALTA
**Reutiliza:** Toda la logica de `FileShare` (re-cifrado de clave AES, permisos granulares, verificaciones Zero Trust)

#### 3.4.1 Modelo de datos: `SecretShare`

```
SecretShare:
  - id: UUID
  - secret_id: FK -> Secret
  - shared_by_id: FK -> User
  - shared_with_user_id: FK -> User (nullable, si se comparte con usuario)
  - shared_with_group_id: FK -> Group (nullable, si se comparte con grupo)
  - encrypted_aes_key_for_recipient: Text (clave AES re-cifrada)
  - can_read: Boolean (default True)
  - can_edit: Boolean (default False)
  - can_share: Boolean (default False)
  - shared_at: DateTime
  - expires_at: DateTime (nullable)
```

**Nota:** Cuando se comparte con un grupo, se genera un `encrypted_aes_key` individual para cada miembro del grupo (re-cifrado con la clave publica de cada uno). Esto mantiene el modelo Zero Knowledge: el servidor nunca ve el secreto en claro.

#### 3.4.2 Endpoints de comparticion

| Metodo | Ruta | Descripcion | Auth |
|--------|------|-------------|------|
| POST | `/api/secrets/:id/share` | Compartir con usuario o grupo | JWT |
| GET | `/api/secrets/shared-with-me` | Secretos compartidos conmigo | JWT |
| GET | `/api/secrets/:id/shares` | Listar comparticiones de un secreto | JWT (propietario) |
| DELETE | `/api/secrets/shares/:share_id` | Revocar comparticion | JWT (propietario o admin) |
| POST | `/api/secrets/shares/:share_id/access` | Acceder a secreto compartido | JWT + verificaciones Zero Trust |

#### 3.4.3 Flujo de comparticion con grupo

```
1. Propietario solicita compartir secreto con grupo G
2. Cliente obtiene lista de miembros de G y sus public_keys
3. Para cada miembro M:
   a. Cliente descifra la clave AES del secreto con su private_key
   b. Cliente re-cifra la clave AES con la public_key de M
   c. Se crea un SecretShare individual para M
4. Cada miembro accede al secreto descifrando su clave AES individual
```

### 3.5 RF05 — Gestion de sesiones

**Prioridad:** ALTA
**Reutiliza:** JWT existente
**Estado actual:** Parcial (tokens sin tracking de sesiones)

#### 3.5.1 Modelo de datos: `Session`

```
Session:
  - id: UUID
  - user_id: FK -> User
  - token_jti: String (JWT ID para revocacion)
  - ip_address: String
  - user_agent: String
  - device_info: String (nullable, parseado del user-agent)
  - created_at: DateTime
  - last_activity: DateTime
  - expires_at: DateTime
  - is_revoked: Boolean (default False)
  - revoked_at: DateTime (nullable)
  - revoked_reason: String (nullable)
```

#### 3.5.2 Endpoints de sesiones

| Metodo | Ruta | Descripcion | Auth |
|--------|------|-------------|------|
| GET | `/api/auth/sessions` | Listar sesiones activas del usuario | JWT |
| DELETE | `/api/auth/sessions/:id` | Revocar sesion especifica | JWT |
| DELETE | `/api/auth/sessions` | Revocar todas las sesiones (excepto actual) | JWT |

#### 3.5.3 Implementacion

Utilizar el callback `@jwt.token_in_blocklist_loader` de Flask-JWT-Extended para verificar tokens revocados contra la tabla `Session`. En cada request autenticado, actualizar `last_activity`.

### 3.6 RF06 — Sistema de auditorias

**Prioridad:** ALTA
**Reutiliza:** `AuditLog` y `FileAccessLog` existentes

#### 3.6.1 Eventos auditados

| Categoria | Eventos |
|-----------|---------|
| Autenticacion | login_success, login_failed, logout, 2fa_setup, 2fa_verify, password_change |
| Sesiones | session_created, session_revoked, session_expired |
| Secretos | secret_created, secret_read, secret_updated, secret_deleted, secret_rotated |
| Comparticion | secret_shared, share_revoked, shared_secret_accessed |
| Grupos | group_created, group_updated, group_deleted, member_added, member_removed |
| Administracion | user_created, user_deactivated, role_changed, backup_created, backup_restored |

#### 3.6.2 Endpoints de auditoria

| Metodo | Ruta | Descripcion | Auth |
|--------|------|-------------|------|
| GET | `/api/audit/logs` | Logs globales (paginados, con filtros) | JWT (ADMIN, AUDITOR) |
| GET | `/api/audit/logs/user/:id` | Logs de un usuario especifico | JWT (ADMIN, AUDITOR, o propio) |
| GET | `/api/audit/logs/secret/:id` | Logs de un secreto especifico | JWT (propietario, ADMIN, AUDITOR) |
| GET | `/api/audit/stats` | Estadisticas de actividad | JWT (ADMIN, AUDITOR) |
| POST | `/api/audit/export` | Exportar logs en CSV/JSON | JWT (ADMIN) |

### 3.7 RF07 — Backup y restauracion

**Prioridad:** MEDIA
**Estado actual:** No existe

#### 3.7.1 Exportacion cifrada

```
EXPORTAR:
1. El usuario solicita backup de sus secretos
2. El servidor recopila todos los secretos del usuario (cifrados)
3. Se genera un paquete JSON con: metadatos + secretos cifrados + firma
4. El paquete se cifra con una clave derivada de una password de backup (Argon2id)
5. Se retorna el archivo .vault cifrado

IMPORTAR:
1. El usuario sube el archivo .vault
2. Introduce la password de backup
3. Se derivan las claves y se descifra el paquete
4. Se verifica la firma de integridad
5. Se importan los secretos (con opcion de merge o reemplazo)
```

#### 3.7.2 Endpoints de backup

| Metodo | Ruta | Descripcion | Auth |
|--------|------|-------------|------|
| POST | `/api/backup/export` | Exportar secretos del usuario | JWT + 2FA |
| POST | `/api/backup/import` | Importar secretos desde backup | JWT + 2FA |
| POST | `/api/backup/system` | Backup completo del sistema (admin) | JWT (ADMIN) + 2FA |

---

## 4. Requisitos no funcionales

### 4.1 RNF01 — Seguridad

| Aspecto | Especificacion |
|---------|---------------|
| Cifrado en transito | TLS 1.2+ obligatorio |
| Cifrado en reposo | AES-256-CTR para datos, Argon2id para claves derivadas |
| Cifrado E2E | El servidor nunca accede a secretos en claro |
| Zero Knowledge | Las claves de descifrado solo existen en el cliente |
| Hashing de contrasenas | Bcrypt (12 rounds) con salt unico de 32 bytes |
| Derivacion de claves | Argon2id (time=3, memory=64MB, parallelism=4) |
| Firma digital | RSA-PSS con SHA-256 para integridad |
| Tamano de clave RSA | 4096 bits |
| 2FA | TOTP (RFC 6238) con codigos de respaldo |
| Bloqueo de cuenta | 5 intentos fallidos -> 30 minutos |

### 4.2 RNF02 — Rendimiento y escalabilidad

| Aspecto | Especificacion |
|---------|---------------|
| Base de datos | SQLite (desarrollo) / PostgreSQL (produccion) |
| Servidor WSGI | Gunicorn con 4 workers |
| Migraciones | Alembic (a incorporar) |
| Paginacion | Obligatoria en listados (default 20, max 100) |
| Tamano maximo de secreto | 1 MB por secreto individual |

### 4.3 RNF03 — Calidad de software

| Aspecto | Especificacion |
|---------|---------------|
| Tests backend | pytest con cobertura minima 70% |
| Tests frontend | Karma + Jasmine para servicios criticos |
| Linting | flake8 (backend), tslint/eslint (frontend) |
| Documentacion API | Swagger/OpenAPI via Flasgger (ya existente) |

---

## 5. Arquitectura del sistema

### 5.1 Diagrama de arquitectura

```
+------------------------------------------------------------------+
|                     CLIENTE (Angular 17 + Electron)               |
|                                                                    |
|  +------------------+  +------------------+  +------------------+ |
|  |  Auth Module     |  |  Secrets Module  |  |  Groups Module   | |
|  |  - Login         |  |  - CRUD Secrets  |  |  - CRUD Groups   | |
|  |  - Register      |  |  - Share         |  |  - Members       | |
|  |  - 2FA Setup     |  |  - Folders       |  |  - Permisos      | |
|  |  - Sessions      |  |  - Versions      |  +------------------+ |
|  +------------------+  |  - Search        |                       |
|                        +------------------+  +------------------+ |
|  +------------------+                        |  Profile Module  | |
|  |  CryptoService   |  +------------------+ |  - Datos usuario | |
|  |  (E2E Encryption)|  |  Audit Module    | |  - Cambiar pass  | |
|  |  RSA-4096        |  |  - Logs          | |  - 2FA config    | |
|  |  AES-256-CTR     |  |  - Estadisticas  | |  - Sesiones      | |
|  |  Argon2id        |  +------------------+ +------------------+ |
|  +------------------+                                             |
+----------------------------+-------------------------------------+
                             |
                        HTTPS/TLS 1.2+
                        JWT Bearer Token
                             |
+----------------------------v-------------------------------------+
|                     SERVIDOR (Flask + Gunicorn)                   |
|                                                                    |
|  +------------------+  +------------------+  +------------------+ |
|  |  auth_bp         |  |  secrets_bp      |  |  groups_bp       | |
|  |  /api/auth/*     |  |  /api/secrets/*  |  |  /api/groups/*   | |
|  +------------------+  +------------------+  +------------------+ |
|                                                                    |
|  +------------------+  +------------------+  +------------------+ |
|  |  audit_bp        |  |  backup_bp       |  |  Middleware      | |
|  |  /api/audit/*    |  |  /api/backup/*   |  |  - JWT verify    | |
|  +------------------+  +------------------+  |  - RBAC check    | |
|                                              |  - Audit log     | |
|  +------------------+  +------------------+  |  - Rate limit    | |
|  |  utils/crypto.py |  |  utils/totp.py   |  +------------------+ |
|  |  (CryptoManager) |  |  (TwoFactorAuth) |                      |
|  +------------------+  +------------------+                      |
|                                                                    |
+----------------------------+-------------------------------------+
                             |
                     SQLAlchemy ORM
                             |
+----------------------------v-------------------------------------+
|                     BASE DE DATOS                                 |
|                                                                    |
|  Users | Secrets | SecretVersions | Folders | Groups              |
|  GroupMemberships | SecretShares | Sessions                       |
|  AuditLogs | SecretAccessLogs                                     |
+------------------------------------------------------------------+
```

### 5.2 Estructura de archivos propuesta

```
DES-N2026/
├── app.py                          # (modificar) Registrar nuevos blueprints
├── config.py                       # (modificar) Nuevas configuraciones
├── models.py                       # (modificar) Nuevos modelos + refactorizar existentes
├── requirements.txt                # (modificar) Anadir alembic, pytest
│
├── routes/
│   ├── auth.py                    # (modificar) Sesiones, refactorizar roles
│   ├── files.py                   # (eliminar o deprecar) Reemplazado por secrets.py
│   ├── secrets.py                 # (NUEVO) CRUD de secretos
│   ├── groups.py                  # (NUEVO) Gestion de grupos
│   ├── audit.py                   # (NUEVO) Endpoints de auditoria
│   └── backup.py                  # (NUEVO) Backup/restauracion
│
├── utils/
│   ├── crypto.py                  # (mantener) Reutilizar intacto
│   ├── totp.py                    # (mantener) Reutilizar intacto
│   ├── decorators.py              # (NUEVO) @require_role, @audit_action
│   └── validators.py              # (NUEVO) Validacion de entrada
│
├── migrations/                     # (NUEVO) Alembic migrations
│   ├── alembic.ini
│   ├── env.py
│   └── versions/
│
├── tests/                          # (NUEVO) Suite de tests
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_secrets.py
│   ├── test_groups.py
│   ├── test_crypto.py
│   └── test_sharing.py
│
├── docs/                           # Documentacion
│   └── PRD.md                     # Este documento
│
├── cliente2/                       # Frontend Angular
│   └── src/app/
│       ├── features/
│       │   ├── auth/              # (modificar) Anadir vista de sesiones
│       │   ├── secrets/           # (NUEVO) Reemplaza features/files/
│       │   │   ├── secret-list/
│       │   │   ├── secret-detail/
│       │   │   ├── secret-create/
│       │   │   ├── secret-edit/
│       │   │   ├── secret-share-dialog/
│       │   │   └── secret-versions/
│       │   ├── groups/            # (NUEVO) Gestion de grupos
│       │   │   ├── group-list/
│       │   │   ├── group-detail/
│       │   │   └── group-members/
│       │   ├── audit/             # (NUEVO) Visualizacion de auditorias
│       │   │   ├── audit-log/
│       │   │   └── audit-stats/
│       │   └── profile/           # (modificar) Anadir sesiones activas
│       │
│       └── core/services/
│           ├── auth.service.ts    # (modificar) Gestion de sesiones
│           ├── crypto.service.ts  # (mantener) Reutilizar intacto
│           ├── secret.service.ts  # (NUEVO) Reemplaza file.service.ts
│           ├── group.service.ts   # (NUEVO) Operaciones de grupos
│           └── audit.service.ts   # (NUEVO) Consulta de auditorias
```

---

## 6. Plan de implementacion

### 6.1 Fase 1 — Fundamentos (Semanas 1-3)

**Objetivo:** Adaptar la base existente al nuevo dominio

| Tarea | Archivos afectados | Esfuerzo |
|-------|-------------------|----------|
| Refactorizar modelo `User`: anadir campo `role`, eliminar `clearance_level` | `models.py` | Bajo |
| Crear modelos `Secret`, `SecretVersion`, `Folder` | `models.py` | Medio |
| Crear modelo `Session` y logica de revocacion | `models.py`, `routes/auth.py` | Medio |
| Configurar Alembic para migraciones | `migrations/`, `app.py` | Bajo |
| Crear decorador `@require_role()` | `utils/decorators.py` | Bajo |
| Crear `routes/secrets.py` con CRUD basico | `routes/secrets.py` | Alto |
| Adaptar pipeline criptografico para secretos JSON | `routes/secrets.py` (reutiliza `utils/crypto.py`) | Medio |
| Tests unitarios para crypto y modelos | `tests/` | Medio |

### 6.2 Fase 2 — Grupos y comparticion (Semanas 4-5)

**Objetivo:** Implementar comparticion avanzada

| Tarea | Archivos afectados | Esfuerzo |
|-------|-------------------|----------|
| Crear modelos `Group`, `GroupMembership` | `models.py` | Bajo |
| Crear `routes/groups.py` con CRUD | `routes/groups.py` | Medio |
| Crear modelo `SecretShare` (adaptar de `FileShare`) | `models.py` | Bajo |
| Implementar comparticion con usuario en `routes/secrets.py` | `routes/secrets.py` | Medio |
| Implementar comparticion con grupo (re-cifrado multiple) | `routes/secrets.py` | Alto |
| Tests de comparticion y permisos | `tests/test_sharing.py` | Medio |

### 6.3 Fase 3 — Frontend (Semanas 5-7)

**Objetivo:** Interfaz de usuario completa

| Tarea | Archivos afectados | Esfuerzo |
|-------|-------------------|----------|
| Crear `SecretService` (adaptar de `FileService`) | `cliente2/src/app/core/services/secret.service.ts` | Medio |
| Crear `GroupService` | `cliente2/src/app/core/services/group.service.ts` | Bajo |
| Crear modulo Secrets con componentes CRUD | `cliente2/src/app/features/secrets/` | Alto |
| Crear modulo Groups con componentes | `cliente2/src/app/features/groups/` | Medio |
| Adaptar modulo Auth (sesiones activas) | `cliente2/src/app/features/auth/` | Bajo |
| Adaptar navegacion y routing | `cliente2/src/app/app-routing.module.ts` | Bajo |

### 6.4 Fase 4 — Auditoria, backup y pulido (Semanas 7-8)

**Objetivo:** Funcionalidades complementarias y calidad

| Tarea | Archivos afectados | Esfuerzo |
|-------|-------------------|----------|
| Crear `routes/audit.py` | `routes/audit.py` | Medio |
| Crear `routes/backup.py` | `routes/backup.py` | Medio |
| Crear modulo Audit en frontend | `cliente2/src/app/features/audit/` | Medio |
| Documentacion Swagger de nuevos endpoints | `routes/*.py` (docstrings Flasgger) | Bajo |
| Tests de integracion end-to-end | `tests/` | Medio |
| Revision de seguridad y hardening | Global | Medio |

---

## 7. Reutilizacion detallada del codigo existente

### 7.1 Componentes que se MANTIENEN INTACTOS

| Componente | Archivo | Justificacion |
|------------|---------|---------------|
| CryptoManager | `utils/crypto.py` | Toda la criptografia (RSA, AES, firmas, hashes) es reutilizable directamente |
| TwoFactorAuth | `utils/totp.py` | TOTP/HOTP no necesita cambios |
| CryptoService (Angular) | `cliente2/.../crypto.service.ts` | Cifrado E2E en cliente es identico |
| AuthInterceptor | `cliente2/.../auth.interceptor.ts` | Inyeccion de JWT no cambia |
| SSL/TLS Certificates | `certs/` | Certificados reutilizables |
| SplashScreen | `cliente2/.../splash-screen/` | Componente UI reutilizable |
| Confirm/Unlock Dialogs | `cliente2/.../shared/` | Componentes UI reutilizables |
| Notification Service | `cliente2/.../notification.service.ts` | Servicio de notificaciones reutilizable |
| Storage Service | `cliente2/.../storage.service.ts` | Gestion de localStorage reutilizable |
| Config/Environments | `config.py`, `environment.ts` | Configuracion base reutilizable |

### 7.2 Componentes que se MODIFICAN

| Componente | Archivo | Cambios |
|------------|---------|---------|
| App factory | `app.py` | Registrar nuevos blueprints (secrets, groups, audit, backup) |
| Models | `models.py` | Anadir Secret, SecretVersion, Folder, Group, GroupMembership, SecretShare, Session. Modificar User (campo role) |
| Auth routes | `routes/auth.py` | Anadir endpoints de sesiones, refactorizar decoradores de rol |
| Auth service (Angular) | `cliente2/.../auth.service.ts` | Anadir gestion de sesiones activas |
| App routing | `cliente2/.../app-routing.module.ts` | Nuevas rutas para secrets, groups, audit |
| App module | `cliente2/.../app.module.ts` | Importar nuevos feature modules |
| Profile component | `cliente2/.../profile/` | Anadir seccion de sesiones activas |

### 7.3 Componentes que se CREAN NUEVOS

| Componente | Archivo | Basado en |
|------------|---------|-----------|
| Secrets routes | `routes/secrets.py` | Adaptar logica de `routes/files.py` |
| Groups routes | `routes/groups.py` | Nuevo |
| Audit routes | `routes/audit.py` | Extraer y extender de logica en `routes/auth.py` y `routes/files.py` |
| Backup routes | `routes/backup.py` | Nuevo |
| Decorators | `utils/decorators.py` | Extraer `@require_clearance` de `routes/files.py` |
| Validators | `utils/validators.py` | Nuevo |
| Secret service (Angular) | `secret.service.ts` | Adaptar de `file.service.ts` |
| Group service (Angular) | `group.service.ts` | Nuevo |
| Audit service (Angular) | `audit.service.ts` | Nuevo |
| Feature modules (Angular) | `features/secrets/`, `features/groups/`, `features/audit/` | Adaptar estructura de `features/files/` |
| Tests | `tests/` | Nuevo |

### 7.4 Componentes que se ELIMINAN / DEPRECAN

| Componente | Archivo | Motivo |
|------------|---------|--------|
| Files routes | `routes/files.py` | Reemplazado por `routes/secrets.py` |
| File service (Angular) | `file.service.ts` | Reemplazado por `secret.service.ts` |
| Files feature module | `features/files/` | Reemplazado por `features/secrets/` |
| Cliente legacy | `cliente/` | Obsoleto, no se migra |

---

## 8. Consideraciones de seguridad

### 8.1 Superficie de ataque

| Vector | Mitigacion |
|--------|-----------|
| Inyeccion SQL | SQLAlchemy ORM con consultas parametrizadas (ya implementado) |
| XSS | Angular sanitiza por defecto; CSP headers |
| CSRF | JWT en header Authorization (no cookies); SameSite |
| Fuerza bruta | Bloqueo de cuenta (5 intentos/30min, ya implementado); rate limiting |
| Robo de JWT | Tokens de corta duracion (1h); revocacion via Session; HTTPS obligatorio |
| Compromiso de servidor | Zero Knowledge: el servidor solo almacena datos cifrados |
| Compromiso de BD | Todos los secretos cifrados con AES-256-CTR; claves cifradas con RSA |
| Man-in-the-Middle | TLS 1.2+ obligatorio; certificate pinning en Electron |
| Enumeracion de usuarios | Respuestas genericas en login fallido (ya implementado) |
| Escalada de privilegios | RBAC verificado en cada endpoint; decorador `@require_role` |

### 8.2 Modelo SDL aplicado

| Fase SDL | Actividad en este proyecto |
|----------|---------------------------|
| Formacion | Documentacion de decisiones criptograficas en este PRD |
| Requisitos | Definicion de requisitos de seguridad (esta seccion) |
| Diseno | Arquitectura Zero Trust, cifrado E2E, RBAC |
| Implementacion | Uso de librerias criptograficas auditadas (cryptography, @noble/*) |
| Verificacion | Tests automatizados, revision de codigo |
| Lanzamiento | Checklist de seguridad pre-despliegue |
| Respuesta | Logging completo, auditorias, mecanismo de revocacion |

### 8.3 Elementos criptograficos y su proposito

| Elemento | Algoritmo | Proposito |
|----------|-----------|-----------|
| Cifrado de secretos | AES-256-CTR | Confidencialidad de los datos almacenados |
| Intercambio de claves | RSA-4096 OAEP | Proteccion de clave AES para cada usuario |
| Firma digital | RSA-PSS SHA-256 | Integridad y no repudio de secretos |
| Hash de contenido | SHA-256 | Verificacion de integridad |
| Hash de contrasenas | Bcrypt (12 rounds) | Proteccion de credenciales de acceso |
| Derivacion de claves | Argon2id | Proteccion de claves privadas almacenadas |
| Segundo factor | TOTP (HMAC-SHA1) | Autenticacion multifactor |
| Tokens de sesion | JWT (HS256) | Autenticacion stateless con posibilidad de revocacion |

---

## 9. Justificacion de herramientas

### 9.1 Backend

| Herramienta | Justificacion de seguridad |
|-------------|---------------------------|
| **Flask** | Framework minimalista que reduce superficie de ataque vs frameworks monoliticos. Control granular sobre middleware y seguridad |
| **SQLAlchemy** | ORM que previene inyeccion SQL por diseno. Consultas parametrizadas automaticas |
| **Flask-JWT-Extended** | Libreria madura para JWT con soporte de blocklist, claims personalizados y refresh tokens |
| **cryptography (Python)** | Libreria criptografica de referencia, auditada, mantenida por PyCA. Evita implementaciones ad-hoc |
| **argon2-cffi** | Implementacion de Argon2 ganadora del Password Hashing Competition. Resistente a ataques GPU y ASIC |
| **Flask-Bcrypt** | Hashing de contrasenas con factor de trabajo adaptable |

### 9.2 Frontend

| Herramienta | Justificacion de seguridad |
|-------------|---------------------------|
| **Angular 17** | Sanitizacion XSS integrada, CSP compatible, AOT compilation que reduce inyeccion de templates |
| **@noble/ciphers, @noble/curves, @noble/hashes** | Librerias criptograficas en JS puro, sin dependencias nativas, auditadas. Permiten cifrado E2E en el navegador |
| **hash-wasm (Argon2id)** | Implementacion WASM de Argon2id para derivacion de claves en cliente con rendimiento cercano a nativo |
| **Electron** | Permite distribucion como app de escritorio con aislamiento de proceso, almacenamiento seguro de claves en memoria |

### 9.3 Minimizacion de dependencias

El proyecto utiliza deliberadamente pocas dependencias:
- **Backend:** 24 paquetes Python (muchos son sub-dependencias de Flask)
- **Frontend:** 17 paquetes npm principales
- **Sin frameworks ORM pesados** (no Django), **sin bases de datos complejas** (SQLite para desarrollo)
- **Criptografia con librerias auditadas**, sin implementaciones propias de algoritmos

---

## 10. Glosario

| Termino | Definicion |
|---------|-----------|
| E2E | End-to-End Encryption: cifrado donde solo el emisor y receptor pueden descifrar |
| Zero Knowledge | El servidor no tiene acceso a los datos en claro |
| RBAC | Role-Based Access Control: control de acceso basado en roles |
| TOTP | Time-based One-Time Password: contrasena de un solo uso basada en tiempo |
| JWT | JSON Web Token: token de autenticacion stateless |
| OAEP | Optimal Asymmetric Encryption Padding: esquema de padding para RSA |
| RSA-PSS | RSA Probabilistic Signature Scheme: esquema de firma digital |
| Argon2id | Funcion de derivacion de claves resistente a hardware especializado |
| AES-256-CTR | Advanced Encryption Standard en modo Counter con clave de 256 bits |
| SDL | Security Development Lifecycle: modelo de desarrollo seguro de Microsoft |
