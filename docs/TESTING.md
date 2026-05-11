# Testing — Suite de Tests Unitarios

## Proyecto DES-N2026

**Implementado en:** `feature/unit-tests`
**Fecha:** 2026-03-05
**Requisito PRD:** RNF03 — Calidad de software (tests backend pytest ≥ 70%, tests frontend Karma + Jasmine)

---

## 1. Resumen

Se incorpora una suite de tests unitarios tanto para el **backend** (Flask/Python con pytest) como para el **frontend** (Angular con Karma + Jasmine). El objetivo es verificar el correcto funcionamiento de modelos, endpoints de autenticación, CRUD de secretos y los servicios Angular que consumen la API.

### Cobertura de tests

| Capa | Framework | Archivos de test | Nº de tests |
|------|-----------|-------------------|-------------|
| Backend — Modelos | pytest | `tests/test_models.py` | 15 |
| Backend — Auth API | pytest | `tests/test_auth.py` | 11 |
| Backend — Secrets API | pytest | `tests/test_secrets.py` | 11 |
| Frontend — AuthService | Jasmine/Karma | `auth.service.spec.ts` | 10 |
| Frontend — SecretsService | Jasmine/Karma | `secrets.service.spec.ts` | 16 |
| **Total** | | | **63** |

---

## 2. Backend (pytest)

### 2.1 Estructura de archivos

```
tests/
├── __init__.py              # Paquete Python
├── conftest.py              # Fixtures compartidos (app, db, client, helpers)
├── test_models.py           # Tests de modelos: User, Secret, Folder
├── test_auth.py             # Tests de endpoints /api/auth/*
└── test_secrets.py          # Tests de endpoints /api/secrets/* y /api/folders/*
```

### 2.2 Configuración (`conftest.py`)

| Fixture | Scope | Descripción |
|---------|-------|-------------|
| `app` | session | Crea la aplicación Flask con SQLite `:memory:` |
| `db_session` | function (autouse) | Transacción aislada por cada test con rollback automático |
| `client` | function | Cliente HTTP de test de Flask |

**Helpers:**
- `create_test_user()` — Crea un usuario válido con clave RSA real (2048-bit) para que la verificación de firma funcione.
- `sign_content_hash()` — Firma un content_hash con la clave privada de test usando RSA-PSS + SHA-256. Se usa en los tests de secretos donde el servidor verifica la firma digital.

> **Nota:** Se genera un par RSA real (2048-bit para velocidad en tests) compartido entre todos los usuarios de test. Esto permite que los endpoints que llaman a `crypto_manager.verify_signature()` funcionen sin mocks.

### 2.3 Tests de modelos (`test_models.py`)

| Clase | Test | Qué verifica |
|-------|------|-------------|
| `TestUserModel` | `test_create_user_defaults` | Valores por defecto (role=USER, is_active=True, etc.) |
| | `test_user_set_and_check_password` | `set_password` + `check_password` con Bcrypt + SHA-256 |
| | `test_user_has_role` | `has_role()` acepta uno o varios roles como strings |
| | `test_user_is_admin_role_property` | Propiedad `is_admin_role` refleja role == ADMIN |
| | `test_user_is_locked` | `is_locked()` respeta `locked_until` (futuro/pasado) |
| | `test_user_to_dict` | Serialización JSON correcta, no expone `password_hash` |
| | `test_user_clearance_legacy` | `has_clearance()` respeta jerarquía (legacy) |
| `TestSecretModel` | `test_create_secret` | Creación con UUID, version=1, is_deleted=False |
| | `test_secret_to_dict_hides_encrypted_by_default` | `to_dict()` sin datos cifrados por defecto |
| | `test_secret_to_dict_includes_encrypted` | `to_dict(include_encrypted=True)` expone datos |
| `TestFolderModel` | `test_create_folder` | Carpeta raíz sin parent_id |
| | `test_folder_hierarchy` | Relación padre/hijo entre carpetas |
| | `test_folder_to_dict` | Serialización JSON de carpeta |
| `TestHelpers` | `test_generate_uuid_format` | Formato UUID v4 (36 chars, 5 segmentos) |
| | `test_generate_uuid_uniqueness` | 100 UUIDs únicos |

### 2.4 Tests de autenticación (`test_auth.py`)

| Clase | Test | Qué verifica |
|-------|------|-------------|
| `TestRegisterEndpoint` | `test_register_missing_fields` | 400 sin campos obligatorios |
| | `test_register_success` | 201 con todos los campos, devuelve `user_id` |
| | `test_register_duplicate_email` | 400/409 con email duplicado |
| `TestLoginEndpoint` | `test_login_wrong_password` | 401 con contraseña incorrecta |
| | `test_login_nonexistent_user` | 401 con email inexistente |
| | `test_login_success` | 200 + `access_token` en respuesta |
| `TestProfileEndpoint` | `test_profile_no_token` | 401 sin JWT |
| | `test_profile_with_token` | 200 + datos del usuario con JWT válido |
| `TestRolesEndpoint` | `test_list_roles` | 200 + lista de roles del sistema |
| | `test_change_role_requires_admin` | 403 si USER intenta cambiar rol |
| | `test_change_role_as_admin` | 200 cuando ADMIN cambia rol de otro usuario |

### 2.5 Tests de secretos (`test_secrets.py`)

| Clase | Test | Qué verifica |
|-------|------|-------------|
| `TestSecretsCreate` | `test_create_secret_no_auth` | 401 sin JWT |
| | `test_create_secret_missing_fields` | 400 sin campos requeridos |
| | `test_create_secret_success` | 201 con firma RSA válida, version=1 |
| `TestSecretsList` | `test_list_secrets_empty` | Lista vacía con total=0 |
| | `test_list_secrets_returns_own_only` | Aislamiento: user2 no ve secretos de user1 |
| `TestSecretsDetail` | `test_get_secret` | 200 con secreto existente |
| | `test_get_secret_not_found` | 404 con UUID inexistente |
| | `test_delete_secret_soft` | Soft delete: 200 + posterior GET devuelve 404 |
| | `test_update_secret_creates_version` | PUT crea versión 2 con nueva firma |
| `TestFoldersCrud` | `test_create_and_list_folders` | Crear y listar carpetas (201 + 200) |
| | `test_delete_folder` | Eliminar carpeta existente (200) |

### 2.6 Cómo ejecutar

```bash
# Desde la raíz del proyecto
pip install pytest       # Si no está instalado
python -m pytest tests/ -v
```

Opciones útiles:

```bash
# Solo un archivo
python -m pytest tests/test_models.py -v

# Solo una clase
python -m pytest tests/test_auth.py::TestLoginEndpoint -v

# Con cobertura (requiere pytest-cov)
pip install pytest-cov
python -m pytest tests/ --cov=. --cov-report=term-missing
```

---

## 3. Frontend (Karma + Jasmine)

### 3.1 Estructura de archivos

```
cliente2/
├── karma.conf.js                                          # Configuración de Karma
├── tsconfig.spec.json                                     # TypeScript config para tests
├── src/
│   ├── test.ts                                            # Bootstrap de Karma
│   └── app/core/services/
│       ├── auth.service.spec.ts                           # Tests de AuthService
│       └── secrets.service.spec.ts                        # Tests de SecretsService
```

### 3.2 Configuración

- **Test runner:** Karma con ChromeHeadless (sin ventana de navegador)
- **Framework:** Jasmine
- **HTTP mocking:** `HttpClientTestingModule` + `HttpTestingController` de Angular
- **Arquitectura de tests:** Se configuró el target `test` en `angular.json` apuntando a `karma.conf.js` y `tsconfig.spec.json`

### 3.3 Tests de AuthService (`auth.service.spec.ts`)

| Test | Qué verifica |
|------|-------------|
| `should be created` | Inyección correcta del servicio |
| `should not be authenticated by default` | Estado inicial: sin token |
| `currentUser$ should emit null initially` | Observable emite null |
| `login() should store token and emit user` | POST `/api/auth/login` → guarda token en localStorage |
| `login() should send totp_code when provided` | Envía `totp_code` en el body si se proporciona |
| `logout() should clear token and localStorage` | Limpia token, localStorage y caché de claves |
| `loadProfile() should GET /api/auth/profile` | GET correcto a profile |
| `hasRole() should return false when no user` | RBAC sin usuario = false |
| `getUsers() should GET /api/auth/users` | Listado de usuarios |
| `changeUserRole() should PUT the new role` | PUT con nuevo rol al endpoint correcto |

**Técnica:** Se inyecta un spy de `CryptoService` para aislar `AuthService` de la criptografía real del navegador.

### 3.4 Tests de SecretsService (`secrets.service.spec.ts`)

| Test | Qué verifica |
|------|-------------|
| `should be created` | Inyección correcta |
| `SECRET_TYPE_LABELS should contain all types` | 8 tipos con etiquetas |
| `SECRET_TYPE_ICONS should contain all types` | Iconos Material correctos |
| `listSecrets() should GET /api/secrets` | GET sin parámetros |
| `listSecrets() should pass query params` | GET con type, page, per_page |
| `getSecret() should GET /api/secrets/:id` | GET por UUID |
| `decryptSecret() should POST /api/secrets/:id/decrypt` | POST decrypt |
| `createSecret() should POST with all fields` | POST con todos los campos |
| `updateSecret() should PUT /api/secrets/:id` | PUT + change_reason |
| `deleteSecret() should DELETE /api/secrets/:id` | DELETE soft delete |
| `getVersions() should GET .../versions` | Historial de versiones |
| `verifyIntegrity() should POST .../verify` | Verificación de integridad |
| `listFolders() should GET /api/folders` | Listar carpetas |
| `createFolder() should POST /api/folders` | Crear carpeta |
| `updateFolder() should PUT /api/folders/:id` | Renombrar carpeta |
| `deleteFolder() should DELETE /api/folders/:id` | Eliminar carpeta |

**Técnica:** Se usa `HttpTestingController` para interceptar y verificar cada petición HTTP (método, URL, body) sin servidor real.

### 3.5 Cómo ejecutar

```bash
cd cliente2

# Instalar dependencias de test (primera vez)
npm install --save-dev karma karma-chrome-launcher karma-coverage \
  karma-jasmine karma-jasmine-html-reporter @types/jasmine jasmine-core

# Ejecutar tests
ng test

# Ejecutar sin watch (CI)
ng test --watch=false --browsers=ChromeHeadless
```

---

## 4. Principios de diseño

### 4.1 Aislamiento

- **Backend:** Cada test usa una transacción SQLite en memoria con rollback automático. No hay estado compartido entre tests.
- **Frontend:** Se usa `HttpClientTestingModule` que intercepta todas las peticiones HTTP. No se necesita servidor backend corriendo.

### 4.2 Firma digital real en tests

Los tests de secretos requieren una firma digital RSA-PSS válida porque el endpoint `POST /api/secrets` llama a `crypto_manager.verify_signature()`. En lugar de mockear la verificación (lo cual reduciría la cobertura de seguridad), se genera un par de claves RSA real en `conftest.py` y se usa para firmar los `content_hash` en los tests.

### 4.3 Sin mocks innecesarios

- **Backend:** No se mockea SQLAlchemy ni Flask — se usa la app real con BD en memoria.
- **Frontend:** Solo se mockea lo necesario (CryptoService en AuthService, HTTP en ambos).

---

## 5. Ampliación futura

| Área | Tests sugeridos |
|------|----------------|
| `tests/test_sharing.py` | Compartición de secretos entre usuarios y grupos |
| `tests/test_groups.py` | CRUD de grupos y membresías |
| `tests/test_crypto.py` | Tests unitarios de `utils/crypto.py` (cifrado, firmas, hashes) |
| `tests/test_decorators.py` | Decorador `@require_role` con distintos roles |
| `*.component.spec.ts` | Tests de componentes Angular (SecretsListComponent, LoginComponent, etc.) |
| Tests E2E | Cypress o Playwright para flujo completo login → crear secreto → compartir |
