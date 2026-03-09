# 🔐 DES-N2026 — Sentryvault

Sistema de gestión segura de identidades y secretos con cifrado End-to-End.

## 📋 Descripción

Plataforma cliente-servidor para almacenamiento y gestión de **secretos** (contraseñas, claves API, certificados, SSH keys, notas seguras) y **archivos clasificados**, con cifrado E2E donde el servidor **nunca** tiene acceso al texto plano (modelo Zero Knowledge).

- **Backend**: Flask REST API con JWT + 2FA (TOTP)
- **Frontend Web**: Angular 17 + Angular Material
- **Cliente Desktop**: Electron (empaquetado del frontend Angular)
- **Cliente CLI**: Python interactivo (legacy)
- **Swagger UI**: Documentación de API en `/swagger/`
- **Base de datos**: SQLite (desarrollo) / PostgreSQL (producción)

## 🔒 Características de Seguridad

- ✅ **RSA-4096** — cifrado asimétrico para intercambio de claves
- ✅ **AES-256-CTR** — cifrado simétrico de secretos y archivos
- ✅ **Argon2id** (64 MB, 3 iter, 4 threads) — derivación de claves desde contraseña
- ✅ **RSA-PSS SHA-256** — firmas digitales para integridad y no-repudio
- ✅ **SHA-256** — verificación de integridad de contenido
- ✅ **TOTP/HOTP** — autenticación de dos factores
- ✅ **JWT** — tokens de acceso/refresh con revocación
- ✅ **Bcrypt** — hashing de contraseñas de usuario
- ✅ **HTTPS/TLS** — cifrado de transporte (certificado autofirmado en desarrollo)
- ✅ **Auditoría completa** — log de todas las operaciones criptográficas
- ✅ **Bloqueo de cuentas** — tras intentos fallidos de autenticación
- ✅ **Zero Knowledge** — el servidor solo almacena datos cifrados

## 📁 Estructura del Proyecto

```
DES-N2026/
├── app.py                     # Servidor Flask (punto de entrada)
├── config.py                  # Configuración (variables de entorno)
├── models.py                  # Modelos SQLAlchemy (User, Secret, SecretVersion, etc.)
├── requirements.txt           # Dependencias Python
├── routes/                    # Endpoints de la API
│   ├── auth.py               #   Autenticación, registro, 2FA, perfil
│   ├── files.py              #   Gestión de archivos cifrados
│   └── secrets.py            #   CRUD de secretos + carpetas + versiones
├── utils/                     # Utilidades
│   ├── crypto.py             #   CryptoManager (RSA, AES, firmas, hashes)
│   ├── totp.py               #   Generación/verificación TOTP
│   └── decorators.py         #   Decoradores de autorización
├── cliente/                   # Cliente CLI (Python)
│   └── client.py
├── cliente2/                  # Frontend Angular 17 + Electron
│   ├── src/app/
│   │   ├── core/services/    #   AuthService, CryptoService, SecretsService, etc.
│   │   ├── features/
│   │   │   ├── auth/         #   Login, registro, 2FA
│   │   │   ├── files/        #   Upload, listado, compartir archivos
│   │   │   ├── secrets/      #   Bóveda de secretos (lista, crear, detalle)
│   │   │   └── profile/      #   Perfil de usuario
│   │   └── shared/           #   Componentes compartidos (dialogs)
│   └── electron.js           #   Wrapper Electron para desktop
├── docs/
│   └── PRD.md                # Product Requirements Document (especificación completa)
├── certs/                     # Certificados SSL autofirmados (auto-generados)
└── instance/
    └── database.db            # Base de datos SQLite (desarrollo)
```

## 🚀 Instalación Rápida (Desarrollo Local)

### Requisitos previos

- Python 3.10+
- Node.js 18+ y npm
- Git

### 1. Backend (Flask)

```powershell
# Desde la raíz del proyecto
python -m venv venv
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt

# Iniciar servidor (HTTPS en puerto 5001)
python app.py
```

El servidor automáticamente:
- Genera certificados SSL si no existen (`certs/`)
- Inicia en `https://localhost:5001`
- Crea la BD SQLite (`instance/database.db`)
- Crea usuario admin: `admin@admin.com` / `1`
- Swagger UI en `https://localhost:5001/swagger/`

Para desactivar HTTPS:
```powershell
$env:USE_SSL = "False"
python app.py
```

### 2. Frontend Angular

```powershell
cd cliente2
npm install
npm start
# Abierto en http://localhost:4200
```

### 3. Cliente CLI (opcional)

```powershell
cd cliente
pip install -r requirements.txt
python client.py
```

## ⚙️ Variables de Entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-key-...` | Clave secreta de Flask |
| `JWT_SECRET_KEY` | = SECRET_KEY | Clave para firmar JWT |
| `DATABASE_URL` | `sqlite:///database.db` | URL de base de datos |
| `PORT` | `5001` | Puerto del servidor |
| `USE_SSL` | `True` | Activar HTTPS |
| `FLASK_ENV` | `development` | Entorno (development/production) |
| `JWT_ACCESS_TOKEN_HOURS` | `1` | Duración del access token |

## 🔧 API Endpoints

### Autenticación (`/api/auth`)

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/auth/register` | Registrar usuario (con claves RSA) |
| POST | `/api/auth/login` | Login → devuelve JWT |
| POST | `/api/auth/setup-2fa` | Configurar TOTP |
| POST | `/api/auth/verify-2fa` | Verificar código TOTP |
| GET | `/api/auth/profile` | Perfil del usuario autenticado |
| POST | `/api/auth/logout` | Cerrar sesión |

### Secretos (`/api/secrets`)

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/secrets` | Crear secreto cifrado E2E |
| GET | `/api/secrets` | Listar secretos (filtros + paginación) |
| GET | `/api/secrets/:id` | Metadatos de un secreto |
| POST | `/api/secrets/:id/decrypt` | Obtener datos cifrados para descifrar en cliente |
| PUT | `/api/secrets/:id` | Actualizar (crea nueva versión) |
| DELETE | `/api/secrets/:id` | Eliminar (soft delete) |
| GET | `/api/secrets/:id/versions` | Historial de versiones |
| POST | `/api/secrets/:id/rotate` | Rotar secreto |
| POST | `/api/secrets/:id/verify` | Verificar integridad |

### Carpetas (`/api/folders`)

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/folders` | Crear carpeta |
| GET | `/api/folders` | Listar carpetas |
| PUT | `/api/folders/:id` | Renombrar/mover |
| DELETE | `/api/folders/:id` | Eliminar |

### Archivos (`/api/files`)

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/files/upload` | Subir archivo cifrado |
| GET | `/api/files/list` | Listar archivos |
| GET | `/api/files/:id` | Descargar archivo |
| POST | `/api/files/share` | Compartir con otro usuario |
| DELETE | `/api/files/:id` | Eliminar |

## 🏗️ Arquitectura de Cifrado E2E

```
CREAR SECRETO (cliente):
  1. JSON del secreto → plaintext bytes
  2. SHA-256(plaintext) → content_hash
  3. Generar AES-256 key + nonce aleatorio
  4. AES-256-CTR(plaintext) → encrypted_data
  5. RSA-4096-OAEP(aes_key, public_key) → encrypted_aes_key
  6. RSA-PSS(content_hash, private_key) → digital_signature
  7. Enviar al servidor: encrypted_data + encrypted_aes_key + hash + firma

LEER SECRETO (cliente):
  1. Servidor devuelve datos cifrados
  2. RSA-4096 descifra clave AES con private_key
  3. AES-256-CTR descifra contenido
  4. Verificar SHA-256 == content_hash
  5. Verificar firma RSA-PSS
  6. Mostrar en UI
```

El servidor **nunca** tiene acceso al contenido descifrado (Zero Knowledge).

## 📊 Modelos de Base de Datos

| Modelo | Tabla | Descripción |
|--------|-------|-------------|
| `User` | users | Usuarios con claves RSA, 2FA, roles |
| `Secret` | secrets | Secretos cifrados E2E (contraseñas, API keys, etc.) |
| `SecretVersion` | secret_versions | Historial de versiones de cada secreto |
| `SecretAccessLog` | secret_access_logs | Log de accesos a secretos |
| `Folder` | folders | Carpetas para organizar secretos |
| `SecureFile` | secure_files | Archivos binarios cifrados |
| `FileAccessLog` | file_access_logs | Log de accesos a archivos |
| `FileShare` | file_shares | Compartición de archivos entre usuarios |
| `AuditLog` | audit_logs | Auditoría general de operaciones |
| `SignedOperation` | signed_operations | Operaciones con firma digital |

## 📖 Documentación Detallada

El **Product Requirements Document** completo está en [`docs/PRD.md`](docs/PRD.md) — contiene:
- Especificación completa de requisitos funcionales y no funcionales
- Modelos de datos detallados
- Flujos criptográficos
- Justificación de herramientas desde perspectiva de seguridad
- Análisis de amenazas y mitigaciones
- Modelo SDL aplicado

## 🛡️ Checklist de Seguridad para Producción

- [ ] Cambiar `SECRET_KEY` y `JWT_SECRET_KEY` por valores aleatorios fuertes
- [ ] Usar HTTPS con certificado válido (no autofirmado)
- [ ] Configurar `FLASK_ENV=production`
- [ ] Migrar a PostgreSQL
- [ ] Validar `CORS_ORIGINS`
- [ ] Implementar rate limiting
- [ ] Backup regular de base de datos

## 📝 Licencia

Proyecto académico — DES-N2026 (Desarrollo de Aplicaciones Seguras, 2026)

## 👥 Contacto

- GitHub: [@zebn](https://github.com/zebn)

---

**v2.0.0** — Febrero 2026 (pivote a gestión de identidades y secretos)
