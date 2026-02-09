# 🔐 PROTECCI-N2025 - Sistema de Protección de Información Militar

Sistema seguro de almacenamiento e intercambio de información clasificada con cifrado de nivel militar.

## 📋 Descripción

Aplicación cliente-servidor para la protección y gestión de documentos clasificados militares, con múltiples capas de seguridad:

- **Servidor Flask**: Backend API REST con autenticación JWT y 2FA
- **Cliente CLI**: Interfaz de línea de comandos interactiva
- **Swagger UI**: Documentación interactiva de la API en `/swagger/`
- **Base de datos**: SQLite con datos sensibles cifrados
- **Criptografía**: RSA-4096, AES-256, PBKDF2-SHA512

## 🔒 Características de Seguridad

- ✅ **Cifrado asimétrico RSA-4096** para intercambio de claves
- ✅ **Cifrado simétrico AES-256-CBC** para archivos
- ✅ **Derivación de claves PBKDF2-SHA512** (200,000 iteraciones)
- ✅ **Autenticación de dos factores (2FA)** con TOTP/HOTP
- ✅ **Firmas digitales RSA-PSS** para verificación de integridad
- ✅ **Control de acceso basado en roles** (4 niveles de clasificación)
- ✅ **Auditoría completa** de todas las operaciones
- ✅ **Tokens JWT** para autenticación stateless
- ✅ **Bloqueo de cuentas** tras intentos fallidos
- ✅ **Hashing seguro** con Bcrypt (salt único por usuario)
- ✅ **HTTPS/SSL** para comunicación cifrada (TLS 1.2/1.3)

## 🎯 Niveles de Clasificación

1. **RESTRICTED** - Nivel básico de acceso restringido
2. **CONFIDENTIAL** - Información confidencial estándar
3. **SECRET** - Información secreta
4. **TOP_SECRET** - Máximo nivel de clasificación

## 📁 Estructura del Proyecto

```
PROTECCI-N2025/
├── servidor/                  # Backend Flask
│   ├── app.py                # Aplicación principal
│   ├── config.py             # Configuración (usa .env)
│   ├── models.py             # Modelos de base de datos
│   ├── requirements.txt      # Dependencias Python
│   ├── .env                  # Variables de entorno (NO SUBIR A GIT)
│   ├── .env.example          # Plantilla de configuración
│   ├── routes/               # Endpoints de la API
│   │   ├── auth.py          # Autenticación y usuarios
│   │   └── files.py         # Gestión de archivos
│   └── utils/                # Utilidades
│       ├── crypto.py        # Criptografía
│       └── totp.py          # Autenticación 2FA
│
├── cliente/                   # Cliente CLI
│   ├── client.py             # Cliente interactivo
│   ├── requirements.txt      # Dependencias
│   ├── .env                  # Configuración cliente
│   ├── .env.example          # Plantilla
│   └── README.md             # Documentación
│
├── .gitignore                 # Archivos ignorados por Git
├── ENV_CONFIG.md              # Guía de configuración .env
└── README.md                  # Este archivo
```

## 🚀 Instalación Rápida

### Requisitos Previos

- Python 3.8+
- pip
- Git (opcional)

### 🌐 Despliegue en Heroku (Producción)

**⚠️ IMPORTANTE:** El proyecto está en la carpeta `servidor/`, por lo que se requiere configuración especial.

Para desplegar en Heroku, consulta las guías detalladas:

- **📖 [DEPLOY_SUBDIR.md](DEPLOY_SUBDIR.md)** - ⭐ Быстрая инструкция для подпапки
- **📖 [HEROKU_SUBDIR.md](HEROKU_SUBDIR.md)** - Детальная документация
- **📖 [HEROKU_RU.md](servidor/HEROKU_RU.md)** - Полная инструкция на русском
- **📖 [QUICK_START.md](servidor/QUICK_START.md)** - Quick Start Guide

**Resumen rápido (desde raíz del proyecto):**
```bash
# Вариант 1: Git Subtree (рекомендуется)
heroku create
heroku addons:create heroku-postgresql:mini
cd servidor && python heroku_config.py && cd ..
git subtree push --prefix servidor heroku main

# Или используй готовый скрипт:
deploy-subtree.bat  # Windows
./deploy-subtree.sh # Linux/Mac

# Вариант 2: Subdir Buildpack
heroku buildpacks:add --index 1 https://github.com/timanovsky/subdir-heroku-buildpack
heroku buildpacks:add heroku/python
heroku config:set PROJECT_PATH=servidor
git push heroku main
```

### 💻 Instalación Local (Desarrollo)

### 1. Clonar o Descargar

```powershell
git clone https://github.com/zebn/PROTECCI-N2025.git
cd PROTECCI-N2025
```

### 2. Configurar Servidor

```powershell
cd servidor

# Crear entorno virtual (recomendado)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
copy .env.example .env
# Editar .env con tus valores (ver ENV_CONFIG.md)

# Ejecutar servidor
python app.py
```

**El servidor se iniciará con HTTPS en**: `https://localhost:5001`

Por defecto, el servidor:
- Genera automáticamente certificados SSL autofirmados si no existen
- Inicia con HTTPS habilitado (variable `USE_SSL=True`)
- Crea directorio `certs/` con certificados

**Para deshabilitar HTTPS** (usar HTTP):
```powershell
$env:USE_SSL = "False"
python app.py
```

**Ver documentación completa de HTTPS**: [HTTPS_SETUP.md](HTTPS_SETUP.md)

### 3. Configurar Cliente

```powershell
cd ..\cliente

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
copy .env.example .env
# Editar .env si es necesario

# Ejecutar cliente
python client.py
```

## ⚙️ Configuración con Variables de Entorno

Este proyecto usa archivos `.env` para configuración. **Ver `ENV_CONFIG.md` para guía completa.**

### Variables Críticas del Servidor

```env
SECRET_KEY=tu-clave-secreta-super-segura
JWT_SECRET_KEY=otra-clave-diferente-para-jwt
DATABASE_URL=sqlite:///database.db
PORT=5001
```

### Variables del Cliente

```env
SERVER_URL=http://localhost:5001
REQUEST_TIMEOUT=30
```

⚠️ **IMPORTANTE**: Cambiar todas las claves por defecto antes de usar en producción.

## 📖 Uso del Cliente CLI

```powershell
python client.py
```

### Menú Principal

```
1. Información del servidor
2. Verificar estado (health check)
3. Registrar nuevo usuario
4. Iniciar sesión
5. Ver perfil
6. Configurar 2FA
7. Verificar 2FA
8. Listar mis archivos
9. Cerrar sesión
0. Salir
```

### Flujo de Trabajo Típico

1. **Registrarse** (opción 3)
2. **Iniciar sesión** (opción 4)
3. **Configurar 2FA** (opción 6) - Recomendado
4. **Verificar 2FA** (opción 7)
5. **Ver archivos** (opción 8)

## 🔧 API Endpoints

### Autenticación (`/api/auth`)

- `POST /register` - Registrar usuario
- `POST /login` - Iniciar sesión
- `POST /setup-2fa` - Configurar 2FA
- `POST /verify-2fa` - Verificar 2FA
- `POST /logout` - Cerrar sesión
- `GET /profile` - Ver perfil

### Archivos (`/api/files`)

- `POST /upload` - Subir archivo cifrado
- `GET /list` - Listar archivos propios
- `GET /<id>` - Descargar archivo
- `POST /share` - Compartir con otro usuario
- `DELETE /<id>` - Eliminar archivo

## 🛡️ Seguridad en Producción

### Checklist de Despliegue

- [ ] Cambiar `SECRET_KEY` y `JWT_SECRET_KEY` por valores aleatorios fuertes
- [ ] Usar HTTPS (no HTTP)
- [ ] Configurar `FLASK_ENV=production`
- [ ] Usar base de datos robusta (PostgreSQL/MySQL en vez de SQLite)
- [ ] Implementar rate limiting
- [ ] Configurar firewall
- [ ] Habilitar logs de auditoría
- [ ] Backup regular de base de datos
- [ ] Revisar permisos de archivos
- [ ] Validar CORS_ORIGINS

### Generar Claves Seguras

```powershell
# PowerShell
-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | % {[char]$_})
```

```python
# Python
import secrets
print(secrets.token_urlsafe(64))
```

## 🧪 Testing

```powershell
# Servidor
cd servidor
python -m pytest

# Cliente
cd cliente
python client.py http://localhost:5001
```

## 📊 Base de Datos

### Modelos Principales

- **User**: Usuarios con claves RSA y 2FA
- **SecureFile**: Archivos cifrados con metadatos
- **FileAccessLog**: Registro de accesos a archivos
- **AuditLog**: Auditoría completa de operaciones
- **SignedOperation**: Operaciones con firma digital

## 🐛 Troubleshooting

**Error: "ModuleNotFoundError: No module named 'dotenv'"**
```powershell
pip install python-dotenv
```

**Error: "SECRET_KEY no configurado"**
- Asegurarse de que existe el archivo `.env`
- Verificar que contiene `SECRET_KEY=valor`

**Error de conexión en cliente**
- Verificar que el servidor está corriendo
- Comprobar que `SERVER_URL` en `cliente/.env` es correcto
- Revisar firewall

**Token expirado**
- Volver a iniciar sesión (opción 4 en el cliente)

## 📝 Licencia

[Especificar licencia]

## 👥 Contribuir

1. Fork el proyecto
2. Crear branch (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agregar funcionalidad'`)
4. Push al branch (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## 📞 Contacto

- GitHub: [@zebn](https://github.com/zebn)
- Proyecto: [PROTECCI-N2025](https://github.com/zebn/PROTECCI-N2025)

## 🔄 Versión

**v1.0.0** - Octubre 2025

---

⚠️ **AVISO**: Este sistema maneja información clasificada. Asegúrese de cumplir con todas las regulaciones de seguridad aplicables en su jurisdicción.
