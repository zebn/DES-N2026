# MILCOM Secure Exchange - Aplicación Desktop

Aplicación de escritorio para el Sistema de Protección de Información Clasificada con cifrado End-to-End.

## Características

- 🔐 Cifrado AES-256-CBC + RSA-4096
- 🛡️ Arquitectura Zero Trust
- 🔑 Gestión de claves criptográficas
- 📁 Subida/descarga de archivos cifrados
- ✍️ Firma digital RSA-PSS
- 🔒 2FA con TOTP

## Desarrollo

### Instalar dependencias
```bash
npm install
```

### Ejecutar en modo desarrollo (con recarga automática)
```bash
npm run electron:serve
```

### Ejecutar sin servidor Angular
```bash
npm run electron:dev
```

## Compilar aplicación de escritorio

### Windows
```bash
npm run electron:build:win
```

Genera:
- `release/MILCOM Secure Exchange Setup.exe` - Instalador NSIS
- `release/MILCOM Secure Exchange.exe` - Versión portable

### macOS
```bash
npm run electron:build:mac
```

Genera:
- `release/MILCOM Secure Exchange.dmg`

### Linux
```bash
npm run electron:build:linux
```

Genera:
- `release/MILCOM Secure Exchange.AppImage`
- `release/milcom-secure-exchange.deb`

## Scripts disponibles

| Script | Descripción |
|--------|-------------|
| `npm run electron` | Ejecutar Electron (requiere build previo) |
| `npm run electron:dev` | Build + Electron |
| `npm run electron:serve` | Desarrollo con recarga automática |
| `npm run electron:build` | Compilar para plataforma actual |
| `npm run electron:build:win` | Compilar para Windows |
| `npm run electron:build:mac` | Compilar para macOS |
| `npm run electron:build:linux` | Compilar para Linux |

## Estructura de archivos

```
cliente2/
├── electron.js           # Proceso principal de Electron
├── src/                  # Código fuente Angular
├── dist/                 # Build de Angular
└── release/              # Aplicaciones compiladas
```

## Configuración de seguridad

La aplicación implementa:
- Content Security Policy (CSP) estricto
- Sandbox de Electron habilitado
- Context isolation activado
- Node integration deshabilitado
- Prevención de navegación externa

## Requisitos del sistema

- **Windows**: Windows 10 o superior
- **macOS**: macOS 10.14 (Mojave) o superior
- **Linux**: Ubuntu 18.04+ o distribuciones equivalentes

## Servidor API

Por defecto, la aplicación se conecta a:
- Desarrollo: `http://localhost:5001`
- Producción: `https://protinf-e061fd7b2275.herokuapp.com`

Configurable en `src/environments/environment.ts` y `environment.prod.ts`

## Tamaño aproximado

- **Instalador Windows**: ~150 MB
- **Portable Windows**: ~200 MB
- **DMG macOS**: ~180 MB
- **AppImage Linux**: ~170 MB

## Atajos de teclado

| Atajo | Acción |
|-------|--------|
| `Ctrl/Cmd + R` | Recargar aplicación |
| `Ctrl/Cmd + Q` | Salir |
| `F11` | Pantalla completa |
| `Ctrl/Cmd + Shift + I` | Herramientas de desarrollo |

## Licencia

Uso interno - Sistema de Inteligencia Militar
