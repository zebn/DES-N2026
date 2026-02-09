# 🚀 MILCOM Secure Exchange - Guía de Compilación

## 📋 Comandos Principales

### Desarrollo (con hot-reload)
```bash
npm run dev
```
- Inicia servidor Angular en `http://localhost:4200`
- Abre ventana Electron automáticamente
- Hot-reload activado (cambios en tiempo real)
- DevTools abierto automáticamente

### Compilar para Windows (.exe)

#### Instalador + Portable
```bash
npm run build:exe
```
**Resultado:**
- 📦 `release/MILCOM Secure Exchange Setup.exe` (~150 MB) - Instalador NSIS
- 📦 `release/MILCOM Secure Exchange.exe` (~200 MB) - Versión portable

#### Solo Portable (más rápido)
```bash
npm run build:portable
```
**Resultado:**
- 📦 `release/MILCOM Secure Exchange.exe` - Solo versión portable

### Compilar para múltiples plataformas
```bash
npm run build:all
```
**Resultado:**
- Windows: Instalador NSIS + Portable
- macOS: DMG
- Linux: AppImage + DEB

---

## 🔧 Proceso de Compilación

1. **Angular Build** (`ng build --configuration production`):
   - Compila aplicación Angular
   - Optimiza y minifica código
   - Genera archivos en `dist/protecci-n-client/`

2. **Electron Builder** (`electron-builder`):
   - Empaqueta aplicación Electron
   - Incluye Chromium + Node.js
   - Genera ejecutables para plataforma seleccionada

---

## 📂 Estructura de Archivos

```
cliente2/
├── dist/                          # Compilación Angular (generado)
│   └── protecci-n-client/
│       ├── index.html
│       ├── main.*.js
│       └── ...
├── release/                       # Ejecutables (generado)
│   ├── MILCOM Secure Exchange Setup.exe
│   └── MILCOM Secure Exchange.exe
├── electron.js                    # Proceso principal Electron
├── start-electron-dev.js          # Script para desarrollo
└── package.json                   # Configuración
```

---

## ⚙️ Configuración de Compilación

### electron-builder (package.json)

```json
{
  "build": {
    "appId": "com.milcom.protecci-n",
    "productName": "MILCOM Secure Exchange",
    "files": [
      "dist/**/*",           // Archivos Angular compilados
      "electron.js",          // Proceso principal
      "package.json"
    ],
    "win": {
      "target": ["nsis", "portable"],
      "icon": "src/favicon.ico"
    }
  }
}
```

### Opciones NSIS (Instalador Windows)
- ✅ Instalación personalizada (elige directorio)
- ✅ Acceso directo en escritorio
- ✅ Acceso directo en menú inicio
- ✅ Desinstalador incluido

---

## 🔒 Características de Seguridad

El ejecutable incluye:
- ✅ Sandbox activado (`sandbox: true`)
- ✅ Context Isolation (`contextIsolation: true`)
- ✅ Node Integration desactivado (`nodeIntegration: false`)
- ✅ Content Security Policy (CSP)
- ✅ Prevención de navegación externa

---

## 📊 Tamaños de Archivos

| Tipo | Tamaño Aproximado |
|------|-------------------|
| Instalador NSIS | ~150 MB |
| Portable .exe | ~200 MB |
| Aplicación instalada | ~250 MB |

**¿Por qué tan grande?**
- Chromium completo (~100 MB)
- Node.js runtime (~30 MB)
- Aplicación Angular (~20 MB)
- Librerías criptográficas

---

## 🐛 Solución de Problemas

### Error: "Cannot find module 'electron'"
```bash
npm install
```

### Error: "dist/protecci-n-client/index.html not found"
```bash
npm run build:prod
```

### Ejecutable no inicia
1. Verifica que no haya antivirus bloqueando
2. Ejecuta desde terminal para ver errores:
   ```bash
   .\release\MILCOM Secure Exchange.exe
   ```

### DevTools no se cierra en producción
Edita `electron.js`:
```javascript
// Comentar esta línea:
// mainWindow.webContents.openDevTools();
```

---

## 📝 Notas Importantes

1. **Primera compilación**: Tarda 2-5 minutos (descarga dependencias)
2. **Compilaciones siguientes**: Tarda 1-2 minutos
3. **Certificado de firma**: Para distribución pública, necesitas firmar con certificado de código
4. **Actualizaciones**: electron-builder soporta auto-update (requiere configuración adicional)

---

## 🌐 URLs del Backend

La aplicación se conecta a:
- **Desarrollo local**: `https://localhost:5001`
- **Producción**: `https://protinf-e061fd7b2275.herokuapp.com`

Configurable en `src/environments/environment.ts` y `environment.prod.ts`

---

## 📦 Distribución

### Instalador (recomendado para usuarios finales)
```
MILCOM Secure Exchange Setup.exe
```
- Se instala en `C:\Program Files\MILCOM Secure Exchange\`
- Crea accesos directos
- Permite desinstalar desde Panel de Control

### Portable (recomendado para USB/pruebas)
```
MILCOM Secure Exchange.exe
```
- No requiere instalación
- Ejecutable único
- Puede correr desde USB

---

## 🚀 Comandos Rápidos

```bash
# Desarrollo
npm run dev

# Compilar para Windows
npm run build:exe

# Solo portable (más rápido)
npm run build:portable

# Todas las plataformas
npm run build:all
```

---

**Versión**: 1.0.0  
**Última actualización**: Noviembre 2025
