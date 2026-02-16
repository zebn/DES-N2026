const { app, BrowserWindow, Menu } = require('electron');
const path = require('path');
const url = require('url');

console.log('🔧 Electron iniciando...');
console.log('📁 __dirname:', __dirname);
console.log('🌍 ELECTRON_START_URL:', process.env.ELECTRON_START_URL);

let mainWindow;

function createWindow() {
    console.log('🪟 Creando ventana principal...');

    // Ignorar errores de certificado SSL para localhost (desarrollo y producción)
    app.commandLine.appendSwitch('ignore-certificate-errors');
    console.log('⚠️  Ignorando errores de certificado SSL para localhost');

    // Crear ventana del navegador
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1024,
        minHeight: 768,
        backgroundColor: '#1a1a2e',
        icon: path.join(__dirname, 'src/favicon.ico'),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            enableRemoteModule: false,
            sandbox: true
        },
        autoHideMenuBar: false,
        title: 'SentryVault - Protrego tu información más secreta"
    });

    // Cargar aplicación Angular
    const startUrl = process.env.ELECTRON_START_URL || url.format({
        pathname: path.join(__dirname, 'dist/protecci-n-client/index.html'),
        protocol: 'file:',
        slashes: true
    });

    console.log('🌐 Cargando aplicación desde:', startUrl);

    mainWindow.loadURL(startUrl).catch(err => {
        console.error('❌ Error al cargar URL:', err);
    });

    // Abrir DevTools en desarrollo
    if (process.env.ELECTRON_START_URL) {
        mainWindow.webContents.openDevTools();
    }

    // Manejo de errores de carga
    mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
        console.error('❌ Error de carga:', errorCode, errorDescription, validatedURL);

        // Si falla cargar, intentar recargar después de 2 segundos
        if (errorCode === -102 || errorCode === -3) {
            console.log('⏳ Reintentando en 2 segundos...');
            setTimeout(() => {
                console.log('🔄 Recargando...');
                mainWindow.reload();
            }, 2000);
        }
    });

    // Logging cuando la página está lista
    mainWindow.webContents.on('did-finish-load', () => {
        console.log('✅ Página cargada correctamente');
    });

    // Logging de mensajes de consola de la aplicación
    mainWindow.webContents.on('console-message', (event, level, message, line, sourceId) => {
        console.log(`[Renderer] ${message}`);
    });

    // Menú personalizado
    const menuTemplate = [
        {
            label: 'Archivo',
            submenu: [
                {
                    label: 'Recargar',
                    accelerator: 'CmdOrCtrl+R',
                    click: () => mainWindow.reload()
                },
                { type: 'separator' },
                {
                    label: 'Salir',
                    accelerator: 'CmdOrCtrl+Q',
                    click: () => app.quit()
                }
            ]
        },
        {
            label: 'Ver',
            submenu: [
                {
                    label: 'Pantalla completa',
                    accelerator: 'F11',
                    click: () => mainWindow.setFullScreen(!mainWindow.isFullScreen())
                },
                {
                    label: 'Herramientas de desarrollo',
                    accelerator: 'CmdOrCtrl+Shift+I',
                    click: () => mainWindow.webContents.toggleDevTools()
                }
            ]
        },
        {
            label: 'Ayuda',
            submenu: [
                {
                    label: 'Acerca de',
                    click: () => {
                        const { dialog } = require('electron');
                        dialog.showMessageBox(mainWindow, {
                            type: 'info',
                            title: 'SentryVault',
                            message: 'Sistema de Protección de Información Clasificada',
                            detail: 'Versión 1.0.0\n\n' +
                                'Cifrado End-to-End:\n' +
                                '• AES-256-CBC\n' +
                                '• RSA-4096-OAEP\n' +
                                '• PBKDF2-SHA512\n' +
                                '• RSA-PSS Firma Digital\n\n' +
                                'Arquitectura Zero Trust'
                        });
                    }
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(menuTemplate);
    Menu.setApplicationMenu(menu);

    // Manejar cierre de ventana
    mainWindow.on('closed', () => {
        mainWindow = null;
    });

    // Prevenir navegación externa (excepto localhost en desarrollo)
    mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
        const parsedUrl = new URL(navigationUrl);
        const allowedOrigins = ['file://', 'http://localhost:4200', 'http://localhost:5001', 'https://localhost:5001'];

        if (!allowedOrigins.some(origin => navigationUrl.startsWith(origin))) {
            console.log('🚫 Navegación bloqueada a:', navigationUrl);
            event.preventDefault();
        }
    });
}

// Cuando Electron termina de inicializarse
app.on('ready', () => {
    console.log('✅ Electron listo, creando ventana...');
    createWindow();
});

// Ignorar errores de certificado SSL para localhost (desarrollo y producción)
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
    if (url.startsWith('https://localhost') || url.startsWith('https://127.0.0.1')) {
        // Aceptar certificados autofirmados para localhost
        event.preventDefault();
        callback(true);
        console.log('⚠️  Certificado SSL aceptado para:', url);
    } else {
        callback(false);
    }
});

// Cerrar cuando todas las ventanas estén cerradas
app.on('window-all-closed', () => {
    console.log('🔴 Todas las ventanas cerradas');
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// Recrear ventana en macOS
app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();
    }
});

// Configuración de seguridad
app.on('web-contents-created', (event, contents) => {
    // Prevenir creación de nuevas ventanas
    contents.setWindowOpenHandler(() => {
        return { action: 'deny' };
    });
});
