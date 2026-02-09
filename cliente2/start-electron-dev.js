const { spawn } = require('child_process');

let electronStarted = false;
let angularPort = null;

// Iniciar servidor Angular
console.log('🚀 Iniciando servidor Angular...\n');
const ngServe = spawn('ng', ['serve'], {
    shell: true,
    stdio: 'pipe'
});

// Capturar salida de Angular para detectar cuando está listo
ngServe.stdout.on('data', (data) => {
    const output = data.toString();
    process.stdout.write(output);

    // Detectar el puerto en el que Angular está escuchando
    const portMatch = output.match(/localhost:(\d+)/);
    if (portMatch && !angularPort) {
        angularPort = portMatch[1];
        console.log(`\n📡 Angular detectado en puerto: ${angularPort}\n`);
    }

    // Detectar cuando Angular está listo
    if (!electronStarted && output.includes('Compiled successfully') && angularPort) {
        electronStarted = true;
        console.log('\n✅ Servidor Angular listo');
        console.log('⏳ Esperando 3 segundos antes de iniciar Electron...\n');

        // Esperar 3 segundos adicionales y luego iniciar Electron
        setTimeout(() => {
            const electronUrl = `http://localhost:${angularPort}`;
            console.log(`🖥️  Iniciando aplicación Electron con URL: ${electronUrl}\n`);
            
            const electronPath = require('electron');
            const electron = spawn(electronPath, ['.'], {
                stdio: 'pipe',
                env: {
                    ...process.env,
                    ELECTRON_START_URL: electronUrl,
                    ELECTRON_ENABLE_LOGGING: '1'
                }
            });

            // Capturar salida de Electron
            electron.stdout.on('data', (data) => {
                console.log('[Electron]', data.toString());
            });

            electron.stderr.on('data', (data) => {
                console.error('[Electron Error]', data.toString());
            });

            electron.on('error', (error) => {
                console.error('❌ Error al iniciar Electron:', error);
                ngServe.kill();
                process.exit(1);
            });

            electron.on('close', (code) => {
                console.log(`\n🛑 Electron cerrado con código: ${code}`);
                ngServe.kill();
                process.exit(code);
            });
        }, 3000);
    }
});

ngServe.stderr.on('data', (data) => {
    process.stderr.write(data);
});// Manejar Ctrl+C
process.on('SIGINT', () => {
    console.log('\n🛑 Deteniendo aplicación...');
    ngServe.kill();
    process.exit(0);
});
