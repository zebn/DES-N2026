import { Injectable } from '@angular/core';
import { MatSnackBar, MatSnackBarConfig } from '@angular/material/snack-bar';
import { NotificationComponent, NotificationData } from '../components/notification/notification.component';

export interface NotificationConfig {
  title: string;
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
  duration?: number;
  details?: string[];
}

@Injectable({
  providedIn: 'root'
})
export class NotificationService {
  constructor(private snackBar: MatSnackBar) {}

  /**
   * Mostrar notificación detallada en el centro de la pantalla
   */
  show(config: NotificationConfig): void {
    const duration = config.duration || 10000;

    const snackBarConfig: MatSnackBarConfig<NotificationData> = {
      duration: duration,
      horizontalPosition: 'center',
      verticalPosition: 'top',
      panelClass: ['custom-snackbar', `snackbar-${config.type}`],
      data: {
        title: config.title,
        message: config.message,
        type: config.type,
        details: config.details
      }
    };

    this.snackBar.openFromComponent(NotificationComponent, snackBarConfig);
  }

  /**
   * Notificación de éxito
   */
  success(title: string, message: string, details?: string[]): void {
    this.show({
      title,
      message,
      type: 'success',
      details
    });
  }

  /**
   * Notificación de error
   */
  error(title: string, message: string, details?: string[]): void {
    this.show({
      title,
      message,
      type: 'error',
      details,
      duration: 5000
    });
  }

  /**
   * Notificación de advertencia
   */
  warning(title: string, message: string, details?: string[]): void {
    this.show({
      title,
      message,
      type: 'warning',
      details
    });
  }

  /**
   * Notificación informativa
   */
  info(title: string, message: string, details?: string[]): void {
    this.show({
      title,
      message,
      type: 'info',
      details
    });
  }

  /**
   * Notificación de proceso de cifrado
   */
  cryptoProcess(step: string, detail: string): void {
    this.info(
      '🔐 Proceso Criptográfico',
      step,
      [detail]
    );
  }

  /**
   * Notificación de generación de claves RSA
   */
  rsaKeyGeneration(): void {
    this.info(
      '🔑 Generando Claves RSA-4096',
      'Por favor espere, esto puede tomar unos segundos...',
      [
        'Generando par de claves asimétricas',
        'Algoritmo: RSA-OAEP con SHA-512',
        'Tamaño: 4096 bits',
        'Exportando clave pública en formato SPKI',
        'Cifrando clave privada con PBKDF2'
      ]
    );
  }

  /**
   * Notificación de éxito en cifrado de archivo
   */
  fileEncrypted(filename: string, size: string): void {
    this.success(
      '✅ Archivo Cifrado Exitosamente',
      `El archivo "${filename}" ha sido cifrado de forma segura`,
      [
        `Tamaño: ${size}`,
        'Algoritmo: AES-256-GCM',
        'Clave AES protegida con RSA-4096',
        'Hash SHA-256 generado para integridad',
        'Listo para subir al servidor'
      ]
    );
  }

  /**
   * Notificación de descarga y descifrado
   */
  fileDecrypted(filename: string): void {
    this.success(
      '✅ Archivo Descifrado',
      `El archivo "${filename}" ha sido descifrado correctamente`,
      [
        'Clave AES recuperada con RSA privada',
        'Contenido descifrado con AES-256-GCM',
        'Integridad verificada con SHA-256',
        'Descarga iniciada automáticamente'
      ]
    );
  }

  /**
   * Notificación de autenticación exitosa
   */
  loginSuccess(userName: string): void {
    this.success(
      '🎉 Bienvenido al Sistema',
      `Sesión iniciada como: ${userName}`,
      [
        'Token JWT generado',
        'Claves criptográficas cargadas',
        'Sesión segura establecida',
        'Acceso concedido a archivos clasificados'
      ]
    );
  }

  /**
   * Notificación de registro exitoso
   */
  registrationSuccess(userName: string): void {
    this.success(
      '✅ Registro Completado',
      `Cuenta creada exitosamente para: ${userName}`,
      [
        'Par de claves RSA-4096 generado',
        'Clave privada cifrada con tu contraseña',
        'Clave pública almacenada en servidor',
        'Usuario registrado en la base de datos',
        'Ya puedes iniciar sesión'
      ]
    );
  }

  /**
   * Notificación de 2FA requerido
   */
  twoFactorRequired(): void {
    this.warning(
      '🔐 Autenticación de Dos Factores',
      'Tu cuenta tiene 2FA habilitado',
      [
        'Ingresa el código TOTP de tu aplicación',
        'El código cambia cada 30 segundos',
        'Usa Google Authenticator o similar'
      ]
    );
  }
}
