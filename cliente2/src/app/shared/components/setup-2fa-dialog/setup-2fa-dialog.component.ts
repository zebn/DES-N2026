import { Component, OnInit } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { FormControl, Validators } from '@angular/forms';
import { AuthService, Setup2FAResponse } from '../../../core/services/auth.service';
import { MatSnackBar } from '@angular/material/snack-bar';

@Component({
    selector: 'app-setup-2fa-dialog',
    template: `
    <h2 mat-dialog-title>
      <mat-icon>security</mat-icon>
      Configurar Autenticación de Dos Factores
    </h2>
    
    <mat-dialog-content>
      <!-- Step 1: Loading -->
      <div *ngIf="isLoading" class="loading-container">
        <mat-spinner diameter="50"></mat-spinner>
        <p>Generando código QR...</p>
      </div>

      <!-- Step 2: Show QR Code -->
      <div *ngIf="!isLoading && setupData && !isVerified" class="setup-container">
        <div class="instructions">
          <mat-icon>phone_android</mat-icon>
          <p>Escanea este código QR con tu aplicación de autenticación:</p>
        </div>

        <div class="qr-container">
          <img [src]="'data:image/png;base64,' + setupData.qr_code" alt="QR Code 2FA" class="qr-code">
        </div>

        <div class="secret-container">
          <p class="secret-label">O ingresa este código manualmente:</p>
          <code class="secret-code">{{ setupData.secret }}</code>
          <button mat-icon-button (click)="copySecret()" matTooltip="Copiar código">
            <mat-icon>content_copy</mat-icon>
          </button>
        </div>

        <mat-divider></mat-divider>

        <div class="verify-section">
          <p>Ingresa el código de 6 dígitos de tu aplicación para confirmar:</p>
          <mat-form-field appearance="outline" class="code-input">
            <mat-label>Código TOTP</mat-label>
            <input matInput [formControl]="totpCode" maxlength="6" 
                   placeholder="000000" (keyup.enter)="verify()">
            <mat-icon matPrefix>pin</mat-icon>
            <mat-error *ngIf="totpCode.hasError('required')">Código requerido</mat-error>
            <mat-error *ngIf="totpCode.hasError('pattern')">Debe ser 6 dígitos</mat-error>
          </mat-form-field>
        </div>
      </div>

      <!-- Step 3: Success with backup codes -->
      <div *ngIf="isVerified && backupCodes.length > 0" class="success-container">
        <div class="success-header">
          <mat-icon class="success-icon">check_circle</mat-icon>
          <h3>¡2FA Habilitado Exitosamente!</h3>
        </div>

        <div class="backup-codes-section">
          <div class="warning-box">
            <mat-icon>warning</mat-icon>
            <p><strong>¡Importante!</strong> Guarda estos códigos de respaldo en un lugar seguro. 
            Los necesitarás si pierdes acceso a tu aplicación de autenticación.</p>
          </div>

          <div class="backup-codes">
            <code *ngFor="let code of backupCodes" class="backup-code">{{ code }}</code>
          </div>

          <button mat-stroked-button (click)="copyBackupCodes()" class="copy-btn">
            <mat-icon>content_copy</mat-icon>
            Copiar todos los códigos
          </button>
        </div>
      </div>

      <!-- Error state -->
      <div *ngIf="errorMessage" class="error-container">
        <mat-icon>error</mat-icon>
        <p>{{ errorMessage }}</p>
      </div>
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="onCancel()" *ngIf="!isVerified">Cancelar</button>
      <button mat-raised-button color="primary" (click)="verify()" 
              *ngIf="setupData && !isVerified && !isLoading"
              [disabled]="!totpCode.valid || isVerifying">
        <mat-spinner diameter="20" *ngIf="isVerifying"></mat-spinner>
        <span *ngIf="!isVerifying">Verificar y Habilitar</span>
      </button>
      <button mat-raised-button color="primary" (click)="onClose()" *ngIf="isVerified">
        <mat-icon>done</mat-icon>
        Entendido
      </button>
    </mat-dialog-actions>
  `,
    styles: [`
    h2 {
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0;
      color: #1976d2;
    }

    h2 mat-icon {
      color: #1976d2;
    }

    mat-dialog-content {
      min-width: 400px;
      max-width: 500px;
    }

    .loading-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
      gap: 16px;
    }

    .setup-container {
      padding: 16px 0;
    }

    .instructions {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 16px;
      color: #666;
    }

    .instructions mat-icon {
      color: #1976d2;
    }

    .qr-container {
      display: flex;
      justify-content: center;
      margin: 20px 0;
    }

    .qr-code {
      width: 200px;
      height: 200px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      padding: 8px;
      background: white;
    }

    .secret-container {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin: 16px 0;
      flex-wrap: wrap;
    }

    .secret-label {
      width: 100%;
      text-align: center;
      color: #666;
      font-size: 13px;
      margin-bottom: 8px;
    }

    .secret-code {
      background: #f5f5f5;
      padding: 8px 16px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 14px;
      letter-spacing: 2px;
      word-break: break-all;
    }

    mat-divider {
      margin: 20px 0;
    }

    .verify-section {
      text-align: center;
    }

    .verify-section p {
      color: #666;
      margin-bottom: 16px;
    }

    .code-input {
      width: 200px;
    }

    .code-input input {
      text-align: center;
      font-size: 24px;
      letter-spacing: 8px;
      font-family: monospace;
    }

    .success-container {
      padding: 20px 0;
    }

    .success-header {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      margin-bottom: 24px;
    }

    .success-icon {
      font-size: 64px;
      width: 64px;
      height: 64px;
      color: #4caf50;
    }

    .success-header h3 {
      color: #4caf50;
      margin: 0;
    }

    .backup-codes-section {
      background: #fff3e0;
      border-radius: 8px;
      padding: 16px;
    }

    .warning-box {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
    }

    .warning-box mat-icon {
      color: #ff9800;
      flex-shrink: 0;
    }

    .warning-box p {
      margin: 0;
      font-size: 14px;
      color: #666;
    }

    .backup-codes {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
      margin-bottom: 16px;
    }

    .backup-code {
      background: white;
      padding: 8px 12px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 14px;
      text-align: center;
      border: 1px solid #e0e0e0;
    }

    .copy-btn {
      width: 100%;
    }

    .error-container {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #f44336;
      padding: 16px;
      background: #ffebee;
      border-radius: 8px;
    }

    mat-dialog-actions {
      padding: 16px 0 0 0;
    }
  `]
})
export class Setup2FADialogComponent implements OnInit {
    isLoading = true;
    isVerifying = false;
    isVerified = false;
    setupData: Setup2FAResponse | null = null;
    backupCodes: string[] = [];
    errorMessage = '';
    totpCode = new FormControl('', [Validators.required, Validators.pattern(/^\d{6}$/)]);

    constructor(
        private dialogRef: MatDialogRef<Setup2FADialogComponent>,
        private authService: AuthService,
        private snackBar: MatSnackBar
    ) { }

    ngOnInit(): void {
        this.loadSetupData();
    }

    loadSetupData(): void {
        this.isLoading = true;
        this.errorMessage = '';

        this.authService.setup2FA().subscribe({
            next: (response) => {
                this.setupData = response;
                this.isLoading = false;
            },
            error: (error) => {
                this.isLoading = false;
                this.errorMessage = error.error?.error || 'Error al configurar 2FA';
            }
        });
    }

    verify(): void {
        if (!this.totpCode.valid) return;

        this.isVerifying = true;
        this.errorMessage = '';

        this.authService.verify2FA(this.totpCode.value!).subscribe({
            next: (response) => {
                this.isVerifying = false;
                this.isVerified = true;
                this.backupCodes = response.backup_codes || [];
                this.snackBar.open('✅ 2FA habilitado exitosamente', 'Cerrar', { duration: 3000 });
            },
            error: (error) => {
                this.isVerifying = false;
                this.errorMessage = error.error?.error || 'Código inválido';
                this.totpCode.reset();
            }
        });
    }

    copySecret(): void {
        if (this.setupData?.secret) {
            navigator.clipboard.writeText(this.setupData.secret);
            this.snackBar.open('✅ Código secreto copiado', 'Cerrar', { duration: 2000 });
        }
    }

    copyBackupCodes(): void {
        const codes = this.backupCodes.join('\n');
        navigator.clipboard.writeText(codes);
        this.snackBar.open('✅ Códigos de respaldo copiados', 'Cerrar', { duration: 2000 });
    }

    onCancel(): void {
        this.dialogRef.close(false);
    }

    onClose(): void {
        this.dialogRef.close(true);
    }
}
