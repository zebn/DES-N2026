import { Component, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { AuthService, User } from '../../core/services/auth.service';
import { Setup2FADialogComponent } from '../../shared/components/setup-2fa-dialog/setup-2fa-dialog.component';
import { ConfirmDialogComponent } from '../../shared/components/confirm-dialog/confirm-dialog.component';
import { FormControl, Validators } from '@angular/forms';

@Component({
    selector: 'app-profile',
    template: `
    <div class="profile-container">
      <mat-card class="profile-card">
        <mat-card-header>
          <div mat-card-avatar class="profile-avatar">
            <mat-icon>person</mat-icon>
          </div>
          <mat-card-title>{{ user?.nombre }} {{ user?.apellidos }}</mat-card-title>
          <mat-card-subtitle>{{ user?.email }}</mat-card-subtitle>
        </mat-card-header>

        <mat-card-content>
          <!-- User Info Section -->
          <div class="info-section">
            <h3>
              <mat-icon>info</mat-icon>
              Información del Usuario
            </h3>
            <div class="info-grid">
              <div class="info-item">
                <label>Nivel de Clasificación</label>
                <mat-chip [class]="'level-' + user?.clearance_level?.toLowerCase()">
                  <mat-icon>shield</mat-icon>
                  {{ user?.clearance_level }}
                </mat-chip>
              </div>
              <div class="info-item">
                <label>Estado</label>
                <mat-chip [color]="user?.is_active ? 'primary' : 'warn'">
                  <mat-icon>{{ user?.is_active ? 'check_circle' : 'cancel' }}</mat-icon>
                  {{ user?.is_active ? 'Activo' : 'Inactivo' }}
                </mat-chip>
              </div>
              <div class="info-item" *ngIf="user?.is_admin">
                <label>Rol</label>
                <mat-chip color="accent">
                  <mat-icon>admin_panel_settings</mat-icon>
                  Administrador
                </mat-chip>
              </div>
            </div>
          </div>

          <mat-divider></mat-divider>

          <!-- 2FA Section -->
          <div class="security-section">
            <h3>
              <mat-icon>security</mat-icon>
              Autenticación de Dos Factores (2FA)
            </h3>
            
            <div class="twofa-status">
              <div class="status-indicator" [class.enabled]="user?.is_2fa_enabled">
                <mat-icon>{{ user?.is_2fa_enabled ? 'verified_user' : 'shield' }}</mat-icon>
                <div class="status-text">
                  <strong>{{ user?.is_2fa_enabled ? '2FA Habilitado' : '2FA Deshabilitado' }}</strong>
                  <p>{{ user?.is_2fa_enabled 
                    ? 'Tu cuenta está protegida con autenticación de dos factores.' 
                    : 'Añade una capa extra de seguridad a tu cuenta.' }}</p>
                </div>
              </div>

              <div class="twofa-actions">
                <button mat-raised-button color="primary" 
                        *ngIf="!user?.is_2fa_enabled" 
                        (click)="setup2FA()">
                  <mat-icon>add_moderator</mat-icon>
                  Habilitar 2FA
                </button>

                <button mat-raised-button color="warn" 
                        *ngIf="user?.is_2fa_enabled" 
                        (click)="showDisable2FADialog()">
                  <mat-icon>remove_moderator</mat-icon>
                  Deshabilitar 2FA
                </button>
              </div>
            </div>

            <!-- Disable 2FA Form (shown inline) -->
            <div class="disable-form" *ngIf="showDisableForm">
              <mat-form-field appearance="outline">
                <mat-label>Código TOTP actual</mat-label>
                <input matInput [formControl]="disableCode" maxlength="6" 
                       placeholder="000000" (keyup.enter)="disable2FA()">
                <mat-icon matPrefix>pin</mat-icon>
                <mat-error *ngIf="disableCode.hasError('required')">Código requerido</mat-error>
                <mat-error *ngIf="disableCode.hasError('pattern')">Debe ser 6 dígitos</mat-error>
              </mat-form-field>
              <div class="disable-actions">
                <button mat-button (click)="cancelDisable()">Cancelar</button>
                <button mat-raised-button color="warn" 
                        (click)="disable2FA()"
                        [disabled]="!disableCode.valid || isDisabling">
                  <mat-spinner diameter="20" *ngIf="isDisabling"></mat-spinner>
                  <span *ngIf="!isDisabling">Confirmar Deshabilitación</span>
                </button>
              </div>
            </div>
          </div>

          <mat-divider></mat-divider>

          <!-- Crypto Keys Section -->
          <div class="crypto-section">
            <h3>
              <mat-icon>vpn_key</mat-icon>
              Claves Criptográficas
            </h3>
            <div class="crypto-info">
              <div class="crypto-item">
                <mat-icon>lock</mat-icon>
                <div>
                  <strong>Clave Privada</strong>
                  <p>Cifrada con AES-256-CTR usando Argon2id</p>
                </div>
              </div>
              <div class="crypto-item">
                <mat-icon>public</mat-icon>
                <div>
                  <strong>Clave Pública</strong>
                  <p>RSA-4096 OAEP con SHA-256</p>
                </div>
              </div>
            </div>
          </div>
        </mat-card-content>

        <mat-card-actions>
          <button mat-button routerLink="/files">
            <mat-icon>arrow_back</mat-icon>
            Volver a Archivos
          </button>
        </mat-card-actions>
      </mat-card>
    </div>
  `,
    styles: [`
    .profile-container {
      padding: 20px;
      max-width: 800px;
      margin: 0 auto;
    }

    .profile-card {
      margin-bottom: 20px;
    }

    .profile-avatar {
      background: #1976d2;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .profile-avatar mat-icon {
      color: white;
      font-size: 24px;
    }

    mat-card-content {
      padding-top: 20px;
    }

    h3 {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #333;
      margin-bottom: 16px;
    }

    h3 mat-icon {
      color: #1976d2;
    }

    .info-section, .security-section, .crypto-section {
      padding: 20px 0;
    }

    .info-grid {
      display: flex;
      gap: 24px;
      flex-wrap: wrap;
    }

    .info-item {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .info-item label {
      color: #666;
      font-size: 12px;
      text-transform: uppercase;
    }

    mat-divider {
      margin: 0;
    }

    .twofa-status {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }

    .status-indicator {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 16px;
      background: #ffebee;
      border-radius: 8px;
      flex: 1;
      min-width: 280px;
    }

    .status-indicator.enabled {
      background: #e8f5e9;
    }

    .status-indicator mat-icon {
      font-size: 40px;
      width: 40px;
      height: 40px;
      color: #f44336;
    }

    .status-indicator.enabled mat-icon {
      color: #4caf50;
    }

    .status-text strong {
      display: block;
      margin-bottom: 4px;
    }

    .status-text p {
      margin: 0;
      color: #666;
      font-size: 13px;
    }

    .twofa-actions {
      display: flex;
      gap: 8px;
    }

    .disable-form {
      margin-top: 20px;
      padding: 16px;
      background: #fff3e0;
      border-radius: 8px;
    }

    .disable-actions {
      display: flex;
      gap: 8px;
      justify-content: flex-end;
      margin-top: 16px;
    }

    .crypto-info {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .crypto-item {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 12px;
      background: #f5f5f5;
      border-radius: 8px;
    }

    .crypto-item mat-icon {
      color: #1976d2;
    }

    .crypto-item strong {
      display: block;
    }

    .crypto-item p {
      margin: 4px 0 0 0;
      color: #666;
      font-size: 13px;
    }

    /* Classification level colors */
    .level-restricted { background-color: #4caf50 !important; color: white !important; }
    .level-confidential { background-color: #2196f3 !important; color: white !important; }
    .level-secret { background-color: #ff9800 !important; color: white !important; }
    .level-top_secret { background-color: #f44336 !important; color: white !important; }
  `]
})
export class ProfileComponent implements OnInit {
    user: User | null = null;
    showDisableForm = false;
    isDisabling = false;
    disableCode = new FormControl('', [Validators.required, Validators.pattern(/^\d{6}$/)]);

    constructor(
        private authService: AuthService,
        private dialog: MatDialog,
        private snackBar: MatSnackBar
    ) { }

    ngOnInit(): void {
        this.authService.currentUser$.subscribe(user => {
            this.user = user;
        });

        // Reload profile to get latest 2FA status
        this.authService.loadProfile().subscribe();
    }

    setup2FA(): void {
        const dialogRef = this.dialog.open(Setup2FADialogComponent, {
            width: '500px',
            disableClose: true
        });

        dialogRef.afterClosed().subscribe(result => {
            if (result) {
                // 2FA was enabled, refresh user data
                this.authService.loadProfile().subscribe();
            }
        });
    }

    showDisable2FADialog(): void {
        const dialogRef = this.dialog.open(ConfirmDialogComponent, {
            width: '400px',
            data: {
                title: 'Deshabilitar 2FA',
                message: '¿Estás seguro de que deseas deshabilitar la autenticación de dos factores? Tu cuenta será menos segura.',
                confirmText: 'Continuar',
                cancelText: 'Cancelar',
                confirmColor: 'warn',
                icon: 'warning'
            }
        });

        dialogRef.afterClosed().subscribe(confirmed => {
            if (confirmed) {
                this.showDisableForm = true;
            }
        });
    }

    cancelDisable(): void {
        this.showDisableForm = false;
        this.disableCode.reset();
    }

    disable2FA(): void {
        if (!this.disableCode.valid) return;

        this.isDisabling = true;

        this.authService.disable2FA(this.disableCode.value!).subscribe({
            next: () => {
                this.isDisabling = false;
                this.showDisableForm = false;
                this.disableCode.reset();
                this.snackBar.open('✅ 2FA deshabilitado', 'Cerrar', { duration: 3000 });
            },
            error: (error) => {
                this.isDisabling = false;
                const message = error.error?.error || 'Código inválido';
                this.snackBar.open(`❌ ${message}`, 'Cerrar', { duration: 3000 });
                this.disableCode.reset();
            }
        });
    }
}
