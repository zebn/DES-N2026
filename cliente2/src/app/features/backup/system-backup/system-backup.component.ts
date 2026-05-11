import { Component, Inject } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { BackupService } from '../../../core/services/backup.service';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-system-backup',
  template: `
    <mat-card class="backup-card">
      <mat-card-header>
        <mat-icon mat-card-avatar class="section-icon admin-icon">admin_panel_settings</mat-icon>
        <mat-card-title>Backup del sistema <span class="badge-admin">ADMIN</span></mat-card-title>
        <mat-card-subtitle>
          Exporta los secretos de <strong>todos</strong> los usuarios en un único archivo .vault cifrado.
          Solo disponible para administradores.
        </mat-card-subtitle>
      </mat-card-header>

      <mat-card-content>
        <!-- Warning banner -->
        <div class="warn-banner">
          <mat-icon>warning_amber</mat-icon>
          <span>Este backup contiene datos sensibles de todos los usuarios.
            Guarda el archivo .vault en un lugar seguro y protegido.</span>
        </div>

        <form [formGroup]="systemForm" (ngSubmit)="onExport()">

          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Contraseña de backup del sistema</mat-label>
            <input matInput
                   [type]="showPassword ? 'text' : 'password'"
                   formControlName="backup_password"
                   placeholder="Mínimo 8 caracteres">
            <button mat-icon-button matSuffix type="button"
                    (click)="showPassword = !showPassword">
              <mat-icon>{{ showPassword ? 'visibility_off' : 'visibility' }}</mat-icon>
            </button>
            <mat-error *ngIf="systemForm.get('backup_password')?.hasError('required')">
              La contraseña es obligatoria
            </mat-error>
            <mat-error *ngIf="systemForm.get('backup_password')?.hasError('minlength')">
              Mínimo 8 caracteres
            </mat-error>
          </mat-form-field>

          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Confirmar contraseña</mat-label>
            <input matInput
                   [type]="showPassword ? 'text' : 'password'"
                   formControlName="confirm_password">
            <mat-error *ngIf="systemForm.hasError('passwordMismatch')">
              Las contraseñas no coinciden
            </mat-error>
          </mat-form-field>

          <mat-form-field appearance="outline" class="full-width" *ngIf="has2FA">
            <mat-label>Código 2FA</mat-label>
            <input matInput formControlName="totp_code"
                   placeholder="123456" maxlength="6" autocomplete="one-time-code">
            <mat-icon matSuffix>security</mat-icon>
            <mat-error *ngIf="systemForm.get('totp_code')?.hasError('required')">
              El código 2FA es obligatorio
            </mat-error>
          </mat-form-field>

          <mat-card-actions>
            <button mat-raised-button color="warn" type="submit"
                    [disabled]="systemForm.invalid || isLoading">
              <mat-spinner diameter="18" *ngIf="isLoading" class="btn-spinner"></mat-spinner>
              <mat-icon *ngIf="!isLoading">save_alt</mat-icon>
              {{ isLoading ? 'Generando backup…' : 'Descargar backup del sistema' }}
            </button>
          </mat-card-actions>
        </form>
      </mat-card-content>
    </mat-card>
  `,
  styles: [`
    .full-width  { width: 100%; margin-bottom: 12px; }
    .admin-icon  { color: #f44336 !important; }
    .badge-admin {
      font-size: 11px; background: #ffebee; color: #c62828;
      padding: 2px 8px; border-radius: 10px; font-weight: 600;
      vertical-align: middle; margin-left: 8px;
    }
    .warn-banner {
      display: flex; align-items: flex-start; gap: 10px;
      background: #fff8e1; border-left: 4px solid #ffc107;
      border-radius: 4px; padding: 12px 14px;
      font-size: 13px; margin-bottom: 20px;
    }
    .warn-banner mat-icon { color: #f57c00; flex-shrink: 0; }
    .btn-spinner { display: inline-block; margin-right: 8px; }
    mat-card-actions { padding: 0 0 4px; }
  `]
})
export class SystemBackupComponent {
  systemForm:  FormGroup;
  isLoading   = false;
  showPassword = false;
  has2FA      = false;

  constructor(
    private fb:     FormBuilder,
    @Inject(BackupService) private backup: BackupService,
    @Inject(AuthService)   private auth:   AuthService,
    private snack:  MatSnackBar,
  ) {
    const user = this.auth.getCurrentUser();
    this.has2FA = user?.is_2fa_enabled ?? false;

    this.systemForm = this.fb.group({
      backup_password:  ['', [Validators.required, Validators.minLength(8)]],
      confirm_password: ['', Validators.required],
      totp_code:        ['', this.has2FA ? Validators.required : []],
    }, { validators: this.passwordMatchValidator });
  }

  private passwordMatchValidator(g: FormGroup) {
    return g.get('backup_password')?.value === g.get('confirm_password')?.value
      ? null
      : { passwordMismatch: true };
  }

  onExport(): void {
    if (this.systemForm.invalid) return;
    this.isLoading = true;

    const { backup_password, totp_code } = this.systemForm.value;
    const payload: any = { backup_password };
    if (this.has2FA && totp_code) payload.totp_code = totp_code;

    this.backup.systemBackup(payload).subscribe({
      next: (blob: Blob) => {
        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        this.backup.downloadBlob(blob, `system_backup_${ts}.vault`);
        this.snack.open('Backup del sistema exportado correctamente', 'OK', { duration: 4000 });
        this.systemForm.reset();
        this.isLoading = false;
      },
      error: (err: any) => {
        const msg = err.error?.error ?? 'Error al generar el backup del sistema';
        this.snack.open(msg, 'Cerrar', { duration: 6000, panelClass: 'snack-error' });
        this.isLoading = false;
      }
    });
  }
}
