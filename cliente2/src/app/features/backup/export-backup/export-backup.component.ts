import { Component, Inject } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { BackupService } from '../../../core/services/backup.service';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-export-backup',
  template: `
    <mat-card class="backup-card">
      <mat-card-header>
        <mat-icon mat-card-avatar class="section-icon">upload_file</mat-icon>
        <mat-card-title>Exportar copia de seguridad</mat-card-title>
        <mat-card-subtitle>
          Descarga un archivo .vault cifrado con todos tus secretos.
          El servidor solo exporta datos ya cifrados (Zero Knowledge).
        </mat-card-subtitle>
      </mat-card-header>

      <mat-card-content>
        <form [formGroup]="exportForm" (ngSubmit)="onExport()">

          <!-- Contraseña de backup -->
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Contraseña de backup</mat-label>
            <input matInput
                   [type]="showPassword ? 'text' : 'password'"
                   formControlName="backup_password"
                   placeholder="Mínimo 8 caracteres">
            <button mat-icon-button matSuffix type="button"
                    (click)="showPassword = !showPassword">
              <mat-icon>{{ showPassword ? 'visibility_off' : 'visibility' }}</mat-icon>
            </button>
            <mat-hint>Necesitarás esta contraseña para restaurar el backup</mat-hint>
            <mat-error *ngIf="exportForm.get('backup_password')?.hasError('required')">
              La contraseña es obligatoria
            </mat-error>
            <mat-error *ngIf="exportForm.get('backup_password')?.hasError('minlength')">
              Mínimo 8 caracteres
            </mat-error>
          </mat-form-field>

          <!-- Confirmar contraseña -->
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Confirmar contraseña</mat-label>
            <input matInput
                   [type]="showPassword ? 'text' : 'password'"
                   formControlName="confirm_password"
                   placeholder="Repite la contraseña">
            <mat-error *ngIf="exportForm.hasError('passwordMismatch')">
              Las contraseñas no coinciden
            </mat-error>
          </mat-form-field>

          <!-- 2FA (si está activo) -->
          <mat-form-field appearance="outline" class="full-width" *ngIf="has2FA">
            <mat-label>Código 2FA</mat-label>
            <input matInput formControlName="totp_code"
                   placeholder="123456" maxlength="6" autocomplete="one-time-code">
            <mat-icon matSuffix>security</mat-icon>
            <mat-hint>Tu cuenta tiene 2FA activo</mat-hint>
            <mat-error *ngIf="exportForm.get('totp_code')?.hasError('required')">
              El código 2FA es obligatorio
            </mat-error>
          </mat-form-field>

          <!-- Incluir historial de versiones -->
          <div class="option-row">
            <mat-checkbox formControlName="include_versions">
              Incluir historial de versiones de cada secreto
            </mat-checkbox>
            <mat-icon class="info-icon"
                      matTooltip="Aumenta el tamaño del archivo pero permite restaurar versiones anteriores">
              info_outline
            </mat-icon>
          </div>

          <!-- Info cifrado -->
          <div class="crypto-info">
            <mat-icon class="lock-small">lock</mat-icon>
            <span>El archivo se cifrará con <strong>Argon2id + AES-256-CTR</strong>.
              El servidor nunca ve tus secretos en claro.</span>
          </div>

          <mat-card-actions>
            <button mat-raised-button color="primary" type="submit"
                    [disabled]="exportForm.invalid || isLoading">
              <mat-spinner diameter="18" *ngIf="isLoading" class="btn-spinner"></mat-spinner>
              <mat-icon *ngIf="!isLoading">download</mat-icon>
              {{ isLoading ? 'Exportando…' : 'Descargar .vault' }}
            </button>
          </mat-card-actions>
        </form>
      </mat-card-content>
    </mat-card>
  `,
  styles: [`
    .full-width { width: 100%; margin-bottom: 12px; }
    .option-row { display: flex; align-items: center; gap: 8px; margin: 8px 0 16px; }
    .info-icon  { font-size: 18px; color: rgba(0,0,0,.45); cursor: default; }
    .crypto-info {
      display: flex; align-items: flex-start; gap: 8px;
      background: rgba(0,0,0,.04); border-radius: 4px;
      padding: 10px 12px; font-size: 13px; color: rgba(0,0,0,.65);
      margin-bottom: 16px;
    }
    .lock-small { font-size: 16px; color: #4caf50; flex-shrink: 0; margin-top: 1px; }
    .btn-spinner { display: inline-block; margin-right: 8px; }
    mat-card-actions { padding: 0 0 4px; }
  `]
})
export class ExportBackupComponent {
  exportForm: FormGroup;
  isLoading   = false;
  showPassword = false;
  has2FA      = false;

  constructor(
    private fb:    FormBuilder,
    @Inject(BackupService) private backup: BackupService,
    @Inject(AuthService)   private auth:   AuthService,
    private snack: MatSnackBar,
  ) {
    const user = this.auth.getCurrentUser();
    this.has2FA = user?.is_2fa_enabled ?? false;

    this.exportForm = this.fb.group({
      backup_password:  ['', [Validators.required, Validators.minLength(8)]],
      confirm_password: ['', Validators.required],
      totp_code:        ['', this.has2FA ? Validators.required : []],
      include_versions: [false],
    }, { validators: this.passwordMatchValidator });
  }

  private passwordMatchValidator(g: FormGroup) {
    return g.get('backup_password')?.value === g.get('confirm_password')?.value
      ? null
      : { passwordMismatch: true };
  }

  onExport(): void {
    if (this.exportForm.invalid) return;
    this.isLoading = true;

    const { backup_password, totp_code, include_versions } = this.exportForm.value;
    const payload: any = { backup_password, include_versions };
    if (this.has2FA && totp_code) payload.totp_code = totp_code;

    this.backup.exportBackup(payload).subscribe({
      next: (blob: Blob) => {
        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        this.backup.downloadBlob(blob, `backup_${ts}.vault`);
        this.snack.open('Backup exportado correctamente', 'OK', { duration: 4000 });
        this.exportForm.reset({ include_versions: false });
        this.isLoading = false;
      },
      error: (err: any) => {
        const msg = err.error?.error ?? 'Error al exportar el backup';
        this.snack.open(msg, 'Cerrar', { duration: 6000, panelClass: 'snack-error' });
        this.isLoading = false;
      }
    });
  }
}
