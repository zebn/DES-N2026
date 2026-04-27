import { Component, Inject } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';
import { BackupService, VaultEnvelope, ImportResult } from '../../../core/services/backup.service';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-import-backup',
  template: `
    <mat-card class="backup-card">
      <mat-card-header>
        <mat-icon mat-card-avatar class="section-icon import-icon">restore</mat-icon>
        <mat-card-title>Restaurar copia de seguridad</mat-card-title>
        <mat-card-subtitle>
          Importa un archivo .vault generado previamente. Los secretos se descifran
          con tu contraseña de backup y se añaden a tu bóveda.
        </mat-card-subtitle>
      </mat-card-header>

      <mat-card-content>
        <form [formGroup]="importForm" (ngSubmit)="onImport()">

          <!-- Selector de archivo .vault -->
          <div class="file-drop-zone"
               [class.has-file]="vaultFile"
               (click)="fileInput.click()"
               (dragover)="$event.preventDefault()"
               (drop)="onFileDrop($event)">
            <mat-icon class="drop-icon">{{ vaultFile ? 'check_circle' : 'cloud_upload' }}</mat-icon>
            <p *ngIf="!vaultFile">Arrastra aquí tu archivo .vault o haz clic para seleccionar</p>
            <p *ngIf="vaultFile" class="file-name">{{ vaultFile.name }}</p>
            <span class="file-hint">Solo se aceptan archivos .vault</span>
          </div>
          <input #fileInput type="file" accept=".vault,application/json"
                 style="display:none" (change)="onFileSelected($event)">
          <mat-error *ngIf="fileError" class="file-error">{{ fileError }}</mat-error>

          <!-- Contraseña de backup -->
          <mat-form-field appearance="outline" class="full-width">
            <mat-label>Contraseña de backup</mat-label>
            <input matInput
                   [type]="showPassword ? 'text' : 'password'"
                   formControlName="backup_password"
                   placeholder="Contraseña usada al exportar">
            <button mat-icon-button matSuffix type="button"
                    (click)="showPassword = !showPassword">
              <mat-icon>{{ showPassword ? 'visibility_off' : 'visibility' }}</mat-icon>
            </button>
            <mat-error *ngIf="importForm.get('backup_password')?.hasError('required')">
              La contraseña es obligatoria
            </mat-error>
          </mat-form-field>

          <!-- 2FA (si está activo) -->
          <mat-form-field appearance="outline" class="full-width" *ngIf="has2FA">
            <mat-label>Código 2FA</mat-label>
            <input matInput formControlName="totp_code"
                   placeholder="123456" maxlength="6" autocomplete="one-time-code">
            <mat-icon matSuffix>security</mat-icon>
            <mat-error *ngIf="importForm.get('totp_code')?.hasError('required')">
              El código 2FA es obligatorio
            </mat-error>
          </mat-form-field>

          <!-- Modo merge / replace -->
          <div class="merge-group">
            <p class="merge-label">Modo de importación</p>
            <mat-radio-group formControlName="merge" class="merge-radio">
              <mat-radio-button [value]="true">
                <div class="radio-option">
                  <span class="radio-title">Combinar <span class="badge badge-safe">recomendado</span></span>
                  <span class="radio-desc">Los secretos existentes no se modifican; solo se añaden los nuevos</span>
                </div>
              </mat-radio-button>
              <mat-radio-button [value]="false">
                <div class="radio-option">
                  <span class="radio-title">Reemplazar <span class="badge badge-warn">sobrescribe</span></span>
                  <span class="radio-desc">Los secretos del backup sobreescriben los actuales si coinciden por ID</span>
                </div>
              </mat-radio-button>
            </mat-radio-group>
          </div>

          <!-- Info vault seleccionado -->
          <div class="vault-info" *ngIf="vaultMeta">
            <mat-icon>info_outline</mat-icon>
            <span>
              Vault creado el <strong>{{ vaultMeta.created_at | date:'dd/MM/yyyy HH:mm' }}</strong>
              <ng-container *ngIf="vaultMeta.secret_count != null">
                &nbsp;·&nbsp;<strong>{{ vaultMeta.secret_count }}</strong> secretos
              </ng-container>
              <ng-container *ngIf="vaultMeta.scope === 'system'">
                &nbsp;·&nbsp;<span class="badge badge-admin">SISTEMA</span>
              </ng-container>
            </span>
          </div>

          <!-- Resultado de la importación -->
          <div class="import-result" *ngIf="importResult">
            <mat-icon class="result-icon">done_all</mat-icon>
            <div>
              <p>
                <strong>{{ importResult.imported }}</strong> importados &nbsp;·&nbsp;
                <strong>{{ importResult.skipped }}</strong> omitidos &nbsp;·&nbsp;
                <strong>{{ importResult.overwritten }}</strong> sobreescritos
              </p>
              <ul *ngIf="importResult.errors?.length" class="error-list">
                <li *ngFor="let e of importResult.errors">{{ e }}</li>
              </ul>
            </div>
          </div>

          <mat-card-actions>
            <button mat-raised-button color="accent" type="submit"
                    [disabled]="importForm.invalid || !vaultFile || isLoading">
              <mat-spinner diameter="18" *ngIf="isLoading" class="btn-spinner"></mat-spinner>
              <mat-icon *ngIf="!isLoading">restore</mat-icon>
              {{ isLoading ? 'Importando…' : 'Restaurar backup' }}
            </button>
          </mat-card-actions>
        </form>
      </mat-card-content>
    </mat-card>
  `,
  styles: [`
    .full-width   { width: 100%; margin-bottom: 12px; }
    .file-error   { font-size: 12px; color: #f44336; display: block; margin: -8px 0 12px; }

    .file-drop-zone {
      border: 2px dashed rgba(0,0,0,.25); border-radius: 8px;
      padding: 24px; text-align: center; cursor: pointer;
      margin-bottom: 16px; transition: border-color .2s;
    }
    .file-drop-zone:hover, .file-drop-zone.has-file {
      border-color: var(--mdc-theme-primary, #3f51b5);
    }
    .drop-icon { font-size: 40px; height: 40px; width: 40px; color: rgba(0,0,0,.35); }
    .file-drop-zone.has-file .drop-icon { color: #4caf50; }
    .file-name  { font-weight: 500; }
    .file-hint  { font-size: 12px; color: rgba(0,0,0,.45); }

    .merge-group  { margin: 8px 0 16px; }
    .merge-label  { font-size: 14px; color: rgba(0,0,0,.6); margin: 0 0 8px; }
    .merge-radio  { display: flex; flex-direction: column; gap: 8px; }
    .radio-option { display: flex; flex-direction: column; padding-left: 4px; }
    .radio-title  { font-size: 14px; font-weight: 500; }
    .radio-desc   { font-size: 12px; color: rgba(0,0,0,.55); }

    .badge {
      display: inline-block; font-size: 10px; padding: 1px 6px;
      border-radius: 10px; font-weight: 600; vertical-align: middle;
    }
    .badge-safe  { background: #e8f5e9; color: #388e3c; }
    .badge-warn  { background: #fff3e0; color: #e65100; }
    .badge-admin { background: #e3f2fd; color: #1565c0; }

    .vault-info {
      display: flex; align-items: center; gap: 8px;
      background: rgba(0,0,0,.04); border-radius: 4px;
      padding: 8px 12px; font-size: 13px; margin-bottom: 12px;
    }

    .import-result {
      display: flex; align-items: flex-start; gap: 8px;
      background: #e8f5e9; border-radius: 4px;
      padding: 10px 12px; font-size: 13px; margin-bottom: 12px;
    }
    .result-icon { color: #388e3c; }
    .error-list  { margin: 4px 0 0; padding-left: 18px; color: #c62828; }

    .btn-spinner { display: inline-block; margin-right: 8px; }
    mat-card-actions { padding: 0 0 4px; }
    .import-icon { color: #ff9800 !important; }
  `]
})
export class ImportBackupComponent {
  importForm:   FormGroup;
  isLoading    = false;
  showPassword = false;
  has2FA       = false;

  vaultFile: File | null = null;
  vaultMeta: VaultEnvelope | null = null;
  fileError: string | null = null;
  importResult: ImportResult | null = null;

  constructor(
    private fb:    FormBuilder,
    @Inject(BackupService) private backup: BackupService,
    @Inject(AuthService)   private auth:   AuthService,
    private snack: MatSnackBar,
  ) {
    const user = this.auth.getCurrentUser();
    this.has2FA = user?.is_2fa_enabled ?? false;

    this.importForm = this.fb.group({
      backup_password: ['', Validators.required],
      totp_code:       ['', this.has2FA ? Validators.required : []],
      merge:           [true],
    });
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files?.length) this.readVaultFile(input.files[0]);
  }

  onFileDrop(event: DragEvent): void {
    event.preventDefault();
    const file = event.dataTransfer?.files[0];
    if (file) this.readVaultFile(file);
  }

  private readVaultFile(file: File): void {
    this.fileError  = null;
    this.vaultMeta  = null;
    this.importResult = null;

    if (!file.name.endsWith('.vault') && file.type !== 'application/json') {
      this.fileError = 'El archivo debe tener extensión .vault';
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(reader.result as string) as VaultEnvelope;
        if (!parsed.kdf_params || !parsed.encrypted_payload) {
          this.fileError = 'El archivo no es un vault válido';
          return;
        }
        this.vaultFile = file;
        this.vaultMeta = parsed;
      } catch {
        this.fileError = 'El archivo no tiene formato JSON válido';
      }
    };
    reader.readAsText(file);
  }

  onImport(): void {
    if (this.importForm.invalid || !this.vaultFile || !this.vaultMeta) return;
    this.importResult = null;
    this.isLoading    = true;

    const { backup_password, totp_code, merge } = this.importForm.value;
    const payload: any = { vault: this.vaultMeta, backup_password, merge };
    if (this.has2FA && totp_code) payload.totp_code = totp_code;

    this.backup.importBackup(payload).subscribe({
      next: (result: ImportResult) => {
        this.importResult = result;
        this.snack.open(
          `Importación completada: ${result.imported} nuevos, ${result.skipped} omitidos`,
          'OK',
          { duration: 6000 }
        );
        this.isLoading = false;
      },
      error: (err: any) => {
        const msg = err.error?.error ?? 'Error al importar el backup';
        this.snack.open(msg, 'Cerrar', { duration: 8000, panelClass: 'snack-error' });
        this.isLoading = false;
      }
    });
  }
}
