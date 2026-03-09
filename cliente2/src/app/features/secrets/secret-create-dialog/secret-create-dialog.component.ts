import { Component, Inject } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import {
  SecretsService, Folder, SecretType,
  SECRET_TYPE_LABELS
} from '../../../core/services/secrets.service';
import { CryptoService } from '../../../core/services/crypto.service';

@Component({
  selector: 'app-secret-create-dialog',
  template: `
    <h2 mat-dialog-title>
      <mat-icon>add_circle</mat-icon>
      Nuevo Secreto
    </h2>

    <mat-dialog-content>
      <form [formGroup]="form" class="secret-form">
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Título</mat-label>
          <input matInput formControlName="title" placeholder="Ej: Contraseña de producción">
          <mat-error *ngIf="form.get('title')?.hasError('required')">
            El título es obligatorio
          </mat-error>
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Tipo de secreto</mat-label>
          <mat-select formControlName="secret_type">
            <mat-option *ngFor="let type of secretTypes" [value]="type.value">
              {{ type.label }}
            </mat-option>
          </mat-select>
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Contenido secreto</mat-label>
          <textarea matInput formControlName="plaintext"
                    rows="4"
                    placeholder="Introduce el contenido que deseas cifrar..."></textarea>
          <mat-hint>Este contenido se cifrará localmente antes de enviarse al servidor</mat-hint>
          <mat-error *ngIf="form.get('plaintext')?.hasError('required')">
            El contenido es obligatorio
          </mat-error>
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Carpeta (opcional)</mat-label>
          <mat-select formControlName="folder_id">
            <mat-option value="">Sin carpeta</mat-option>
            <mat-option *ngFor="let folder of data.folders" [value]="folder.id">
              {{ folder.name }}
            </mat-option>
          </mat-select>
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Etiquetas (opcional, separadas por coma)</mat-label>
          <input matInput formControlName="tags" placeholder="Ej: producción, aws, crítico">
        </mat-form-field>

        <div class="form-row">
          <mat-form-field appearance="outline">
            <mat-label>Caduca (opcional)</mat-label>
            <input matInput type="date" formControlName="expires_at">
          </mat-form-field>

          <mat-form-field appearance="outline">
            <mat-label>Rotación (días)</mat-label>
            <input matInput type="number" formControlName="rotation_period_days" min="1">
          </mat-form-field>
        </div>
      </form>

      <!-- Encryption info -->
      <div class="encryption-info">
        <mat-icon>shield</mat-icon>
        <span>El contenido se cifra con AES-256-CTR + RSA-4096 en tu navegador. El servidor nunca ve el texto plano.</span>
      </div>

      <!-- Progress -->
      <mat-progress-bar *ngIf="isSaving" mode="indeterminate"></mat-progress-bar>
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close [disabled]="isSaving">Cancelar</button>
      <button mat-raised-button color="primary"
              (click)="save()"
              [disabled]="form.invalid || isSaving">
        <mat-icon>lock</mat-icon>
        Cifrar y Guardar
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .secret-form {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .full-width {
      width: 100%;
    }

    .form-row {
      display: flex;
      gap: 12px;
    }

    .form-row mat-form-field {
      flex: 1;
    }

    .encryption-info {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px;
      background: #e8f5e9;
      border-radius: 8px;
      font-size: 13px;
      color: #2e7d32;
      margin-top: 8px;
    }

    .encryption-info mat-icon {
      color: #2e7d32;
      flex-shrink: 0;
    }
  `]
})
export class SecretCreateDialogComponent {
  form: FormGroup;
  isSaving = false;

  secretTypes = [
    { value: 'PASSWORD', label: 'Contraseña' },
    { value: 'API_KEY', label: 'Clave API' },
    { value: 'CERTIFICATE', label: 'Certificado' },
    { value: 'SSH_KEY', label: 'Clave SSH' },
    { value: 'NOTE', label: 'Nota segura' },
    { value: 'DATABASE', label: 'Base de datos' },
    { value: 'ENV_VARIABLE', label: 'Variable de entorno' },
    { value: 'IDENTITY', label: 'Identidad' },
  ];

  constructor(
    private fb: FormBuilder,
    private dialogRef: MatDialogRef<SecretCreateDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { folders: Folder[] },
    private secretsService: SecretsService,
    private cryptoService: CryptoService,
    private snackBar: MatSnackBar,
  ) {
    this.form = this.fb.group({
      title: ['', Validators.required],
      secret_type: ['PASSWORD', Validators.required],
      plaintext: ['', Validators.required],
      folder_id: [''],
      tags: [''],
      expires_at: [''],
      rotation_period_days: [null],
    });
  }

  async save(): Promise<void> {
    if (this.form.invalid || this.isSaving) return;
    this.isSaving = true;

    try {
      const { title, secret_type, plaintext, folder_id, tags, expires_at, rotation_period_days } = this.form.value;

      // Build the secret JSON to encrypt
      const secretPayload = JSON.stringify({
        content: plaintext,
        type: secret_type,
        created: new Date().toISOString(),
      });

      const payloadBytes = new TextEncoder().encode(secretPayload);

      // Encrypt using the file encryption pipeline (AES-256-CTR + RSA-4096)
      const encrypted = await this.cryptoService.encryptFileForUpload(
        new Uint8Array(payloadBytes)
      );

      // Prepare tags as JSON
      let tagsJson: string | undefined;
      if (tags && tags.trim()) {
        const tagArray = tags.split(',').map((t: string) => t.trim()).filter((t: string) => t);
        tagsJson = JSON.stringify(tagArray);
      }

      // Build API payload
      const payload: any = {
        title,
        secret_type,
        encrypted_data: encrypted.encrypted_content,
        encrypted_aes_key: encrypted.encrypted_aes_key,
        content_hash: encrypted.file_hash,
        digital_signature: encrypted.digital_signature,
      };

      if (folder_id) payload.folder_id = folder_id;
      if (tagsJson) payload.tags = tagsJson;
      if (expires_at) payload.expires_at = new Date(expires_at).toISOString();
      if (rotation_period_days) payload.rotation_period_days = rotation_period_days;

      // Send to API
      this.secretsService.createSecret(payload).subscribe({
        next: () => {
          this.isSaving = false;
          this.dialogRef.close(true);
        },
        error: (err) => {
          this.isSaving = false;
          this.snackBar.open(
            err.error?.error || 'Error creando secreto',
            'Cerrar',
            { duration: 5000 }
          );
        }
      });

    } catch (err: any) {
      this.isSaving = false;
      this.snackBar.open(
        'Error cifrando secreto: ' + (err.message || err),
        'Cerrar',
        { duration: 5000 }
      );
    }
  }
}
