import { Component, Inject, OnInit } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import {
  SecretsService, Secret, Folder, SecretVersion,
  SECRET_TYPE_LABELS, SECRET_TYPE_ICONS, SecretType
} from '../../../core/services/secrets.service';
import { CryptoService } from '../../../core/services/crypto.service';

@Component({
  selector: 'app-secret-detail-dialog',
  template: `
    <h2 mat-dialog-title>
      <mat-icon [class]="'type-icon type-' + secret.secret_type.toLowerCase()">
        {{ getTypeIcon(secret.secret_type) }}
      </mat-icon>
      {{ secret.title }}
    </h2>

    <mat-dialog-content>
      <!-- Metadata section -->
      <div class="detail-section">
        <h3>Información</h3>
        <div class="meta-grid">
          <div class="meta-field">
            <span class="label">Tipo</span>
            <span class="value">{{ getTypeLabel(secret.secret_type) }}</span>
          </div>
          <div class="meta-field">
            <span class="label">Versión</span>
            <span class="value">v{{ secret.version }}</span>
          </div>
          <div class="meta-field">
            <span class="label">Creado</span>
            <span class="value">{{ formatDateTime(secret.created_at) }}</span>
          </div>
          <div class="meta-field">
            <span class="label">Actualizado</span>
            <span class="value">{{ formatDateTime(secret.updated_at) }}</span>
          </div>
          <div class="meta-field" *ngIf="secret.expires_at">
            <span class="label">Caduca</span>
            <span class="value" [class.expired]="isExpired()">
              {{ formatDateTime(secret.expires_at) }}
              <mat-icon *ngIf="isExpired()" class="warn-icon">warning</mat-icon>
            </span>
          </div>
          <div class="meta-field" *ngIf="secret.rotation_period_days">
            <span class="label">Rotación</span>
            <span class="value">Cada {{ secret.rotation_period_days }} días</span>
          </div>
        </div>
      </div>

      <!-- Decrypt section -->
      <div class="detail-section">
        <h3>Contenido Cifrado</h3>

        <div *ngIf="!decryptedContent" class="decrypt-prompt">
          <mat-icon>enhanced_encryption</mat-icon>
          <p>El contenido está cifrado E2E. Solo tú puedes verlo.</p>
          <button mat-raised-button color="primary"
                  (click)="decrypt()"
                  [disabled]="isDecrypting">
            <mat-icon>lock_open</mat-icon>
            {{ isDecrypting ? 'Descifrando...' : 'Descifrar' }}
          </button>
          <mat-progress-bar *ngIf="isDecrypting" mode="indeterminate" class="decrypt-progress"></mat-progress-bar>
        </div>

        <div *ngIf="decryptedContent" class="decrypted-content">
          <div class="content-header">
            <mat-icon color="primary">lock_open</mat-icon>
            <span>Contenido descifrado</span>
            <button mat-icon-button (click)="copyToClipboard()" matTooltip="Copiar">
              <mat-icon>content_copy</mat-icon>
            </button>
            <button mat-icon-button (click)="toggleVisibility()" [matTooltip]="showContent ? 'Ocultar' : 'Mostrar'">
              <mat-icon>{{ showContent ? 'visibility_off' : 'visibility' }}</mat-icon>
            </button>
          </div>
          <pre class="content-box" [class.hidden-content]="!showContent">{{ showContent ? decryptedContent : maskedContent }}</pre>
        </div>
      </div>

      <!-- Version history -->
      <div class="detail-section" *ngIf="versions.length > 0">
        <h3>
          <mat-icon>history</mat-icon>
          Historial de Versiones ({{ versions.length }})
        </h3>
        <div class="versions-list">
          <div *ngFor="let v of versions" class="version-item">
            <div class="version-number">v{{ v.version_number }}</div>
            <div class="version-info">
              <span class="version-date">{{ formatDateTime(v.created_at) }}</span>
              <span class="version-reason" *ngIf="v.change_reason">{{ v.change_reason }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Integrity verification -->
      <div class="detail-section">
        <h3>Integridad</h3>
        <div class="integrity-status" [class]="integrityClass">
          <mat-icon>{{ integrityIcon }}</mat-icon>
          <span>{{ integrityMessage }}</span>
        </div>
        <div class="hash-display">
          <span class="label">SHA-256:</span>
          <code>{{ secret.content_hash }}</code>
        </div>
      </div>
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="dialogRef.close()">Cerrar</button>
      <button mat-button color="warn" (click)="confirmDelete()">
        <mat-icon>delete</mat-icon>
        Eliminar
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .type-icon {
      font-size: 28px;
      width: 28px;
      height: 28px;
    }

    .type-icon.type-password { color: #3f51b5; }
    .type-icon.type-api_key { color: #e65100; }
    .type-icon.type-certificate { color: #2e7d32; }
    .type-icon.type-ssh_key { color: #c62828; }
    .type-icon.type-note { color: #f9a825; }
    .type-icon.type-database { color: #1565c0; }
    .type-icon.type-env_variable { color: #7b1fa2; }
    .type-icon.type-identity { color: #4e342e; }

    .detail-section {
      margin-bottom: 20px;
    }

    .detail-section h3 {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 15px;
      color: #555;
      border-bottom: 1px solid #eee;
      padding-bottom: 6px;
      margin-bottom: 12px;
    }

    .meta-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }

    .meta-field {
      display: flex;
      flex-direction: column;
    }

    .meta-field .label {
      font-size: 11px;
      color: #999;
      text-transform: uppercase;
    }

    .meta-field .value {
      font-size: 14px;
      display: flex;
      align-items: center;
      gap: 4px;
    }

    .meta-field .value.expired {
      color: #f44336;
      font-weight: 500;
    }

    .warn-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
      color: #f44336;
    }

    .decrypt-prompt {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 24px;
      background: #f5f5f5;
      border-radius: 8px;
      text-align: center;
    }

    .decrypt-prompt mat-icon {
      font-size: 40px;
      width: 40px;
      height: 40px;
      color: #bbb;
      margin-bottom: 8px;
    }

    .decrypt-prompt p {
      color: #888;
      margin: 0 0 12px;
    }

    .decrypt-progress {
      width: 100%;
      margin-top: 12px;
    }

    .decrypted-content {
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      overflow: hidden;
    }

    .content-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      background: #e3f2fd;
      font-weight: 500;
      font-size: 14px;
    }

    .content-header span {
      flex: 1;
    }

    .content-box {
      margin: 0;
      padding: 16px;
      background: #fafafa;
      font-family: 'Roboto Mono', monospace;
      font-size: 13px;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 200px;
      overflow-y: auto;
    }

    .hidden-content {
      color: transparent;
      text-shadow: 0 0 8px rgba(0, 0, 0, 0.5);
      user-select: none;
    }

    .versions-list {
      max-height: 150px;
      overflow-y: auto;
    }

    .version-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 6px 0;
      border-bottom: 1px solid #f0f0f0;
    }

    .version-number {
      font-weight: 600;
      color: #3f51b5;
      min-width: 30px;
    }

    .version-info {
      display: flex;
      flex-direction: column;
    }

    .version-date {
      font-size: 13px;
    }

    .version-reason {
      font-size: 12px;
      color: #888;
    }

    .integrity-status {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 14px;
      margin-bottom: 8px;
    }

    .integrity-status.pending {
      background: #f5f5f5;
      color: #888;
    }

    .integrity-status.valid {
      background: #e8f5e9;
      color: #2e7d32;
    }

    .integrity-status.invalid {
      background: #ffebee;
      color: #c62828;
    }

    .hash-display {
      font-size: 12px;
      display: flex;
      gap: 6px;
      align-items: center;
    }

    .hash-display .label {
      color: #999;
      flex-shrink: 0;
    }

    .hash-display code {
      font-family: 'Roboto Mono', monospace;
      font-size: 11px;
      word-break: break-all;
      color: #555;
    }
  `]
})
export class SecretDetailDialogComponent implements OnInit {
  secret: Secret;
  versions: SecretVersion[] = [];
  decryptedContent: string | null = null;
  showContent = false;
  maskedContent = '••••••••••••••••••••••••';
  isDecrypting = false;

  integrityClass = 'pending';
  integrityIcon = 'help_outline';
  integrityMessage = 'No verificada aún';

  constructor(
    public dialogRef: MatDialogRef<SecretDetailDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { secret: Secret; folders: Folder[] },
    private secretsService: SecretsService,
    private cryptoService: CryptoService,
    private snackBar: MatSnackBar,
  ) {
    this.secret = data.secret;
  }

  ngOnInit(): void {
    this.loadVersions();
  }

  loadVersions(): void {
    this.secretsService.getVersions(this.secret.id).subscribe({
      next: (res) => { this.versions = res.versions; },
      error: () => {}
    });
  }

  async decrypt(): Promise<void> {
    this.isDecrypting = true;
    try {
      // 1. Request encrypted data from server (logs the access)
      const res = await this.secretsService.decryptSecret(this.secret.id).toPromise();
      if (!res) throw new Error('No response');

      const s = res.secret;

      // 2. Decrypt locally using cached private key
      const decryptedBuffer = await this.cryptoService.decryptFileWithCachedKey(
        s.encrypted_data!,
        s.encrypted_aes_key!
      );

      const decryptedText = new TextDecoder().decode(decryptedBuffer);

      // 3. Try to parse JSON (our secrets are stored as JSON)
      try {
        const parsed = JSON.parse(decryptedText);
        this.decryptedContent = parsed.content || decryptedText;
      } catch {
        this.decryptedContent = decryptedText;
      }

      // 4. Verify integrity
      const hash = await this.cryptoService.sha256(decryptedBuffer);
      if (hash === this.secret.content_hash) {
        this.integrityClass = 'valid';
        this.integrityIcon = 'verified';
        this.integrityMessage = 'Integridad verificada — hash coincide';
      } else {
        this.integrityClass = 'invalid';
        this.integrityIcon = 'error';
        this.integrityMessage = 'ALERTA: hash no coincide — posible manipulación';
      }

      this.showContent = true;
      this.isDecrypting = false;

    } catch (err: any) {
      this.isDecrypting = false;
      this.snackBar.open(
        'Error descifrando: ' + (err.message || err),
        'Cerrar',
        { duration: 5000 }
      );
    }
  }

  toggleVisibility(): void {
    this.showContent = !this.showContent;
  }

  async copyToClipboard(): Promise<void> {
    if (!this.decryptedContent) return;
    try {
      await navigator.clipboard.writeText(this.decryptedContent);
      this.snackBar.open('Copiado al portapapeles', 'OK', { duration: 2000 });
    } catch {
      this.snackBar.open('Error al copiar', 'Cerrar', { duration: 3000 });
    }
  }

  confirmDelete(): void {
    this.secretsService.deleteSecret(this.secret.id).subscribe({
      next: () => {
        this.snackBar.open('Secreto eliminado', 'OK', { duration: 3000 });
        this.dialogRef.close('deleted');
      },
      error: (err) => {
        this.snackBar.open(
          err.error?.error || 'Error eliminando secreto',
          'Cerrar',
          { duration: 5000 }
        );
      }
    });
  }

  isExpired(): boolean {
    if (!this.secret.expires_at) return false;
    return new Date(this.secret.expires_at) < new Date();
  }

  getTypeLabel(type: string): string {
    return SECRET_TYPE_LABELS[type as SecretType] || type;
  }

  getTypeIcon(type: string): string {
    return SECRET_TYPE_ICONS[type as SecretType] || 'lock';
  }

  formatDateTime(dateStr: string): string {
    const d = new Date(dateStr);
    return d.toLocaleDateString('es-ES', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }
}
