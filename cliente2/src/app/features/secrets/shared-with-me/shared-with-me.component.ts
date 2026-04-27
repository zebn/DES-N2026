import { Component, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';

import {
  SecretsService, SecretShare, SECRET_TYPE_ICONS, SECRET_TYPE_LABELS, SecretType,
} from '../../../core/services/secrets.service';
import { CryptoService } from '../../../core/services/crypto.service';
import { UnlockDialogComponent } from '../../../shared/components/unlock-dialog/unlock-dialog.component';

@Component({
  selector: 'app-shared-with-me',
  template: `
    <div class="container">
      <mat-card>
        <mat-card-header>
          <mat-card-title>
            <mat-icon>inbox</mat-icon>
            Compartido conmigo
          </mat-card-title>
          <button mat-icon-button (click)="load()" [disabled]="isLoading" matTooltip="Actualizar">
            <mat-icon>refresh</mat-icon>
          </button>
        </mat-card-header>

        <mat-card-content>
          <div *ngIf="isLoading" class="loading">
            <mat-spinner diameter="42"></mat-spinner>
          </div>

          <div *ngIf="!isLoading && shares.length === 0" class="empty">
            <mat-icon>folder_shared</mat-icon>
            <h3>Nadie ha compartido secretos contigo todavía</h3>
          </div>

          <div *ngIf="!isLoading && shares.length > 0" class="shares-grid">
            <mat-card *ngFor="let share of shares" class="share-card">
              <div class="card-head">
                <mat-icon [class]="'type-icon type-' + (share.secret?.secret_type || '').toLowerCase()">
                  {{ getTypeIcon(share.secret?.secret_type) }}
                </mat-icon>
                <div class="title-block">
                  <h3>{{ share.secret?.title }}</h3>
                  <span class="from">de {{ share.shared_by_email }}</span>
                </div>
              </div>

              <div class="meta-row">
                <mat-chip-set>
                  <mat-chip *ngIf="share.shared_with_group_name">
                    <mat-icon matChipAvatar>group</mat-icon>
                    {{ share.shared_with_group_name }}
                  </mat-chip>
                  <mat-chip *ngIf="share.can_read">Leer</mat-chip>
                  <mat-chip *ngIf="share.can_edit">Editar</mat-chip>
                  <mat-chip *ngIf="share.can_share">Re-comp.</mat-chip>
                  <mat-chip *ngIf="share.expires_at" color="warn">
                    Hasta {{ formatDate(share.expires_at) }}
                  </mat-chip>
                </mat-chip-set>
              </div>

              <div *ngIf="share.id === activeId && decryptedById[share.id]" class="decrypted">
                <div class="decrypted-header">
                  <mat-icon color="primary">lock_open</mat-icon>
                  <span>Contenido descifrado</span>
                  <button mat-icon-button (click)="copy(share.id)" matTooltip="Copiar">
                    <mat-icon>content_copy</mat-icon>
                  </button>
                </div>
                <pre class="content-box">{{ decryptedById[share.id] }}</pre>
              </div>

              <div class="card-actions">
                <button mat-button color="primary"
                        (click)="decryptShare(share)"
                        [disabled]="isDecrypting === share.id">
                  <mat-icon>lock_open</mat-icon>
                  {{ isDecrypting === share.id ? 'Descifrando…' : 'Ver / Descifrar' }}
                </button>
                <button mat-button color="warn" (click)="renounce(share)">
                  <mat-icon>block</mat-icon>
                  Renunciar
                </button>
              </div>
            </mat-card>
          </div>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .container { max-width: 1100px; margin: 0 auto; }
    mat-card-header { display: flex; align-items: center; justify-content: space-between; }
    mat-card-title { display: flex; align-items: center; gap: 8px; }
    .loading { display: flex; justify-content: center; padding: 40px; }
    .empty {
      text-align: center; padding: 40px; color: #888;
    }
    .empty mat-icon { font-size: 56px; width: 56px; height: 56px; color: #ddd; }

    .shares-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 12px; padding-top: 12px;
    }
    .share-card { display: flex; flex-direction: column; gap: 8px; }
    .card-head { display: flex; gap: 12px; align-items: flex-start; }
    .type-icon {
      font-size: 28px; width: 28px; height: 28px; flex-shrink: 0;
    }
    .type-icon.type-password { color: #3f51b5; }
    .type-icon.type-api_key { color: #e65100; }
    .type-icon.type-certificate { color: #2e7d32; }
    .type-icon.type-ssh_key { color: #c62828; }
    .type-icon.type-note { color: #f9a825; }
    .type-icon.type-database { color: #1565c0; }
    .type-icon.type-env_variable { color: #7b1fa2; }
    .type-icon.type-identity { color: #4e342e; }
    .title-block h3 { margin: 0; font-size: 15px; }
    .from { font-size: 12px; color: #888; }
    .meta-row mat-chip { font-size: 11px; }

    .decrypted { border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden; }
    .decrypted-header {
      display: flex; align-items: center; gap: 6px;
      padding: 6px 10px; background: #e3f2fd; font-size: 13px; font-weight: 500;
    }
    .decrypted-header span { flex: 1; }
    .content-box {
      margin: 0; padding: 12px; background: #fafafa;
      font-family: 'Roboto Mono', monospace; font-size: 12px;
      white-space: pre-wrap; word-break: break-all;
      max-height: 200px; overflow-y: auto;
    }
    .card-actions { display: flex; justify-content: flex-end; gap: 4px; }
  `]
})
export class SharedWithMeComponent implements OnInit {
  shares: SecretShare[] = [];
  isLoading = false;
  isDecrypting: string | null = null;
  activeId: string | null = null;
  decryptedById: Record<string, string> = {};

  constructor(
    private secretsService: SecretsService,
    private cryptoService: CryptoService,
    private snackBar: MatSnackBar,
    private dialog: MatDialog,
  ) {}

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.isLoading = true;
    this.secretsService.listSharedWithMe({ per_page: 100 }).subscribe({
      next: (res) => {
        this.shares = res.shares;
        this.isLoading = false;
      },
      error: (err) => {
        this.isLoading = false;
        this.snackBar.open(err.error?.error || 'Error cargando comparticiones', 'Cerrar', { duration: 5000 });
      }
    });
  }

  async decryptShare(share: SecretShare): Promise<void> {
    if (!this.cryptoService.isUnlocked()) {
      const ref = this.dialog.open(UnlockDialogComponent, { disableClose: true });
      ref.afterClosed().subscribe((unlocked: boolean) => {
        if (unlocked) this.decryptShare(share);
      });
      return;
    }

    this.isDecrypting = share.id;
    try {
      const res = await this.secretsService.accessSharedSecret(share.id).toPromise();
      if (!res) throw new Error('Sin respuesta');

      // Descifrar la AES con MI clave privada (la entrega ya viene re-cifrada para mí)
      const decryptedBuffer = await this.cryptoService.decryptFileWithCachedKey(
        res.secret.encrypted_data,
        res.share.encrypted_aes_key_for_recipient!,
      );

      const text = new TextDecoder().decode(decryptedBuffer);

      // Verificar integridad: hash debe coincidir con secret.content_hash
      const hash = await this.cryptoService.sha256(decryptedBuffer);
      if (hash !== res.secret.content_hash) {
        this.snackBar.open('⚠️ Hash no coincide — posible manipulación', 'Cerrar', { duration: 6000 });
      }

      // Verificar firma del propietario
      try {
        const pubKey = await this.cryptoService.importPublicKeyForSigning(res.secret.owner_public_key);
        const sigBuf = this.cryptoService.base64ToArrayBuffer(res.secret.digital_signature);
        const valid = await crypto.subtle.verify(
          { name: 'RSA-PSS', saltLength: 32 },
          pubKey,
          sigBuf,
          new TextEncoder().encode(res.secret.content_hash),
        );
        if (!valid) {
          this.snackBar.open('⚠️ Firma inválida', 'Cerrar', { duration: 6000 });
        }
      } catch {}

      let display = text;
      try {
        const parsed = JSON.parse(text);
        display = parsed.content || JSON.stringify(parsed, null, 2);
      } catch {}

      this.decryptedById[share.id] = display;
      this.activeId = share.id;
      this.isDecrypting = null;
    } catch (e: any) {
      this.isDecrypting = null;
      this.snackBar.open(e.message || 'Error descifrando', 'Cerrar', { duration: 5000 });
    }
  }

  renounce(share: SecretShare): void {
    this.secretsService.revokeShare(share.id).subscribe({
      next: () => {
        this.snackBar.open('Has renunciado al acceso', 'OK', { duration: 3000 });
        this.load();
      },
      error: (err) => {
        this.snackBar.open(err.error?.error || 'Error', 'Cerrar', { duration: 5000 });
      }
    });
  }

  async copy(shareId: string): Promise<void> {
    const text = this.decryptedById[shareId];
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      this.snackBar.open('Copiado', 'OK', { duration: 1500 });
    } catch {
      this.snackBar.open('Error al copiar', 'Cerrar', { duration: 3000 });
    }
  }

  getTypeIcon(type: string | undefined): string {
    if (!type) return 'lock';
    return SECRET_TYPE_ICONS[type as SecretType] || 'lock';
  }

  formatDate(s: string): string {
    return new Date(s).toLocaleDateString('es-ES', {
      day: '2-digit', month: 'short', year: 'numeric'
    });
  }
}
