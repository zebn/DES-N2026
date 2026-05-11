import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';

import { AuthService, User } from '../../../core/services/auth.service';
import {
  SecretsService, Secret, SecretShare, ShareRecipient,
} from '../../../core/services/secrets.service';
import { GroupsService, Group } from '../../../core/services/groups.service';
import { CryptoService } from '../../../core/services/crypto.service';

@Component({
  selector: 'app-secret-share-dialog',
  template: `
    <h2 mat-dialog-title>
      <mat-icon>share</mat-icon>
      Compartir secreto
    </h2>

    <mat-dialog-content>
      <p class="secret-title">{{ data.secret.title }}</p>

      <mat-tab-group [(selectedIndex)]="selectedTab">
        <mat-tab label="Compartir">
          <form [formGroup]="shareForm" class="share-form">
            <mat-radio-group formControlName="target_type" class="target-radio">
              <mat-radio-button value="user">Usuario</mat-radio-button>
              <mat-radio-button value="group">Grupo</mat-radio-button>
            </mat-radio-group>

            <mat-form-field *ngIf="targetType === 'user'" appearance="outline" class="full-width">
              <mat-label>Email del destinatario</mat-label>
              <input matInput formControlName="recipient_email"
                     type="email" placeholder="usuario@ejemplo.com" autocomplete="off">
              <mat-icon matSuffix>person</mat-icon>
              <mat-error *ngIf="shareForm.get('recipient_email')?.hasError('email')">
                Email no válido
              </mat-error>
            </mat-form-field>

            <mat-form-field *ngIf="targetType === 'group'" appearance="outline" class="full-width">
              <mat-label>Grupo destinatario</mat-label>
              <mat-select formControlName="group_id">
                <mat-option *ngFor="let g of groups" [value]="g.id">
                  {{ g.name }} ({{ g.member_count || 0 }} miembros)
                </mat-option>
              </mat-select>
            </mat-form-field>

            <div class="permissions-block">
              <span class="permissions-label">Permisos</span>
              <mat-checkbox formControlName="can_read">Leer</mat-checkbox>
              <mat-checkbox formControlName="can_edit">Editar</mat-checkbox>
              <mat-checkbox formControlName="can_share">Re-compartir</mat-checkbox>
            </div>

            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Caduca el (opcional)</mat-label>
              <input matInput formControlName="expires_at" type="datetime-local">
              <mat-icon matSuffix>schedule</mat-icon>
            </mat-form-field>

            <p class="zk-note">
              <mat-icon>shield</mat-icon>
              La clave AES se re-cifra en tu navegador con la clave pública RSA-4096
              de cada destinatario. El servidor nunca ve la clave en claro.
            </p>
          </form>
        </mat-tab>

        <mat-tab label="Activas ({{ shares.length }})">
          <div class="shares-list" *ngIf="!isLoadingShares">
            <p *ngIf="shares.length === 0" class="empty">
              Aún no has compartido este secreto.
            </p>
            <div *ngFor="let s of shares" class="share-row" [class.revoked]="s.is_revoked">
              <mat-icon>{{ s.shared_with_group_id ? 'group' : 'person' }}</mat-icon>
              <div class="share-info">
                <span class="share-target">
                  {{ s.shared_with_group_name || s.shared_with_user_email }}
                  <small *ngIf="s.shared_with_group_id">→ {{ s.shared_with_user_email }}</small>
                </span>
                <span class="share-perms">
                  <mat-chip-set>
                    <mat-chip *ngIf="s.can_read">Leer</mat-chip>
                    <mat-chip *ngIf="s.can_edit">Editar</mat-chip>
                    <mat-chip *ngIf="s.can_share">Re-comp.</mat-chip>
                  </mat-chip-set>
                </span>
                <span class="share-date">{{ formatDate(s.shared_at) }}</span>
              </div>
              <button mat-icon-button color="warn"
                      [disabled]="s.is_revoked"
                      (click)="revoke(s)"
                      [matTooltip]="s.is_revoked ? 'Revocada' : 'Revocar'">
                <mat-icon>{{ s.is_revoked ? 'block' : 'remove_circle' }}</mat-icon>
              </button>
            </div>
          </div>
          <mat-progress-bar *ngIf="isLoadingShares" mode="indeterminate"></mat-progress-bar>
        </mat-tab>
      </mat-tab-group>
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="dialogRef.close(refreshed)" [disabled]="isSharing">Cerrar</button>
      <button mat-raised-button color="primary"
              *ngIf="selectedTab === 0"
              [disabled]="isSharing || !canSubmit()"
              (click)="onSubmit()">
        <mat-icon>share</mat-icon>
        {{ isSharing ? 'Compartiendo…' : 'Compartir' }}
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] {
      display: flex; align-items: center; gap: 8px;
    }
    .secret-title {
      font-weight: 500; color: #555; margin: 0 0 12px;
    }
    .share-form {
      display: flex; flex-direction: column; gap: 12px; padding-top: 16px;
    }
    .target-radio { display: flex; gap: 16px; }
    .full-width { width: 100%; }
    .permissions-block {
      display: flex; align-items: center; gap: 12px;
      flex-wrap: wrap;
      padding: 8px 12px;
      background: #f5f5f5; border-radius: 6px;
    }
    .permissions-label { color: #666; font-size: 13px; margin-right: 8px; }
    .zk-note {
      display: flex; align-items: flex-start; gap: 8px;
      font-size: 12px; color: #2e7d32;
      background: #e8f5e9; padding: 8px 12px; border-radius: 6px;
    }
    .zk-note mat-icon { font-size: 18px; width: 18px; height: 18px; flex-shrink: 0; }

    .shares-list { padding-top: 12px; }
    .empty { color: #888; text-align: center; padding: 24px; }
    .share-row {
      display: flex; align-items: center; gap: 12px;
      padding: 8px 0; border-bottom: 1px solid #f0f0f0;
    }
    .share-row.revoked { opacity: 0.5; }
    .share-info { flex: 1; display: flex; flex-direction: column; gap: 4px; }
    .share-target { font-size: 14px; }
    .share-target small { color: #888; margin-left: 4px; }
    .share-perms mat-chip { font-size: 11px; }
    .share-date { font-size: 11px; color: #999; }
  `]
})
export class SecretShareDialogComponent implements OnInit {
  shareForm: FormGroup;
  groups: Group[] = [];
  shares: SecretShare[] = [];

  selectedTab = 0;
  isSharing = false;
  isLoadingShares = false;
  refreshed = false;

  constructor(
    private fb: FormBuilder,
    public dialogRef: MatDialogRef<SecretShareDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { secret: Secret },
    private authService: AuthService,
    private secretsService: SecretsService,
    private groupsService: GroupsService,
    private cryptoService: CryptoService,
    private snackBar: MatSnackBar,
  ) {
    this.shareForm = this.fb.group({
      target_type: ['user', Validators.required],
      recipient_email: ['', [Validators.email]],
      group_id: [''],
      can_read: [true],
      can_edit: [false],
      can_share: [false],
      expires_at: [''],
    });
  }

  get targetType(): string {
    return this.shareForm.get('target_type')?.value;
  }

  ngOnInit(): void {
    this.groupsService.listGroups({ per_page: 100 }).subscribe({
      next: (res) => { this.groups = res.groups; },
      error: () => {},
    });
    this.loadShares();
  }

  loadShares(): void {
    this.isLoadingShares = true;
    this.secretsService.listShares(this.data.secret.id).subscribe({
      next: (res) => {
        this.shares = res.shares;
        this.isLoadingShares = false;
      },
      error: () => { this.isLoadingShares = false; }
    });
  }

  canSubmit(): boolean {
    if (this.targetType === 'user') {
      const email = this.shareForm.get('recipient_email')?.value;
      return !!email && this.shareForm.get('recipient_email')?.valid === true;
    }
    return !!this.shareForm.get('group_id')?.value;
  }

  async onSubmit(): Promise<void> {
    if (!this.canSubmit()) return;

    if (!this.cryptoService.isUnlocked()) {
      this.snackBar.open('Desbloquea tu clave privada antes de compartir', 'Cerrar', { duration: 4000 });
      return;
    }

    this.isSharing = true;
    const f = this.shareForm.value;

    try {
      // 1. Recuperar la clave AES en claro descifrándola con nuestra private_key
      const encMeta = await this.secretsService.decryptSecret(this.data.secret.id).toPromise();
      const encryptedAesKeyBase64 = encMeta!.secret.encrypted_aes_key!;
      const encAesBuf = this.cryptoService.base64ToArrayBuffer(encryptedAesKeyBase64);
      const myPrivateKey = this.cryptoService.getPrivateKey();
      const aesKeyBuf = await this.cryptoService.rsaDecrypt(encAesBuf, myPrivateKey);

      // 2. Resolver destinatario(s) y sus claves públicas
      const recipients: ShareRecipient[] = [];
      let target_type: 'user' | 'group';
      let target_id: number | string;

      if (this.targetType === 'user') {
        target_type = 'user';
        const email = f.recipient_email.trim();
        const pubResp = await this.authService.getUserPublicKey(email).toPromise();
        if (!pubResp || !pubResp.public_key) throw new Error('Usuario destinatario no encontrado');
        if (!pubResp.is_active) throw new Error('El destinatario está inactivo');

        const userResp = await this.authService.getUsers().toPromise().catch(() => null);
        const targetUser = userResp?.users.find((u: User) => u.email === email);
        if (!targetUser) throw new Error('No se pudo resolver el id del destinatario');
        target_id = targetUser.id;

        const recipientKey = await this.cryptoService.importPublicKey(pubResp.public_key);
        const reEnc = await this.cryptoService.rsaEncrypt(aesKeyBuf, recipientKey);
        recipients.push({
          user_id: targetUser.id,
          encrypted_aes_key_for_recipient: this.cryptoService.arrayBufferToBase64(reEnc),
        });
      } else {
        target_type = 'group';
        target_id = f.group_id;
        const memberResp = await this.groupsService.getMemberPublicKeys(f.group_id).toPromise();
        if (!memberResp) throw new Error('No se pudo obtener miembros del grupo');

        const myUserId = this.authService.getCurrentUserId?.() ?? null;
        const targets = memberResp.members.filter(m => m.user_id !== myUserId);
        if (targets.length === 0) throw new Error('El grupo no tiene otros miembros');

        for (const m of targets) {
          const pk = await this.cryptoService.importPublicKey(m.public_key);
          const reEnc = await this.cryptoService.rsaEncrypt(aesKeyBuf, pk);
          recipients.push({
            user_id: m.user_id,
            encrypted_aes_key_for_recipient: this.cryptoService.arrayBufferToBase64(reEnc),
          });
        }
      }

      // 3. Llamada al backend
      const payload = {
        target_type,
        target_id,
        recipients,
        can_read: !!f.can_read,
        can_edit: !!f.can_edit,
        can_share: !!f.can_share,
        expires_at: f.expires_at ? new Date(f.expires_at).toISOString() : undefined,
      };

      this.secretsService.shareSecret(this.data.secret.id, payload).subscribe({
        next: (res) => {
          this.snackBar.open(
            `Compartido con ${res.recipient_count} destinatario(s)`,
            'OK', { duration: 3000 }
          );
          this.refreshed = true;
          this.shareForm.patchValue({ recipient_email: '', group_id: '', can_edit: false, can_share: false, expires_at: '' });
          this.isSharing = false;
          this.loadShares();
          this.selectedTab = 1;
        },
        error: (err) => {
          this.isSharing = false;
          this.snackBar.open(
            err.error?.error || 'Error al compartir',
            'Cerrar', { duration: 5000 }
          );
        }
      });

    } catch (e: any) {
      this.isSharing = false;
      this.snackBar.open(e.message || 'Error al compartir', 'Cerrar', { duration: 5000 });
    }
  }

  revoke(share: SecretShare): void {
    this.secretsService.revokeShare(share.id).subscribe({
      next: () => {
        this.snackBar.open('Compartición revocada', 'OK', { duration: 3000 });
        this.refreshed = true;
        this.loadShares();
      },
      error: (err) => {
        this.snackBar.open(
          err.error?.error || 'Error al revocar',
          'Cerrar', { duration: 5000 }
        );
      }
    });
  }

  formatDate(s: string): string {
    return new Date(s).toLocaleString('es-ES', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }
}
