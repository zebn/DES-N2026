import { Component, OnInit } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDialog } from '@angular/material/dialog';
import { PageEvent } from '@angular/material/paginator';
import {
  SecretsService, Secret, Folder,
  SecretType, SECRET_TYPE_LABELS, SECRET_TYPE_ICONS
} from '../../../core/services/secrets.service';
import { CryptoService } from '../../../core/services/crypto.service';
import { UnlockDialogComponent } from '../../../shared/components/unlock-dialog/unlock-dialog.component';
import { ConfirmDialogComponent } from '../../../shared/components/confirm-dialog/confirm-dialog.component';
import { SecretCreateDialogComponent } from '../secret-create-dialog/secret-create-dialog.component';
import { SecretDetailDialogComponent } from '../secret-detail-dialog/secret-detail-dialog.component';

@Component({
  selector: 'app-secrets-list',
  template: `
    <div class="secrets-container">
      <mat-card>
        <mat-card-header>
          <mat-card-title>
            <mat-icon>lock</mat-icon>
            Bóveda de Secretos
          </mat-card-title>
          <div class="header-actions">
            <button mat-raised-button color="primary" (click)="openCreateDialog()">
              <mat-icon>add</mat-icon>
              Nuevo Secreto
            </button>
            <button mat-icon-button (click)="loadSecrets()" [disabled]="isLoading" matTooltip="Actualizar">
              <mat-icon>refresh</mat-icon>
            </button>
          </div>
        </mat-card-header>

        <mat-card-content>
          <!-- Filters -->
          <div class="filters-row">
            <mat-form-field appearance="outline" class="search-field">
              <mat-label>Buscar secretos</mat-label>
              <input matInput [(ngModel)]="searchQuery" (keyup.enter)="loadSecrets()" placeholder="Buscar por título...">
              <mat-icon matSuffix>search</mat-icon>
            </mat-form-field>

            <mat-form-field appearance="outline" class="type-filter">
              <mat-label>Tipo</mat-label>
              <mat-select [(ngModel)]="filterType" (selectionChange)="loadSecrets()">
                <mat-option value="">Todos</mat-option>
                <mat-option *ngFor="let type of secretTypes" [value]="type">
                  {{ getTypeLabel(type) }}
                </mat-option>
              </mat-select>
            </mat-form-field>

            <mat-form-field appearance="outline" class="folder-filter">
              <mat-label>Carpeta</mat-label>
              <mat-select [(ngModel)]="filterFolder" (selectionChange)="loadSecrets()">
                <mat-option value="">Todas</mat-option>
                <mat-option *ngFor="let f of folders" [value]="f.id">
                  {{ f.name }}
                </mat-option>
              </mat-select>
            </mat-form-field>
          </div>

          <!-- Loading -->
          <div *ngIf="isLoading" class="loading-container">
            <mat-spinner diameter="50"></mat-spinner>
            <p>Cargando secretos...</p>
          </div>

          <!-- Empty state -->
          <div *ngIf="!isLoading && secrets.length === 0" class="empty-state">
            <mat-icon class="empty-icon">enhanced_encryption</mat-icon>
            <h3>No hay secretos</h3>
            <p>Almacena tu primera contraseña, clave API o nota segura</p>
            <button mat-raised-button color="primary" (click)="openCreateDialog()">
              <mat-icon>add</mat-icon>
              Crear Primer Secreto
            </button>
          </div>

          <!-- Secrets grid -->
          <div *ngIf="!isLoading && secrets.length > 0" class="secrets-grid">
            <mat-card *ngFor="let secret of secrets"
                      class="secret-card"
                      [class.expired]="isExpired(secret)"
                      (click)="openDetailDialog(secret)">
              <div class="secret-card-header">
                <mat-icon [class]="'type-icon type-' + secret.secret_type.toLowerCase()">
                  {{ getTypeIcon(secret.secret_type) }}
                </mat-icon>
                <div class="secret-info">
                  <h3 class="secret-title">{{ secret.title }}</h3>
                  <span class="secret-type-label">{{ getTypeLabel(secret.secret_type) }}</span>
                </div>
                <button mat-icon-button [matMenuTriggerFor]="secretMenu" (click)="$event.stopPropagation()">
                  <mat-icon>more_vert</mat-icon>
                </button>
                <mat-menu #secretMenu="matMenu">
                  <button mat-menu-item (click)="openDetailDialog(secret)">
                    <mat-icon>visibility</mat-icon>
                    <span>Ver / Descifrar</span>
                  </button>
                  <button mat-menu-item (click)="deleteSecret(secret)">
                    <mat-icon color="warn">delete</mat-icon>
                    <span>Eliminar</span>
                  </button>
                </mat-menu>
              </div>

              <div class="secret-card-meta">
                <div class="meta-item" *ngIf="secret.folder_id">
                  <mat-icon>folder</mat-icon>
                  <span>{{ getFolderName(secret.folder_id) }}</span>
                </div>
                <div class="meta-item">
                  <mat-icon>history</mat-icon>
                  <span>v{{ secret.version }}</span>
                </div>
                <div class="meta-item">
                  <mat-icon>schedule</mat-icon>
                  <span>{{ formatDate(secret.updated_at) }}</span>
                </div>
              </div>

              <div class="secret-card-footer">
                <mat-chip-set>
                  <mat-chip *ngIf="isExpired(secret)" color="warn" selected>
                    <mat-icon matChipAvatar>warning</mat-icon>
                    Expirado
                  </mat-chip>
                  <mat-chip *ngIf="secret.rotation_period_days">
                    <mat-icon matChipAvatar>autorenew</mat-icon>
                    Rotación {{ secret.rotation_period_days }}d
                  </mat-chip>
                </mat-chip-set>
              </div>
            </mat-card>
          </div>

          <!-- Paginator -->
          <mat-paginator *ngIf="totalSecrets > pageSize"
                         [length]="totalSecrets"
                         [pageSize]="pageSize"
                         [pageSizeOptions]="[10, 20, 50]"
                         (page)="onPage($event)"
                         showFirstLastButtons>
          </mat-paginator>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .secrets-container {
      max-width: 1200px;
      margin: 0 auto;
    }

    mat-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }

    mat-card-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 22px;
      margin: 0;
    }

    .header-actions {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    .filters-row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }

    .search-field {
      flex: 2;
      min-width: 200px;
    }

    .type-filter,
    .folder-filter {
      flex: 1;
      min-width: 150px;
    }

    .loading-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px;
      gap: 16px;
      color: #666;
    }

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 60px 20px;
      color: #888;
    }

    .empty-icon {
      font-size: 72px;
      width: 72px;
      height: 72px;
      color: #ccc;
      margin-bottom: 16px;
    }

    .empty-state h3 {
      font-size: 20px;
      margin: 0 0 8px;
    }

    .empty-state p {
      margin: 0 0 24px;
    }

    /* Secrets Grid */
    .secrets-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 16px;
    }

    .secret-card {
      cursor: pointer;
      transition: transform 0.15s, box-shadow 0.15s;
      border-left: 4px solid #3f51b5;
    }

    .secret-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }

    .secret-card.expired {
      border-left-color: #f44336;
      opacity: 0.85;
    }

    .secret-card-header {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 16px 16px 8px;
    }

    .type-icon {
      font-size: 32px;
      width: 32px;
      height: 32px;
      padding: 8px;
      border-radius: 8px;
      background: #e8eaf6;
      color: #3f51b5;
    }

    .type-icon.type-password { background: #e8eaf6; color: #3f51b5; }
    .type-icon.type-api_key { background: #fff3e0; color: #e65100; }
    .type-icon.type-certificate { background: #e8f5e9; color: #2e7d32; }
    .type-icon.type-ssh_key { background: #fce4ec; color: #c62828; }
    .type-icon.type-note { background: #fffde7; color: #f9a825; }
    .type-icon.type-database { background: #e3f2fd; color: #1565c0; }
    .type-icon.type-env_variable { background: #f3e5f5; color: #7b1fa2; }
    .type-icon.type-identity { background: #efebe9; color: #4e342e; }

    .secret-info {
      flex: 1;
      min-width: 0;
    }

    .secret-title {
      margin: 0;
      font-size: 16px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .secret-type-label {
      font-size: 12px;
      color: #888;
    }

    .secret-card-meta {
      display: flex;
      gap: 16px;
      padding: 8px 16px;
      color: #666;
      font-size: 12px;
    }

    .meta-item {
      display: flex;
      align-items: center;
      gap: 4px;
    }

    .meta-item mat-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
    }

    .secret-card-footer {
      padding: 4px 16px 12px;
    }
  `]
})
export class SecretsListComponent implements OnInit {
  secrets: Secret[] = [];
  folders: Folder[] = [];
  isLoading = false;
  totalSecrets = 0;
  page = 1;
  pageSize = 20;
  searchQuery = '';
  filterType = '';
  filterFolder = '';

  secretTypes: SecretType[] = [
    'PASSWORD', 'API_KEY', 'CERTIFICATE', 'SSH_KEY',
    'NOTE', 'DATABASE', 'ENV_VARIABLE', 'IDENTITY'
  ];

  constructor(
    private secretsService: SecretsService,
    private cryptoService: CryptoService,
    private snackBar: MatSnackBar,
    private dialog: MatDialog,
  ) {}

  ngOnInit(): void {
    this.loadFolders();
    this.loadSecrets();
  }

  loadSecrets(): void {
    this.isLoading = true;
    this.secretsService.listSecrets({
      type: this.filterType || undefined,
      folder_id: this.filterFolder || undefined,
      search: this.searchQuery || undefined,
      page: this.page,
      per_page: this.pageSize,
    }).subscribe({
      next: (res) => {
        this.secrets = res.secrets;
        this.totalSecrets = res.total;
        this.isLoading = false;
      },
      error: (err) => {
        this.isLoading = false;
        this.snackBar.open(
          err.error?.error || 'Error cargando secretos',
          'Cerrar',
          { duration: 5000 }
        );
      }
    });
  }

  loadFolders(): void {
    this.secretsService.listFolders().subscribe({
      next: (res) => { this.folders = res.folders; },
      error: () => {}
    });
  }

  onPage(event: PageEvent): void {
    this.page = event.pageIndex + 1;
    this.pageSize = event.pageSize;
    this.loadSecrets();
  }

  openCreateDialog(): void {
    // Ensure private key is unlocked
    if (!this.cryptoService.isUnlocked()) {
      const ref = this.dialog.open(UnlockDialogComponent, { disableClose: true });
      ref.afterClosed().subscribe((unlocked: boolean) => {
        if (unlocked) this.openCreateDialog();
      });
      return;
    }

    const dialogRef = this.dialog.open(SecretCreateDialogComponent, {
      width: '600px',
      data: { folders: this.folders }
    });

    dialogRef.afterClosed().subscribe((created: boolean) => {
      if (created) {
        this.loadSecrets();
        this.snackBar.open('Secreto creado exitosamente', 'OK', { duration: 3000 });
      }
    });
  }

  openDetailDialog(secret: Secret): void {
    // Ensure private key is unlocked
    if (!this.cryptoService.isUnlocked()) {
      const ref = this.dialog.open(UnlockDialogComponent, { disableClose: true });
      ref.afterClosed().subscribe((unlocked: boolean) => {
        if (unlocked) this.openDetailDialog(secret);
      });
      return;
    }

    const dialogRef = this.dialog.open(SecretDetailDialogComponent, {
      width: '700px',
      data: { secret, folders: this.folders }
    });

    dialogRef.afterClosed().subscribe((result: string) => {
      if (result === 'deleted' || result === 'updated') {
        this.loadSecrets();
      }
    });
  }

  deleteSecret(secret: Secret): void {
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      data: {
        title: 'Eliminar Secreto',
        message: `¿Estás seguro de eliminar "${secret.title}"? Esta acción no se puede deshacer.`,
        confirmText: 'Eliminar',
        cancelText: 'Cancelar',
      }
    });

    dialogRef.afterClosed().subscribe((confirmed: boolean) => {
      if (confirmed) {
        this.secretsService.deleteSecret(secret.id).subscribe({
          next: () => {
            this.snackBar.open('Secreto eliminado', 'OK', { duration: 3000 });
            this.loadSecrets();
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
    });
  }

  getTypeLabel(type: string): string {
    return SECRET_TYPE_LABELS[type as SecretType] || type;
  }

  getTypeIcon(type: string): string {
    return SECRET_TYPE_ICONS[type as SecretType] || 'lock';
  }

  getFolderName(folderId: string): string {
    const folder = this.folders.find(f => f.id === folderId);
    return folder ? folder.name : 'Sin carpeta';
  }

  isExpired(secret: Secret): boolean {
    if (!secret.expires_at) return false;
    return new Date(secret.expires_at) < new Date();
  }

  formatDate(dateStr: string): string {
    const d = new Date(dateStr);
    return d.toLocaleDateString('es-ES', {
      day: '2-digit', month: 'short', year: 'numeric'
    });
  }
}
