import { Component, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { SecretsService, Folder } from '../../../core/services/secrets.service';
import { FolderDialogComponent } from '../folder-dialog/folder-dialog.component';
import { ConfirmDialogComponent } from '../../../shared/components/confirm-dialog/confirm-dialog.component';

@Component({
  selector: 'app-folders-list',
  template: `
    <div class="folders-container">
      <mat-card>
        <mat-card-header>
          <mat-card-title>
            <mat-icon>folder</mat-icon>
            Gestión de Carpetas
          </mat-card-title>
          <div class="header-actions">
            <button mat-raised-button color="primary" (click)="openCreateDialog()">
              <mat-icon>create_new_folder</mat-icon>
              Nueva Carpeta
            </button>
            <button mat-icon-button (click)="loadFolders()" [disabled]="isLoading" matTooltip="Actualizar">
              <mat-icon>refresh</mat-icon>
            </button>
          </div>
        </mat-card-header>

        <mat-card-content>
          <!-- Loading -->
          <div *ngIf="isLoading" class="loading-container">
            <mat-spinner diameter="50"></mat-spinner>
            <p>Cargando carpetas...</p>
          </div>

          <!-- Empty state -->
          <div *ngIf="!isLoading && folders.length === 0" class="empty-state">
            <mat-icon class="empty-icon">folder_open</mat-icon>
            <h3>No hay carpetas</h3>
            <p>Crea tu primera carpeta para organizar tus secretos</p>
            <button mat-raised-button color="primary" (click)="openCreateDialog()">
              <mat-icon>create_new_folder</mat-icon>
              Crear Primera Carpeta
            </button>
          </div>

          <!-- Folders table -->
          <div *ngIf="!isLoading && folders.length > 0" class="table-container">
            <table mat-table [dataSource]="folders" class="folders-table">
              <!-- Icon Column -->
              <ng-container matColumnDef="icon">
                <th mat-header-cell *matHeaderCellDef></th>
                <td mat-cell *matCellDef="let folder">
                  <mat-icon class="folder-icon">folder</mat-icon>
                </td>
              </ng-container>

              <!-- Name Column -->
              <ng-container matColumnDef="name">
                <th mat-header-cell *matHeaderCellDef>Nombre</th>
                <td mat-cell *matCellDef="let folder">
                  <strong>{{ folder.name }}</strong>
                </td>
              </ng-container>

              <!-- Parent Column -->
              <ng-container matColumnDef="parent">
                <th mat-header-cell *matHeaderCellDef>Carpeta Padre</th>
                <td mat-cell *matCellDef="let folder">
                  {{ getParentPath(folder.parent_id) || 'Raíz' }}
                </td>
              </ng-container>

              <!-- Secrets Count Column -->
              <ng-container matColumnDef="secrets">
                <th mat-header-cell *matHeaderCellDef>Secretos</th>
                <td mat-cell *matCellDef="let folder">
                  <mat-chip>{{ getSecretsCount(folder.id) }}</mat-chip>
                </td>
              </ng-container>

              <!-- Created Date Column -->
              <ng-container matColumnDef="created">
                <th mat-header-cell *matHeaderCellDef>Creada</th>
                <td mat-cell *matCellDef="let folder">
                  {{ formatDate(folder.created_at) }}
                </td>
              </ng-container>

              <!-- Actions Column -->
              <ng-container matColumnDef="actions">
                <th mat-header-cell *matHeaderCellDef>Acciones</th>
                <td mat-cell *matCellDef="let folder">
                  <button mat-icon-button [matMenuTriggerFor]="menu" matTooltip="Opciones">
                    <mat-icon>more_vert</mat-icon>
                  </button>
                  <mat-menu #menu="matMenu">
                    <button mat-menu-item (click)="openEditDialog(folder)">
                      <mat-icon>edit</mat-icon>
                      <span>Editar</span>
                    </button>
                    <button mat-menu-item (click)="deleteFolder(folder)">
                      <mat-icon color="warn">delete</mat-icon>
                      <span>Eliminar</span>
                    </button>
                  </mat-menu>
                </td>
              </ng-container>

              <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
              <tr mat-row *matRowDef="let row; columns: displayedColumns;" class="folder-row"></tr>
            </table>
          </div>

          <!-- Info message -->
          <div *ngIf="!isLoading && folders.length > 0" class="info-message">
            <mat-icon>info</mat-icon>
            <span>Las carpetas te ayudan a organizar tus secretos. Al eliminar una carpeta, los secretos dentro quedan sin carpeta.</span>
          </div>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .folders-container {
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

    .table-container {
      overflow-x: auto;
    }

    .folders-table {
      width: 100%;
    }

    .folder-icon {
      color: #ffc107;
      font-size: 24px;
      width: 24px;
      height: 24px;
    }

    .folder-row {
      cursor: pointer;
      transition: background-color 0.2s;
    }

    .folder-row:hover {
      background-color: #f5f5f5;
    }

    .info-message {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 16px;
      margin-top: 16px;
      background: #e3f2fd;
      border-left: 4px solid #2196f3;
      border-radius: 4px;
      font-size: 14px;
      color: #1565c0;
    }

    .info-message mat-icon {
      color: #2196f3;
      flex-shrink: 0;
    }
  `]
})
export class FoldersListComponent implements OnInit {
  folders: Folder[] = [];
  isLoading = false;
  displayedColumns: string[] = ['icon', 'name', 'parent', 'secrets', 'created', 'actions'];

  constructor(
    private secretsService: SecretsService,
    private dialog: MatDialog,
    private snackBar: MatSnackBar,
  ) {}

  ngOnInit(): void {
    this.loadFolders();
  }

  loadFolders(): void {
    this.isLoading = true;
    this.secretsService.listFolders().subscribe({
      next: (res) => {
        this.folders = res.folders;
        this.isLoading = false;
      },
      error: (err) => {
        this.isLoading = false;
        this.snackBar.open(
          err.error?.error || 'Error cargando carpetas',
          'Cerrar',
          { duration: 5000 }
        );
      }
    });
  }

  openCreateDialog(): void {
    const dialogRef = this.dialog.open(FolderDialogComponent, {
      width: '500px',
      data: { folders: this.folders }
    });

    dialogRef.afterClosed().subscribe((result: boolean) => {
      if (result) {
        this.loadFolders();
        this.snackBar.open('Carpeta creada exitosamente', 'OK', { duration: 3000 });
      }
    });
  }

  openEditDialog(folder: Folder): void {
    const dialogRef = this.dialog.open(FolderDialogComponent, {
      width: '500px',
      data: { folder, folders: this.folders }
    });

    dialogRef.afterClosed().subscribe((result: boolean) => {
      if (result) {
        this.loadFolders();
        this.snackBar.open('Carpeta actualizada exitosamente', 'OK', { duration: 3000 });
      }
    });
  }

  deleteFolder(folder: Folder): void {
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      data: {
        title: 'Eliminar Carpeta',
        message: `¿Estás seguro de eliminar la carpeta "${folder.name}"? Los secretos dentro quedarán sin carpeta.`,
        confirmText: 'Eliminar',
        cancelText: 'Cancelar',
      }
    });

    dialogRef.afterClosed().subscribe((confirmed: boolean) => {
      if (confirmed) {
        this.secretsService.deleteFolder(folder.id).subscribe({
          next: () => {
            this.snackBar.open('Carpeta eliminada', 'OK', { duration: 3000 });
            this.loadFolders();
          },
          error: (err) => {
            this.snackBar.open(
              err.error?.error || 'Error eliminando carpeta',
              'Cerrar',
              { duration: 5000 }
            );
          }
        });
      }
    });
  }

  getParentName(parentId: string | null): string | null {
    if (!parentId) return null;
    const parent = this.folders.find(f => f.id === parentId);
    return parent ? parent.name : null;
  }

  getParentPath(parentId: string | null): string | null {
    if (!parentId) return null;
    const parent = this.folders.find(f => f.id === parentId);
    if (!parent) return null;
    return this.getFolderPath(parent);
  }

  getFolderPath(folder: Folder): string {
    const path: string[] = [];
    let current: Folder | undefined = folder;

    // Build path from current folder to root
    while (current) {
      path.unshift(current.name);
      current = this.folders.find(f => f.id === current?.parent_id);
    }

    return path.join(' / ');
  }

  getSecretsCount(folderId: string): number {
    // This would need to be populated from the backend
    // For now, we return a placeholder
    return 0;
  }

  formatDate(dateStr: string): string {
    const d = new Date(dateStr);
    return d.toLocaleDateString('es-ES', {
      day: '2-digit',
      month: 'short',
      year: 'numeric'
    });
  }
}
