import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDialog } from '@angular/material/dialog';
import { FileService } from '../../../core/services/file.service';
import { CryptoService } from '../../../core/services/crypto.service';
import { UnlockDialogComponent } from '../../../shared/components/unlock-dialog/unlock-dialog.component';
import { ShareFileDialogComponent } from '../share-file-dialog/share-file-dialog.component';
import { ConfirmDialogComponent } from '../../../shared/components/confirm-dialog/confirm-dialog.component';

interface FileInfo {
  id: number;
  title: string;
  original_filename: string;
  file_size: number;
  mime_type: string;
  classification_level: string;
  uploaded_at: string;
  updated_at: string;
  owner_name?: string;
  encrypted_aes_key?: string;
}

@Component({
  selector: 'app-file-list',
  template: `
    <div class="file-list-container">
      <mat-card>
        <mat-card-header>
          <mat-card-title>
            <mat-icon>folder_open</mat-icon>
            Mis Archivos
          </mat-card-title>
          <div class="header-actions">
            <button mat-raised-button color="primary" routerLink="/files/upload">
              <mat-icon>cloud_upload</mat-icon>
              Subir Archivo
            </button>
            <button mat-icon-button (click)="loadFiles()" [disabled]="isLoading">
              <mat-icon>refresh</mat-icon>
            </button>
          </div>
        </mat-card-header>

        <mat-card-content>
          <!-- Loading spinner -->
          <div *ngIf="isLoading" class="loading-container">
            <mat-spinner diameter="50"></mat-spinner>
            <p>Cargando archivos...</p>
          </div>

          <!-- Empty state -->
          <div *ngIf="!isLoading && files.length === 0" class="empty-state">
            <mat-icon class="empty-icon">cloud_off</mat-icon>
            <h3>No hay archivos</h3>
            <p>Sube tu primer archivo cifrado para comenzar</p>
            <button mat-raised-button color="primary" routerLink="/files/upload">
              <mat-icon>add</mat-icon>
              Subir Primer Archivo
            </button>
          </div>

          <!-- Files table -->
          <div *ngIf="!isLoading && files.length > 0" class="files-table-container">
            <table mat-table [dataSource]="files" class="files-table">
              
              <!-- Icon Column -->
              <ng-container matColumnDef="icon">
                <th mat-header-cell *matHeaderCellDef></th>
                <td mat-cell *matCellDef="let file">
                  <mat-icon [class]="'file-icon ' + getFileIconClass(file.mime_type)">
                    {{ getFileIcon(file.mime_type) }}
                  </mat-icon>
                </td>
              </ng-container>

              <!-- Title Column -->
              <ng-container matColumnDef="title">
                <th mat-header-cell *matHeaderCellDef>Título</th>
                <td mat-cell *matCellDef="let file">
                  <div class="file-title">
                    <strong>{{ file.title }}</strong>
                    <small>{{ file.original_filename }}</small>
                  </div>
                </td>
              </ng-container>

              <!-- Size Column -->
              <ng-container matColumnDef="size">
                <th mat-header-cell *matHeaderCellDef>Tamaño</th>
                <td mat-cell *matCellDef="let file">
                  {{ formatFileSize(file.file_size) }}
                </td>
              </ng-container>

              <!-- Classification Column -->
              <ng-container matColumnDef="classification">
                <th mat-header-cell *matHeaderCellDef>Clasificación</th>
                <td mat-cell *matCellDef="let file">
                  <mat-chip [class]="'classification-chip ' + file.classification_level.toLowerCase()">
                    <mat-icon>shield</mat-icon>
                    {{ file.classification_level }}
                  </mat-chip>
                </td>
              </ng-container>

              <!-- Date Column -->
              <ng-container matColumnDef="date">
                <th mat-header-cell *matHeaderCellDef>Fecha</th>
                <td mat-cell *matCellDef="let file">
                  {{ formatDate(file.uploaded_at) }}
                </td>
              </ng-container>

              <!-- Actions Column -->
              <ng-container matColumnDef="actions">
                <th mat-header-cell *matHeaderCellDef>Acciones</th>
                <td mat-cell *matCellDef="let file">
                  <button mat-icon-button [matMenuTriggerFor]="menu">
                    <mat-icon>more_vert</mat-icon>
                  </button>
                  <mat-menu #menu="matMenu">
                    <button mat-menu-item (click)="viewFile(file)">
                      <mat-icon>visibility</mat-icon>
                      <span>Ver detalles</span>
                    </button>
                    <button mat-menu-item (click)="downloadFile(file)">
                      <mat-icon>download</mat-icon>
                      <span>Descargar</span>
                    </button>
                    <button mat-menu-item (click)="shareFile(file)">
                      <mat-icon>share</mat-icon>
                      <span>Compartir</span>
                    </button>
                    <mat-divider></mat-divider>
                    <button mat-menu-item (click)="deleteFile(file)" class="delete-action">
                      <mat-icon>delete</mat-icon>
                      <span>Eliminar</span>
                    </button>
                  </mat-menu>
                </td>
              </ng-container>

              <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
              <tr mat-row *matRowDef="let row; columns: displayedColumns;" 
                  class="file-row"
                  (click)="viewFile(row)"></tr>
            </table>

            <!-- Pagination -->
            <mat-paginator 
              [length]="files.length"
              [pageSize]="10"
              [pageSizeOptions]="[5, 10, 25, 50]"
              showFirstLastButtons>
            </mat-paginator>
          </div>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .file-list-container {
      padding: 20px;
      max-width: 1400px;
      margin: 0 auto;
    }

    mat-card {
      margin-bottom: 20px;
    }

    mat-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px;
      border-bottom: 1px solid #e0e0e0;
    }

    mat-card-title {
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0;
    }

    .header-actions {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    mat-card-content {
      padding: 0 !important;
    }

    .loading-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 60px 20px;
      gap: 16px;
    }

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 60px 20px;
      text-align: center;
      color: #666;
    }

    .empty-icon {
      font-size: 64px;
      width: 64px;
      height: 64px;
      color: #ccc;
      margin-bottom: 16px;
    }

    .empty-state h3 {
      margin: 8px 0;
      color: #333;
    }

    .empty-state p {
      margin-bottom: 24px;
    }

    .files-table-container {
      overflow-x: auto;
    }

    .files-table {
      width: 100%;
    }

    .file-row {
      cursor: pointer;
      transition: background-color 0.2s;
    }

    .file-row:hover {
      background-color: #f5f5f5;
    }

    .file-icon {
      font-size: 32px;
      width: 32px;
      height: 32px;
    }

    .file-icon.image { color: #4CAF50; }
    .file-icon.pdf { color: #F44336; }
    .file-icon.document { color: #2196F3; }
    .file-icon.video { color: #9C27B0; }
    .file-icon.archive { color: #FF9800; }
    .file-icon.default { color: #757575; }

    .file-title {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .file-title small {
      color: #666;
      font-size: 12px;
    }

    .classification-chip {
      font-size: 11px;
      font-weight: 500;
      display: inline-flex !important;
      align-items: center;
      gap: 4px;
      padding: 4px 8px !important;
      height: 24px !important;
      min-height: 24px !important;
    }

    .classification-chip mat-icon {
      font-size: 14px;
      width: 14px;
      height: 14px;
    }

    .classification-chip.restricted {
      background-color: #4CAF50 !important;
      color: white !important;
    }

    .classification-chip.confidential {
      background-color: #2196F3 !important;
      color: white !important;
    }

    .classification-chip.secret {
      background-color: #FF9800 !important;
      color: white !important;
    }

    .classification-chip.top_secret {
      background-color: #F44336 !important;
      color: white !important;
    }

    .delete-action {
      color: #f44336;
    }

    mat-paginator {
      border-top: 1px solid #e0e0e0;
    }

    th.mat-header-cell {
      font-weight: 600;
      color: #333;
    }
  `]
})
export class FileListComponent implements OnInit {
  files: FileInfo[] = [];
  isLoading = false;
  displayedColumns: string[] = ['icon', 'title', 'size', 'classification', 'date', 'actions'];

  constructor(
    private fileService: FileService,
    private cryptoService: CryptoService,
    private router: Router,
    private snackBar: MatSnackBar,
    private dialog: MatDialog
  ) { }

  ngOnInit() {
    this.loadFiles();
  }

  loadFiles() {
    this.isLoading = true;
    console.log('[FileList] Loading files...');

    this.fileService.listFiles().subscribe({
      next: (response: any) => {
        console.log('[FileList] Files loaded:', response);
        this.files = response.files || [];
        this.isLoading = false;
      },
      error: (error: any) => {
        console.error('[FileList] Error loading files:', error);
        this.isLoading = false;
        this.snackBar.open('❌ Error al cargar archivos', 'Cerrar', {
          duration: 5000,
          panelClass: ['error-snackbar']
        });
      }
    });
  }

  viewFile(file: FileInfo) {
    console.log('[FileList] View file:', file);
    // Show file details in snackbar for now
    this.snackBar.open(`📄 ${file.title} - ${this.formatFileSize(file.file_size)}`, 'Cerrar', {
      duration: 5000
    });
    // TODO: Create file details component and route
    // this.router.navigate(['/files', file.id]);
  }

  async downloadFile(file: FileInfo) {
    console.log('[FileList] Download file:', file);

    try {
      // Check if private key is unlocked
      if (!this.cryptoService.isUnlocked()) {
        console.log('[FileList] Private key not unlocked, requesting password');

        const dialogRef = this.dialog.open(UnlockDialogComponent, {
          width: '400px',
          disableClose: true
        });

        const password = await dialogRef.afterClosed().toPromise();

        if (!password) {
          console.log('[FileList] User cancelled password dialog');
          return;
        }

        try {
          await this.cryptoService.unlockPrivateKey(password);
          console.log('[FileList] Private key unlocked successfully');
        } catch (error: any) {
          console.error('[FileList] Error unlocking private key:', error);
          this.snackBar.open('❌ ' + error.message, 'Cerrar', {
            duration: 5000,
            panelClass: ['error-snackbar']
          });
          return;
        }
      }

      this.snackBar.open('⏳ Descargando y descifrando archivo...', '', {
        duration: 0 // Infinite until we close it
      });

      // Download encrypted file from server
      console.log('[FileList] Requesting file from server:', file.id);
      this.fileService.downloadFile(file.id).subscribe({
        next: async (response) => {
          console.log('[FileList] File data received:', response);

          try {
            const downloadData = response.download_data;

            // Decrypt file (IV is embedded in encrypted_content - first 16 bytes)
            console.log('[FileList] Decrypting file...');
            const decryptedContent = await this.cryptoService.decryptFileWithCachedKey(
              downloadData.encrypted_content,
              downloadData.encrypted_aes_key
            );

            console.log('[FileList] File decrypted, size:', decryptedContent.byteLength);

            // Create blob and download
            const blob = new Blob([decryptedContent], { type: file.mime_type });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = file.original_filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            this.snackBar.dismiss();
            this.snackBar.open(`✅ Archivo descargado: ${file.original_filename}`, 'Cerrar', {
              duration: 5000,
              panelClass: ['success-snackbar']
            });

            console.log('[FileList] File downloaded successfully');
          } catch (error: any) {
            console.error('[FileList] Decryption error:', error);
            this.snackBar.dismiss();
            this.snackBar.open('❌ Error al descifrar archivo: ' + error.message, 'Cerrar', {
              duration: 5000,
              panelClass: ['error-snackbar']
            });
          }
        },
        error: (error: any) => {
          console.error('[FileList] Download error:', error);
          this.snackBar.dismiss();
          this.snackBar.open('❌ Error al descargar archivo', 'Cerrar', {
            duration: 5000,
            panelClass: ['error-snackbar']
          });
        }
      });

    } catch (error: any) {
      console.error('[FileList] Download error:', error);
      this.snackBar.open('❌ Error: ' + error.message, 'Cerrar', {
        duration: 5000,
        panelClass: ['error-snackbar']
      });
    }
  }

  shareFile(file: FileInfo) {
    console.log('[FileList] Share file:', file);

    // Get file details including encrypted_aes_key
    this.fileService.getFileInfo(file.id).subscribe({
      next: (response) => {
        const fileData = response.file;  // Backend returns { file: {...} }
        console.log('[FileList] File info response:', JSON.stringify({
          id: fileData.id,
          title: fileData.title,
          has_encrypted_aes_key: !!fileData.encrypted_aes_key,
          encrypted_key_length: fileData.encrypted_aes_key?.length
        }, null, 2));

        const dialogRef = this.dialog.open(ShareFileDialogComponent, {
          width: '600px',
          data: {
            file: {
              id: file.id,  // Use original file.id to ensure it's always present
              title: fileData.title,
              original_filename: fileData.original_filename,
              classification_level: fileData.classification_level,
              encrypted_aes_key: fileData.encrypted_aes_key
            }
          }
        });

        dialogRef.afterClosed().subscribe(result => {
          if (result) {
            console.log('[FileList] File shared successfully');
            this.snackBar.open('✅ Archivo compartido exitosamente', 'Cerrar', {
              duration: 3000
            });
          }
        });
      },
      error: (error) => {
        console.error('[FileList] Error getting file info:', error);
        this.snackBar.open('❌ Error al obtener información del archivo', 'Cerrar', {
          duration: 3000
        });
      }
    });
  }

  deleteFile(file: FileInfo) {
    console.log('[FileList] Delete file:', file);

    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      width: '400px',
      data: {
        title: 'Eliminar Archivo',
        message: `¿Estás seguro de que deseas eliminar "${file.title}"? Esta acción no se puede deshacer.`,
        confirmText: 'Eliminar',
        cancelText: 'Cancelar',
        confirmColor: 'warn',
        icon: 'delete'
      }
    });

    dialogRef.afterClosed().subscribe(confirmed => {
      if (confirmed) {
        this.isLoading = true;
        this.fileService.deleteFile(file.id).subscribe({
          next: () => {
            console.log('[FileList] File deleted successfully:', file.id);
            this.snackBar.open(`✅ Archivo "${file.title}" eliminado`, 'Cerrar', {
              duration: 3000,
              panelClass: ['success-snackbar']
            });
            // Remove file from list without reloading
            this.files = this.files.filter(f => f.id !== file.id);
            this.isLoading = false;
          },
          error: (error: any) => {
            console.error('[FileList] Delete error:', error);
            const message = error.error?.error || 'Error al eliminar archivo';
            this.snackBar.open(`❌ ${message}`, 'Cerrar', {
              duration: 5000,
              panelClass: ['error-snackbar']
            });
            this.isLoading = false;
          }
        });
      }
    });
  }

  formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }

  formatDate(dateString: string): string {
    const date = new Date(dateString);
    return date.toLocaleDateString('es-ES', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  getFileIcon(mimeType: string): string {
    if (mimeType.startsWith('image/')) return 'image';
    if (mimeType === 'application/pdf') return 'picture_as_pdf';
    if (mimeType.includes('word') || mimeType.includes('document')) return 'description';
    if (mimeType.includes('sheet') || mimeType.includes('excel')) return 'table_chart';
    if (mimeType.startsWith('video/')) return 'videocam';
    if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('tar')) return 'folder_zip';
    return 'insert_drive_file';
  }

  getFileIconClass(mimeType: string): string {
    if (mimeType.startsWith('image/')) return 'image';
    if (mimeType === 'application/pdf') return 'pdf';
    if (mimeType.includes('word') || mimeType.includes('document') || mimeType.includes('sheet')) return 'document';
    if (mimeType.startsWith('video/')) return 'video';
    if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('tar')) return 'archive';
    return 'default';
  }
}
