import { Component, OnInit } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDialog } from '@angular/material/dialog';
import { FileService } from '../../../core/services/file.service';
import { CryptoService } from '../../../core/services/crypto.service';
import { UnlockDialogComponent } from '../../../shared/components/unlock-dialog/unlock-dialog.component';

export interface SharedFile {
    share_id: number;
    file_id: number;
    title: string;
    filename: string;
    classification_level: string;
    shared_by: string;
    shared_at: string;
    can_download: boolean;
    can_share: boolean;
    expires_at: string | null;
    file_size: number;
    mime_type: string;
}

@Component({
    selector: 'app-shared-files',
    templateUrl: './shared-files.component.html',
    styleUrls: ['./shared-files.component.scss']
})
export class SharedFilesComponent implements OnInit {
    sharedFiles: SharedFile[] = [];
    displayedColumns: string[] = ['title', 'filename', 'classification', 'shared_by', 'actions'];
    isLoading = false;

    constructor(
        private fileService: FileService,
        private cryptoService: CryptoService,
        private snackBar: MatSnackBar,
        private dialog: MatDialog
    ) { }

    ngOnInit(): void {
        this.loadSharedFiles();
    }

    loadSharedFiles(): void {
        this.isLoading = true;
        this.fileService.listSharedFiles().subscribe({
            next: (response: any) => {
                console.log('[SharedFiles] Backend response:', response);
                this.sharedFiles = response.shared_files || [];
                console.log('[SharedFiles] Loaded files:', this.sharedFiles);
                this.isLoading = false;
            },
            error: (error: any) => {
                console.error('[SharedFiles] Error loading shared files:', error);
                this.snackBar.open('❌ Error al cargar archivos compartidos', 'Cerrar', { duration: 3000 });
                this.isLoading = false;
            }
        });
    }

    async downloadSharedFile(share: SharedFile): Promise<void> {
        console.log('[SharedFiles] Downloading shared file:', share.share_id);

        // Check if private key is unlocked
        if (!this.cryptoService.isUnlocked()) {
            console.log('[SharedFiles] Private key not unlocked, requesting password');

            const dialogRef = this.dialog.open(UnlockDialogComponent, {
                width: '400px',
                disableClose: true
            });

            const password = await dialogRef.afterClosed().toPromise();

            if (!password) {
                console.log('[SharedFiles] User cancelled password dialog');
                return;
            }

            try {
                await this.cryptoService.unlockPrivateKey(password);
                console.log('[SharedFiles] Private key unlocked successfully');
            } catch (error: any) {
                console.error('[SharedFiles] Error unlocking private key:', error);
                this.snackBar.open('❌ ' + error.message, 'Cerrar', { duration: 5000 });
                return;
            }
        }

        try {
            this.isLoading = true;

            // Download encrypted file from backend
            this.fileService.downloadSharedFile(share.share_id).subscribe({
                next: async (response: any) => {
                    try {
                        console.log('[SharedFiles] Download response:', response);
                        const data = response.download_data;

                        // Decrypt file content
                        const decryptedContent = await this.cryptoService.decryptFileWithCachedKey(
                            data.encrypted_content,
                            data.encrypted_aes_key
                        );

                        // Create blob and download
                        const blob = new Blob([decryptedContent], { type: data.mime_type || 'application/octet-stream' });
                        const url = window.URL.createObjectURL(blob);
                        const link = document.createElement('a');
                        link.href = url;
                        link.download = data.original_filename || share.filename;
                        link.click();
                        window.URL.revokeObjectURL(url);

                        this.snackBar.open('✅ Archivo descargado exitosamente', 'Cerrar', { duration: 3000 });
                    } catch (decryptError) {
                        console.error('[SharedFiles] Decryption error:', decryptError);
                        this.snackBar.open('❌ Error al descifrar archivo', 'Cerrar', { duration: 3000 });
                    } finally {
                        this.isLoading = false;
                    }
                },
                error: (error) => {
                    console.error('[SharedFiles] Download error:', error);
                    const message = error.error?.error || 'Error al descargar archivo';
                    this.snackBar.open(`❌ ${message}`, 'Cerrar', { duration: 3000 });
                    this.isLoading = false;
                }
            });
        } catch (error: any) {
            console.error('[SharedFiles] Error:', error);
            this.snackBar.open(`❌ ${error.message}`, 'Cerrar', { duration: 3000 });
            this.isLoading = false;
        }
    }

    isExpired(expiresAt: string | null): boolean {
        if (!expiresAt) return false;
        return new Date(expiresAt) < new Date();
    }

    formatDate(dateString: string): string {
        return new Date(dateString).toLocaleString('es-ES');
    }
}
