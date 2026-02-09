import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { AuthService, User } from '../../../core/services/auth.service';
import { FileService } from '../../../core/services/file.service';
import { CryptoService } from '../../../core/services/crypto.service';

export interface FileInfo {
    id: number;
    title: string;
    original_filename: string;
    classification_level: string;
    encrypted_aes_key: string;
}

@Component({
    selector: 'app-share-file-dialog',
    templateUrl: './share-file-dialog.component.html',
    styleUrls: ['./share-file-dialog.component.scss']
})
export class ShareFileDialogComponent implements OnInit {
    shareForm: FormGroup;
    users: User[] = [];
    filteredUsers: User[] = [];
    isLoading = false;
    isSharing = false;

    constructor(
        private fb: FormBuilder,
        private dialogRef: MatDialogRef<ShareFileDialogComponent>,
        @Inject(MAT_DIALOG_DATA) public data: { file: FileInfo },
        private authService: AuthService,
        private fileService: FileService,
        private cryptoService: CryptoService,
        private snackBar: MatSnackBar
    ) {
        this.shareForm = this.fb.group({
            recipient_email: ['', [Validators.required, Validators.email]],
            password: ['', Validators.required],
            can_download: [true],
            can_share: [false],
            expires_at: ['']
        });
    }

    ngOnInit(): void {
        this.loadUsers();
    }

    loadUsers(): void {
        this.isLoading = true;
        this.authService.getUsers().subscribe({
            next: (response) => {
                this.users = response.users.filter(u => u.is_active);
                this.filteredUsers = this.users;
                this.isLoading = false;
            },
            error: (error: any) => {
                // Log as warning for 403 (expected), error for others
                if (error.status === 403) {
                    console.warn('[ShareDialog] No permissions to list users - manual entry only');
                } else {
                    console.error('[ShareDialog] Error loading users:', error);
                }

                // If 403, show a more specific message
                const message = error.status === 403
                    ? '⚠️ No tienes permisos para ver la lista de usuarios. Ingresa el email manualmente.'
                    : '❌ Error al cargar usuarios';
                this.snackBar.open(message, 'Cerrar', { duration: 5000 });
                // Don't block the form - allow manual email entry
                this.isLoading = false;
            }
        });
    }

    filterUsers(searchTerm: string): void {
        if (!searchTerm) {
            this.filteredUsers = this.users;
            return;
        }

        const term = searchTerm.toLowerCase();
        this.filteredUsers = this.users.filter(u =>
            u.email?.toLowerCase().includes(term) ||
            u.nombre?.toLowerCase().includes(term) ||
            u.apellidos?.toLowerCase().includes(term)
        );
    }

    selectUser(user: User): void {
        // User email is already set via [value]="user.email"
        console.log('[ShareDialog] Selected user:', user.email);
    } async onSubmit(): Promise<void> {
        if (!this.shareForm.valid) {
            return;
        }

        this.isSharing = true;
        const formData = this.shareForm.value;

        try {
            // 1. Check if private key is unlocked
            if (!this.cryptoService.isUnlocked()) {
                await this.cryptoService.unlockPrivateKey(formData.password);
            }

            // 2. Find recipient
            const recipient = this.users.find(u => u.email === formData.recipient_email);

            // 3. Get recipient's public key (from list or fetch from backend)
            let recipientPublicKey: string;
            if (recipient?.public_key) {
                recipientPublicKey = recipient.public_key;
            } else {
                // Fetch recipient's public key from backend
                console.log('[ShareDialog] Fetching public key for:', formData.recipient_email);
                try {
                    const recipientData = await this.authService.getUserPublicKey(formData.recipient_email).toPromise();
                    if (!recipientData || !recipientData.public_key) {
                        throw new Error('No se pudo obtener la clave pública del destinatario');
                    }
                    if (!recipientData.is_active) {
                        throw new Error('El usuario destinatario no está activo');
                    }
                    recipientPublicKey = recipientData.public_key;
                    console.log('[ShareDialog] Fetched public key successfully');
                } catch (error: any) {
                    throw new Error(error.error?.error || 'Error al obtener clave pública del destinatario');
                }
            }

            // 4. Decrypt the AES key with our private key
            const encryptedAesKeyBuffer = this.cryptoService.base64ToArrayBuffer(this.data.file.encrypted_aes_key);
            const privateKey = this.cryptoService.getPrivateKey();
            if (!privateKey) {
                throw new Error('Clave privada no disponible');
            }

            console.log('[ShareDialog] Decrypting AES key with owner private key...');
            const aesKeyBuffer = await this.cryptoService.rsaDecrypt(encryptedAesKeyBuffer, privateKey);
            console.log('[ShareDialog] AES key decrypted, length:', aesKeyBuffer.byteLength);

            // 5. Import recipient's public key
            const recipientPublicKeyCrypto = await this.cryptoService.importPublicKey(recipientPublicKey);

            // 6. Re-encrypt AES key with recipient's public key
            console.log('[ShareDialog] Re-encrypting AES key with recipient public key...');
            const encryptedAesKeyForRecipient = await this.cryptoService.rsaEncrypt(aesKeyBuffer, recipientPublicKeyCrypto);
            const encryptedAesKeyForRecipientBase64 = this.cryptoService.arrayBufferToBase64(encryptedAesKeyForRecipient);
            console.log('[ShareDialog] Re-encrypted key length:', encryptedAesKeyForRecipientBase64.length);

            // 7. Prepare share data
            const shareData = {
                recipient_email: formData.recipient_email,
                password: formData.password,
                encrypted_aes_key_for_recipient: encryptedAesKeyForRecipientBase64,
                can_download: formData.can_download,
                can_share: formData.can_share,
                expires_at: formData.expires_at ? new Date(formData.expires_at).toISOString() : undefined
            };

            console.log('[ShareDialog] Sending share data:', JSON.stringify({
                recipient_email: shareData.recipient_email,
                can_download: shareData.can_download,
                can_share: shareData.can_share,
                expires_at: shareData.expires_at,
                has_encrypted_key: !!shareData.encrypted_aes_key_for_recipient,
                encrypted_key_length: shareData.encrypted_aes_key_for_recipient?.length
            }, null, 2));

            // 7. Send to server
            this.fileService.shareFile(this.data.file.id, shareData).subscribe({
                next: (response) => {
                    this.snackBar.open('✅ Archivo compartido exitosamente', 'Cerrar', { duration: 3000 });
                    this.dialogRef.close(true);
                },
                error: (error) => {
                    console.error('[ShareDialog] Error sharing file:', JSON.stringify({
                        status: error.status,
                        statusText: error.statusText,
                        message: error.error?.error || error.message,
                        fullError: error.error
                    }, null, 2));
                    const message = error.error?.error || 'Error al compartir archivo';
                    this.snackBar.open(`❌ ${message}`, 'Cerrar', { duration: 5000 });
                    this.isSharing = false;
                }
            });

        } catch (error: any) {
            console.error('Error during share process:', error);
            this.snackBar.open(`❌ ${error.message}`, 'Cerrar', { duration: 5000 });
            this.isSharing = false;
        }
    }

    onCancel(): void {
        this.dialogRef.close(false);
    }
}
