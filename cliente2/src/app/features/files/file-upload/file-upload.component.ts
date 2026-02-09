import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { FileService } from '../../../core/services/file.service';
import { CryptoService } from '../../../core/services/crypto.service';
import { AuthService } from '../../../core/services/auth.service';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDialog } from '@angular/material/dialog';
import { UnlockDialogComponent } from '../../../shared/components/unlock-dialog/unlock-dialog.component';

@Component({
  selector: 'app-file-upload',
  template: `
    <div class="upload-container">
      <mat-card>
        <mat-card-header>
          <mat-card-title>
            <mat-icon class="title-icon">cloud_upload</mat-icon>
            Subir Archivo Cifrado
          </mat-card-title>
          <mat-card-subtitle>
            El archivo será cifrado de extremo a extremo con AES-256
          </mat-card-subtitle>
        </mat-card-header>
        
        <mat-card-content>
          <form [formGroup]="uploadForm" (ngSubmit)="onSubmit()" class="upload-form">
            
            <!-- File Selection -->
            <div class="file-drop-zone" 
                 (click)="fileInput.click()"
                 (dragover)="onDragOver($event)"
                 (drop)="onDrop($event)"
                 [class.drag-over]="isDragOver">
              <mat-icon class="upload-icon">upload_file</mat-icon>
              <p class="drop-text" *ngIf="!selectedFile">
                Arrastra un archivo aquí o haz clic para seleccionar
              </p>
              <div class="selected-file-info" *ngIf="selectedFile">
                <mat-icon>description</mat-icon>
                <div>
                  <p class="file-name">{{ selectedFile.name }}</p>
                  <p class="file-size">{{ formatFileSize(selectedFile.size) }}</p>
                </div>
                <button mat-icon-button type="button" (click)="removeFile($event)" class="remove-btn">
                  <mat-icon>close</mat-icon>
                </button>
              </div>
              <input #fileInput type="file" (change)="onFileSelected($event)" hidden>
            </div>

            <!-- Title -->
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Título del archivo</mat-label>
              <input matInput formControlName="title" placeholder="Informe Confidencial" required>
              <mat-icon matPrefix>title</mat-icon>
              <mat-error *ngIf="uploadForm.get('title')?.hasError('required')">
                El título es obligatorio
              </mat-error>
            </mat-form-field>

            <!-- Description -->
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Descripción (opcional)</mat-label>
              <textarea matInput formControlName="description" rows="3" 
                        placeholder="Descripción del contenido del archivo"></textarea>
              <mat-icon matPrefix>notes</mat-icon>
            </mat-form-field>

            <!-- Classification Level -->
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Nivel de Clasificación</mat-label>
              <mat-select formControlName="classification_level" required>
                <mat-option value="PUBLIC">PÚBLICO</mat-option>
                <mat-option value="INTERNAL">INTERNO</mat-option>
                <mat-option value="CONFIDENTIAL">CONFIDENCIAL</mat-option>
                <mat-option value="SECRET">SECRETO</mat-option>
                <mat-option value="TOP_SECRET">TOP SECRET</mat-option>
              </mat-select>
              <mat-icon matPrefix>security</mat-icon>
              <mat-error *ngIf="uploadForm.get('classification_level')?.hasError('required')">
                Selecciona un nivel de clasificación
              </mat-error>
            </mat-form-field>

            <!-- Encryption Status -->
            <div class="encryption-status" *ngIf="isEncrypting">
              <mat-spinner diameter="20"></mat-spinner>
              <span>Cifrando archivo...</span>
            </div>

            <!-- Progress Bar -->
            <mat-progress-bar *ngIf="uploadProgress > 0 && uploadProgress < 100" 
                              mode="determinate" 
                              [value]="uploadProgress">
            </mat-progress-bar>

            <!-- Actions -->
            <div class="form-actions">
              <button mat-button type="button" routerLink="/files">
                <mat-icon>arrow_back</mat-icon>
                Cancelar
              </button>
              <button mat-raised-button color="primary" type="submit" 
                      [disabled]="!uploadForm.valid || !selectedFile || isUploading || isEncrypting">
                <mat-icon>lock</mat-icon>
                Cifrar y Subir
              </button>
            </div>
          </form>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .upload-container {
      max-width: 800px;
      margin: 0 auto;
      padding: 20px;
    }
    
    mat-card-title {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .title-icon {
      color: #3f51b5;
    }

    .upload-form {
      display: flex;
      flex-direction: column;
      gap: 20px;
      margin-top: 20px;
    }

    .file-drop-zone {
      border: 2px dashed #ccc;
      border-radius: 8px;
      padding: 40px;
      text-align: center;
      cursor: pointer;
      transition: all 0.3s ease;
      background-color: #fafafa;
    }

    .file-drop-zone:hover {
      border-color: #3f51b5;
      background-color: #f5f5f5;
    }

    .file-drop-zone.drag-over {
      border-color: #3f51b5;
      background-color: #e3f2fd;
    }

    .upload-icon {
      font-size: 48px;
      width: 48px;
      height: 48px;
      color: #999;
      margin-bottom: 10px;
    }

    .drop-text {
      color: #666;
      font-size: 16px;
    }

    .selected-file-info {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px;
      background-color: white;
      border-radius: 4px;
      border: 1px solid #ddd;
    }

    .selected-file-info mat-icon {
      color: #3f51b5;
    }

    .selected-file-info > div {
      flex: 1;
      text-align: left;
    }

    .file-name {
      margin: 0;
      font-weight: 500;
      color: #333;
    }

    .file-size {
      margin: 4px 0 0;
      font-size: 12px;
      color: #666;
    }

    .remove-btn {
      color: #f44336;
    }

    .full-width {
      width: 100%;
    }

    .encryption-status {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px;
      background-color: #fff3e0;
      border-radius: 4px;
      color: #e65100;
    }

    .form-actions {
      display: flex;
      justify-content: space-between;
      margin-top: 20px;
    }

    mat-progress-bar {
      margin: 10px 0;
    }
  `]
})
export class FileUploadComponent implements OnInit {
  uploadForm: FormGroup;
  selectedFile: File | null = null;
  isDragOver = false;
  isUploading = false;
  isEncrypting = false;
  uploadProgress = 0;

  constructor(
    private fb: FormBuilder,
    private fileService: FileService,
    private cryptoService: CryptoService,
    private authService: AuthService,
    private router: Router,
    private snackBar: MatSnackBar,
    private dialog: MatDialog
  ) {
    this.uploadForm = this.fb.group({
      title: ['', Validators.required],
      description: [''],
      classification_level: ['CONFIDENTIAL', Validators.required]
    });
  }

  ngOnInit(): void {
  }

  onDragOver(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.isDragOver = true;
  }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.isDragOver = false;

    const files = event.dataTransfer?.files;
    if (files && files.length > 0) {
      this.selectedFile = files[0];
    }
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.selectedFile = input.files[0];
    }
  }

  removeFile(event: Event): void {
    event.stopPropagation();
    this.selectedFile = null;
  }

  formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }

  async onSubmit(): Promise<void> {
    if (!this.uploadForm.valid || !this.selectedFile) {
      return;
    }

    try {
      // Verificar si la clave privada está desbloqueada
      if (!this.cryptoService.isUnlocked()) {
        console.log('[FileUpload] Key not unlocked, requesting password');

        // Pedir contraseña al usuario
        const password = await this.requestPassword();
        if (!password) {
          console.log('[FileUpload] User cancelled password dialog');
          return; // Usuario canceló
        }

        try {
          console.log('[FileUpload] Attempting to unlock private key');
          await this.cryptoService.unlockPrivateKey(password);
          console.log('[FileUpload] Private key unlocked successfully');
          this.snackBar.open('🔓 Clave privada desbloqueada', '', {
            duration: 2000
          });
        } catch (error: any) {
          console.error('[FileUpload] Error unlocking private key:', error);
          this.snackBar.open('❌ ' + error.message, 'Cerrar', {
            duration: 5000,
            panelClass: ['error-snackbar']
          });
          return;
        }
      } else {
        console.log('[FileUpload] Key already unlocked, proceeding with encryption');
      }

      this.isEncrypting = true;
      this.isUploading = true;
      this.uploadProgress = 0;

      // Leer el archivo
      const fileContent = await this.readFileAsArrayBuffer(this.selectedFile);
      console.log('[FileUpload] File read successfully, size:', fileContent.byteLength);

      // Encriptar el archivo
      console.log('[FileUpload] Starting encryption');
      const encryptedData = await this.cryptoService.encryptFileForUpload(
        new Uint8Array(fileContent)
      );
      console.log('[FileUpload] File encrypted successfully');

      this.isEncrypting = false;
      this.uploadProgress = 10;

      // Preparar datos para enviar
      const uploadData = {
        title: this.uploadForm.value.title,
        description: this.uploadForm.value.description,
        original_filename: this.selectedFile.name,
        file_size: this.selectedFile.size,
        mime_type: this.selectedFile.type || 'application/octet-stream',
        classification_level: this.uploadForm.value.classification_level,
        encrypted_content: encryptedData.encrypted_content,
        encrypted_aes_key: encryptedData.encrypted_aes_key,
        counter: encryptedData.counter,
        file_hash: encryptedData.file_hash,
        digital_signature: encryptedData.digital_signature
      };

      console.log('[FileUpload] Upload data prepared, encrypted content size:', encryptedData.encrypted_content.length);
      console.log('[FileUpload] Hash:', encryptedData.file_hash);
      console.log('[FileUpload] Hash length (chars):', encryptedData.file_hash.length);
      console.log('[FileUpload] Signature (base64) length:', encryptedData.digital_signature.length);
      console.log('[FileUpload] Signature preview:', encryptedData.digital_signature.substring(0, 50));

      this.uploadProgress = 30;

      // Enviar al servidor
      console.log('[FileUpload] Uploading to server');
      this.fileService.uploadFile(uploadData).subscribe({
        next: (response) => {
          console.log('[FileUpload] Upload successful:', response);
          this.uploadProgress = 100;
          this.snackBar.open('✅ Archivo cifrado y subido correctamente', 'Cerrar', {
            duration: 5000,
            panelClass: ['success-snackbar']
          });

          setTimeout(() => {
            this.router.navigate(['/files']);
          }, 1500);
        },
        error: (error) => {
          console.error('[FileUpload] Upload error:', error);
          console.error('[FileUpload] Error details:', JSON.stringify({
            status: error.status,
            statusText: error.statusText,
            message: error.message,
            error: error.error,
            url: error.url
          }, null, 2));

          let errorMessage = 'Error desconocido';
          if (error.error?.error) {
            errorMessage = error.error.error;
          } else if (error.error?.message) {
            errorMessage = error.error.message;
          } else if (error.message) {
            errorMessage = error.message;
          } else if (error.statusText) {
            errorMessage = error.statusText;
          }

          this.snackBar.open('❌ Error al subir el archivo: ' + errorMessage, 'Cerrar', {
            duration: 7000,
            panelClass: ['error-snackbar']
          });
          this.isUploading = false;
          this.uploadProgress = 0;
        }
      });

    } catch (error: any) {
      console.error('[FileUpload] Encryption error:', error);
      console.error('[FileUpload] Error stack:', error.stack);
      this.snackBar.open('❌ Error al cifrar el archivo: ' + error.message, 'Cerrar', {
        duration: 7000,
        panelClass: ['error-snackbar']
      });
      this.isEncrypting = false;
      this.isUploading = false;
      this.uploadProgress = 0;
    }
  }

  private async requestPassword(): Promise<string | null> {
    const dialogRef = this.dialog.open(UnlockDialogComponent, {
      width: '450px',
      disableClose: true
    });

    return dialogRef.afterClosed().toPromise();
  }

  private readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(file);
    });
  }
}
