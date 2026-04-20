import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { SecretsService, Folder } from '../../../core/services/secrets.service';

@Component({
  selector: 'app-folder-dialog',
  template: `
    <h2 mat-dialog-title>
      <mat-icon>{{ isEditMode ? 'edit' : 'create_new_folder' }}</mat-icon>
      {{ isEditMode ? 'Editar' : 'Nueva' }} Carpeta
    </h2>

    <mat-dialog-content>
      <form [formGroup]="form">
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Nombre de la carpeta</mat-label>
          <input matInput formControlName="name" placeholder="Ej: Cuentas Personales" maxlength="255" required>
          <mat-hint align="end">{{ form.get('name')?.value?.length || 0 }}/255</mat-hint>
          <mat-error *ngIf="form.get('name')?.hasError('required')">
            El nombre es requerido
          </mat-error>
          <mat-error *ngIf="form.get('name')?.hasError('maxlength')">
            El nombre no puede exceder 255 caracteres
          </mat-error>
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Carpeta padre (opcional)</mat-label>
          <mat-select formControlName="parent_id">
            <mat-option [value]="null">Ninguna (Raíz)</mat-option>
            <mat-option *ngFor="let folder of availableFolders" [value]="folder.id">
              {{ getFolderPath(folder) }}
            </mat-option>
          </mat-select>
          <mat-hint>Selecciona una carpeta padre para organizar jerárquicamente</mat-hint>
        </mat-form-field>
      </form>
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="dialogRef.close(false)">Cancelar</button>
      <button mat-raised-button color="primary" (click)="save()" [disabled]="!form.valid || isSaving">
        <mat-icon>{{ isEditMode ? 'save' : 'create_new_folder' }}</mat-icon>
        {{ isSaving ? 'Guardando...' : (isEditMode ? 'Guardar' : 'Crear') }}
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    mat-dialog-content {
      min-width: 400px;
      padding-top: 16px;
    }

    .full-width {
      width: 100%;
      margin-bottom: 12px;
    }

    mat-dialog-actions {
      padding: 16px 24px;
    }
  `]
})
export class FolderDialogComponent implements OnInit {
  form: FormGroup;
  isEditMode = false;
  isSaving = false;
  availableFolders: Folder[] = [];

  constructor(
    public dialogRef: MatDialogRef<FolderDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { folder?: Folder; folders: Folder[] },
    private fb: FormBuilder,
    private secretsService: SecretsService,
    private snackBar: MatSnackBar,
  ) {
    this.isEditMode = !!data.folder;
    this.form = this.fb.group({
      name: [data.folder?.name || '', [Validators.required, Validators.maxLength(255)]],
      parent_id: [data.folder?.parent_id || null]
    });

    // Filter out the current folder from available parents to prevent circular references
    this.availableFolders = data.folders.filter(f => f.id !== data.folder?.id);
  }

  ngOnInit(): void {}

  getFolderPath(folder: Folder): string {
    const path: string[] = [];
    let current: Folder | undefined = folder;
    const allFolders = this.data.folders;

    // Build path from current folder to root
    while (current) {
      path.unshift(current.name);
      current = allFolders.find(f => f.id === current?.parent_id);
    }

    return path.join(' / ');
  }

  save(): void {
    if (!this.form.valid) return;

    this.isSaving = true;
    const formValue = this.form.value;

    if (this.isEditMode) {
      // Update existing folder
      this.secretsService.updateFolder(this.data.folder!.id, formValue).subscribe({
        next: () => {
          this.isSaving = false;
          this.dialogRef.close(true);
        },
        error: (err) => {
          this.isSaving = false;
          this.snackBar.open(
            err.error?.error || 'Error actualizando carpeta',
            'Cerrar',
            { duration: 5000 }
          );
        }
      });
    } else {
      // Create new folder
      this.secretsService.createFolder(formValue.name, formValue.parent_id).subscribe({
        next: () => {
          this.isSaving = false;
          this.dialogRef.close(true);
        },
        error: (err) => {
          this.isSaving = false;
          this.snackBar.open(
            err.error?.error || 'Error creando carpeta',
            'Cerrar',
            { duration: 5000 }
          );
        }
      });
    }
  }
}
