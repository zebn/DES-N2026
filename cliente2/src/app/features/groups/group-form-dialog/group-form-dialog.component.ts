import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { GroupsService, Group } from '../../../core/services/groups.service';

export interface GroupFormDialogData {
  group: Group | null;
}

@Component({
  selector: 'app-group-form-dialog',
  template: `
    <h2 mat-dialog-title>
      <mat-icon>{{ isEdit ? 'edit' : 'group_add' }}</mat-icon>
      {{ isEdit ? 'Editar Grupo' : 'Nuevo Grupo' }}
    </h2>

    <mat-dialog-content>
      <form [formGroup]="form" class="group-form">
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Nombre del grupo</mat-label>
          <input matInput formControlName="name" placeholder="Ej: Equipo Backend">
          <mat-error *ngIf="form.get('name')?.hasError('required')">El nombre es obligatorio</mat-error>
          <mat-error *ngIf="form.get('name')?.hasError('maxlength')">Máximo 100 caracteres</mat-error>
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Descripción (opcional)</mat-label>
          <textarea matInput formControlName="description" rows="3"
                    placeholder="Describe el propósito del grupo"></textarea>
          <mat-error *ngIf="form.get('description')?.hasError('maxlength')">Máximo 500 caracteres</mat-error>
        </mat-form-field>
      </form>
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="cancel()" [disabled]="isSaving">Cancelar</button>
      <button mat-raised-button color="primary" (click)="save()"
              [disabled]="form.invalid || isSaving">
        <mat-spinner *ngIf="isSaving" diameter="20"></mat-spinner>
        <span *ngIf="!isSaving">{{ isEdit ? 'Guardar' : 'Crear Grupo' }}</span>
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .group-form {
      display: flex;
      flex-direction: column;
      gap: 4px;
      padding-top: 8px;
    }

    .full-width {
      width: 100%;
    }

    mat-dialog-content {
      min-width: 400px;
    }

    mat-dialog-actions button {
      min-width: 90px;
    }
  `]
})
export class GroupFormDialogComponent implements OnInit {
  form!: FormGroup;
  isEdit = false;
  isSaving = false;

  constructor(
    private fb: FormBuilder,
    private groupsService: GroupsService,
    private snackBar: MatSnackBar,
    private dialogRef: MatDialogRef<GroupFormDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: GroupFormDialogData
  ) {}

  ngOnInit(): void {
    this.isEdit = !!this.data.group;
    this.form = this.fb.group({
      name: [this.data.group?.name || '', [Validators.required, Validators.maxLength(100)]],
      description: [this.data.group?.description || '', [Validators.maxLength(500)]]
    });
  }

  save(): void {
    if (this.form.invalid) return;
    this.isSaving = true;
    const payload = {
      name: this.form.value.name.trim(),
      description: this.form.value.description?.trim() || null
    };

    const obs = this.isEdit
      ? this.groupsService.updateGroup(this.data.group!.id, payload)
      : this.groupsService.createGroup(payload);

    obs.subscribe({
      next: ({ group }) => {
        this.snackBar.open(
          this.isEdit ? 'Grupo actualizado' : 'Grupo creado',
          '', { duration: 3000 }
        );
        this.dialogRef.close(group);
      },
      error: (err) => {
        this.snackBar.open(err.error?.error || 'Error al guardar', 'Cerrar', { duration: 4000 });
        this.isSaving = false;
      }
    });
  }

  cancel(): void {
    this.dialogRef.close(null);
  }
}
