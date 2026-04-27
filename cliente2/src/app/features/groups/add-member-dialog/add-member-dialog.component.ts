import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { HttpClient } from '@angular/common/http';
import { GroupsService, GroupRole } from '../../../core/services/groups.service';
import { environment } from '../../../../environments/environment';

export interface AddMemberDialogData {
  groupId: string;
  existingUserIds: number[];
}

interface UserOption {
  id: number;
  email: string;
  nombre: string;
  apellidos: string;
}

@Component({
  selector: 'app-add-member-dialog',
  template: `
    <h2 mat-dialog-title>
      <mat-icon>person_add</mat-icon>
      Añadir Miembro
    </h2>

    <mat-dialog-content>
      <form [formGroup]="form" class="member-form">

        <!-- User search -->
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Buscar usuario</mat-label>
          <input matInput formControlName="search" placeholder="Nombre o email..."
                 (input)="filterUsers()">
          <mat-icon matSuffix>search</mat-icon>
        </mat-form-field>

        <!-- User list -->
        <div class="user-list" *ngIf="filteredUsers.length > 0">
          <mat-radio-group formControlName="userId" class="user-radio-group">
            <mat-radio-button *ngFor="let u of filteredUsers" [value]="u.id" class="user-option">
              <div class="user-option-content">
                <mat-icon class="user-icon">account_circle</mat-icon>
                <div>
                  <div class="user-name">{{ u.nombre }} {{ u.apellidos }}</div>
                  <div class="user-email">{{ u.email }}</div>
                </div>
              </div>
            </mat-radio-button>
          </mat-radio-group>
        </div>

        <div *ngIf="filteredUsers.length === 0 && form.value.search" class="no-results">
          <mat-icon>search_off</mat-icon>
          No se encontraron usuarios
        </div>

        <!-- Role selection -->
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Rol en el grupo</mat-label>
          <mat-select formControlName="role">
            <mat-option value="MEMBER">Miembro</mat-option>
            <mat-option value="READONLY">Solo lectura</mat-option>
            <mat-option value="ADMIN">Admin</mat-option>
            <mat-option value="OWNER">Propietario</mat-option>
          </mat-select>
        </mat-form-field>
      </form>
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="cancel()" [disabled]="isAdding">Cancelar</button>
      <button mat-raised-button color="primary"
              [disabled]="!form.value.userId || isAdding"
              (click)="addMember()">
        <mat-spinner *ngIf="isAdding" diameter="20"></mat-spinner>
        <span *ngIf="!isAdding">Añadir</span>
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
      min-width: 440px;
    }

    .member-form {
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding-top: 8px;
    }

    .full-width {
      width: 100%;
    }

    .user-list {
      max-height: 200px;
      overflow-y: auto;
      border: 1px solid rgba(0,0,0,0.12);
      border-radius: 4px;
      padding: 4px 0;
    }

    .user-radio-group {
      display: flex;
      flex-direction: column;
    }

    .user-option {
      padding: 6px 12px;
    }

    .user-option:hover {
      background: rgba(63,81,181,0.05);
    }

    .user-option-content {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .user-icon {
      font-size: 28px;
      width: 28px;
      height: 28px;
      color: #9e9e9e;
    }

    .user-name {
      font-weight: 500;
      font-size: 14px;
    }

    .user-email {
      font-size: 12px;
      color: rgba(0,0,0,0.5);
    }

    .no-results {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px;
      color: rgba(0,0,0,0.5);
      font-size: 14px;
    }

    mat-dialog-actions button {
      min-width: 80px;
    }
  `]
})
export class AddMemberDialogComponent implements OnInit {
  form!: FormGroup;
  allUsers: UserOption[] = [];
  filteredUsers: UserOption[] = [];
  isAdding = false;

  constructor(
    private fb: FormBuilder,
    private http: HttpClient,
    private groupsService: GroupsService,
    private snackBar: MatSnackBar,
    private dialogRef: MatDialogRef<AddMemberDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: AddMemberDialogData
  ) {}

  ngOnInit(): void {
    this.form = this.fb.group({
      search: [''],
      userId: [null, Validators.required],
      role: ['MEMBER']
    });

    this.loadUsers();
  }

  loadUsers(): void {
    this.http.get<{ users: UserOption[] }>(`${environment.apiUrl}/api/auth/users`).subscribe({
      next: ({ users }) => {
        this.allUsers = users.filter(u => !this.data.existingUserIds.includes(u.id));
        this.filteredUsers = this.allUsers.slice(0, 20);
      },
      error: () => {
        this.snackBar.open('Error al cargar usuarios', 'Cerrar', { duration: 3000 });
      }
    });
  }

  filterUsers(): void {
    const q = (this.form.value.search || '').toLowerCase();
    if (!q) {
      this.filteredUsers = this.allUsers.slice(0, 20);
      return;
    }
    this.filteredUsers = this.allUsers.filter(u =>
      u.email.toLowerCase().includes(q) ||
      u.nombre.toLowerCase().includes(q) ||
      u.apellidos.toLowerCase().includes(q)
    ).slice(0, 20);
    // Reset selection if current user not in filtered list
    const currentId = this.form.value.userId;
    if (currentId && !this.filteredUsers.find(u => u.id === currentId)) {
      this.form.patchValue({ userId: null });
    }
  }

  addMember(): void {
    const userId = this.form.value.userId;
    if (!userId) return;
    this.isAdding = true;
    this.groupsService.addMember(this.data.groupId, {
      user_id: userId,
      role_in_group: this.form.value.role as GroupRole
    }).subscribe({
      next: () => {
        this.snackBar.open('Miembro añadido', '', { duration: 2000 });
        this.dialogRef.close(true);
      },
      error: (err) => {
        this.snackBar.open(err.error?.error || 'Error al añadir miembro', 'Cerrar', { duration: 4000 });
        this.isAdding = false;
      }
    });
  }

  cancel(): void {
    this.dialogRef.close(null);
  }
}
