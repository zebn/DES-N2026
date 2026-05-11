import { Component, OnInit, ViewChild } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDialog } from '@angular/material/dialog';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTableDataSource } from '@angular/material/table';
import { AuthService, User, UserRole } from '../../../core/services/auth.service';
import { ConfirmDialogComponent } from '../../../shared/components/confirm-dialog/confirm-dialog.component';

@Component({
  selector: 'app-admin-panel',
  template: `
    <div class="admin-container">
      <h2 class="admin-title">
        <mat-icon>admin_panel_settings</mat-icon>
        Panel de Administración
      </h2>

      <!-- Stats Cards -->
      <div class="stats-grid">
        <mat-card class="stat-card">
          <mat-icon class="stat-icon users">people</mat-icon>
          <div class="stat-info">
            <span class="stat-value">{{ users.length }}</span>
            <span class="stat-label">Usuarios totales</span>
          </div>
        </mat-card>
        <mat-card class="stat-card">
          <mat-icon class="stat-icon active">check_circle</mat-icon>
          <div class="stat-info">
            <span class="stat-value">{{ getActiveCount() }}</span>
            <span class="stat-label">Activos</span>
          </div>
        </mat-card>
        <mat-card class="stat-card">
          <mat-icon class="stat-icon admins">shield</mat-icon>
          <div class="stat-info">
            <span class="stat-value">{{ getRoleCount('ADMIN') }}</span>
            <span class="stat-label">Administradores</span>
          </div>
        </mat-card>
        <mat-card class="stat-card">
          <mat-icon class="stat-icon twofa">verified_user</mat-icon>
          <div class="stat-info">
            <span class="stat-value">{{ get2FACount() }}</span>
            <span class="stat-label">Con 2FA</span>
          </div>
        </mat-card>
      </div>

      <!-- Loading -->
      <div class="loading" *ngIf="isLoading">
        <mat-spinner diameter="40"></mat-spinner>
        <span>Cargando usuarios...</span>
      </div>

      <!-- Users Table -->
      <mat-card class="table-card" *ngIf="!isLoading">
        <mat-card-header>
          <mat-card-title>
            <mat-icon>group</mat-icon>
            Gestión de Usuarios
          </mat-card-title>
        </mat-card-header>

        <mat-card-content>
          <div class="table-container">
            <table mat-table [dataSource]="dataSource" matSort class="users-table">
              <!-- ID -->
              <ng-container matColumnDef="id">
                <th mat-header-cell *matHeaderCellDef mat-sort-header>ID</th>
                <td mat-cell *matCellDef="let user">{{ user.id }}</td>
              </ng-container>

              <!-- Name -->
              <ng-container matColumnDef="nombre">
                <th mat-header-cell *matHeaderCellDef mat-sort-header>Nombre</th>
                <td mat-cell *matCellDef="let user">{{ user.nombre }} {{ user.apellidos }}</td>
              </ng-container>

              <!-- Email -->
              <ng-container matColumnDef="email">
                <th mat-header-cell *matHeaderCellDef mat-sort-header>Email</th>
                <td mat-cell *matCellDef="let user">{{ user.email }}</td>
              </ng-container>

              <!-- Role -->
              <ng-container matColumnDef="role">
                <th mat-header-cell *matHeaderCellDef mat-sort-header>Rol</th>
                <td mat-cell *matCellDef="let user">
                  <mat-chip [class]="'role-chip role-' + user.role?.toLowerCase()">
                    <mat-icon>{{ getRoleIcon(user.role) }}</mat-icon>
                    {{ getRoleLabel(user.role) }}
                  </mat-chip>
                </td>
              </ng-container>

              <!-- Status -->
              <ng-container matColumnDef="is_active">
                <th mat-header-cell *matHeaderCellDef mat-sort-header>Estado</th>
                <td mat-cell *matCellDef="let user">
                  <mat-chip [class]="user.is_active ? 'status-active' : 'status-inactive'">
                    <mat-icon>{{ user.is_active ? 'check_circle' : 'cancel' }}</mat-icon>
                    {{ user.is_active ? 'Activo' : 'Inactivo' }}
                  </mat-chip>
                </td>
              </ng-container>

              <!-- 2FA -->
              <ng-container matColumnDef="is_2fa_enabled">
                <th mat-header-cell *matHeaderCellDef mat-sort-header>2FA</th>
                <td mat-cell *matCellDef="let user">
                  <mat-icon [class]="user.is_2fa_enabled ? 'twofa-on' : 'twofa-off'"
                            [matTooltip]="user.is_2fa_enabled ? '2FA habilitado' : '2FA deshabilitado'">
                    {{ user.is_2fa_enabled ? 'verified_user' : 'shield' }}
                  </mat-icon>
                </td>
              </ng-container>

              <!-- Actions -->
              <ng-container matColumnDef="actions">
                <th mat-header-cell *matHeaderCellDef>Acciones</th>
                <td mat-cell *matCellDef="let user">
                  <ng-container *ngIf="!isSelf(user)">
                    <!-- Change Role -->
                    <button mat-icon-button [matMenuTriggerFor]="roleMenu"
                            matTooltip="Cambiar rol">
                      <mat-icon>swap_horiz</mat-icon>
                    </button>
                    <mat-menu #roleMenu="matMenu">
                      <button mat-menu-item *ngFor="let role of availableRoles"
                              [disabled]="user.role === role"
                              (click)="changeRole(user, role)">
                        <mat-icon>{{ getRoleIcon(role) }}</mat-icon>
                        <span>{{ getRoleLabel(role) }}</span>
                      </button>
                    </mat-menu>

                    <!-- Activate/Deactivate -->
                    <button mat-icon-button
                            [matTooltip]="user.is_active ? 'Desactivar' : 'Activar'"
                            [color]="user.is_active ? 'warn' : 'primary'"
                            (click)="toggleUserStatus(user)">
                      <mat-icon>{{ user.is_active ? 'person_off' : 'person_add' }}</mat-icon>
                    </button>
                  </ng-container>
                  <span *ngIf="isSelf(user)" class="self-label">Tú</span>
                </td>
              </ng-container>

              <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
              <tr mat-row *matRowDef="let row; columns: displayedColumns;"
                  [class.self-row]="isSelf(row)"></tr>
            </table>
          </div>

          <mat-paginator [pageSizeOptions]="[5, 10, 25]"
                         showFirstLastButtons>
          </mat-paginator>
        </mat-card-content>
      </mat-card>

      <!-- Roles Reference -->
      <mat-card class="roles-card">
        <mat-card-header>
          <mat-card-title>
            <mat-icon>security</mat-icon>
            Referencia de Roles
          </mat-card-title>
        </mat-card-header>
        <mat-card-content>
          <div class="roles-grid">
            <div class="role-info" *ngFor="let role of rolesInfo">
              <mat-chip [class]="'role-chip role-' + role.name.toLowerCase()">
                <mat-icon>{{ role.icon }}</mat-icon>
                {{ role.label }}
              </mat-chip>
              <p>{{ role.description }}</p>
            </div>
          </div>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .admin-container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }

    .admin-title {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 24px;
      font-weight: 500;
      margin-bottom: 24px;
      color: #333;
    }

    .admin-title mat-icon {
      font-size: 32px;
      width: 32px;
      height: 32px;
      color: #3f51b5;
    }

    /* Stats */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat-card {
      display: flex;
      flex-direction: row;
      align-items: center;
      padding: 20px !important;
      gap: 16px;
    }

    .stat-icon {
      font-size: 40px;
      width: 40px;
      height: 40px;
    }

    .stat-icon.users { color: #3f51b5; }
    .stat-icon.active { color: #4caf50; }
    .stat-icon.admins { color: #ff9800; }
    .stat-icon.twofa { color: #9c27b0; }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat-value {
      font-size: 28px;
      font-weight: 700;
      line-height: 1;
    }

    .stat-label {
      font-size: 13px;
      color: #666;
      margin-top: 4px;
    }

    /* Loading */
    .loading {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 16px;
      padding: 60px;
      color: #666;
    }

    /* Table */
    .table-card {
      margin-bottom: 24px;
    }

    .table-card mat-card-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 18px;
    }

    .table-container {
      overflow-x: auto;
    }

    .users-table {
      width: 100%;
    }

    .self-row {
      background-color: rgba(63, 81, 181, 0.04);
    }

    .self-label {
      font-size: 12px;
      color: #999;
      font-style: italic;
    }

    /* Role chips */
    .role-chip {
      font-size: 12px !important;
    }

    .role-chip mat-icon {
      font-size: 16px !important;
      width: 16px !important;
      height: 16px !important;
      margin-right: 4px;
    }

    .role-admin {
      background-color: #fff3e0 !important;
      color: #e65100 !important;
    }

    .role-manager {
      background-color: #e8eaf6 !important;
      color: #283593 !important;
    }

    .role-user {
      background-color: #e8f5e9 !important;
      color: #2e7d32 !important;
    }

    .role-auditor {
      background-color: #f3e5f5 !important;
      color: #6a1b9a !important;
    }

    /* Status */
    .status-active {
      background-color: #e8f5e9 !important;
      color: #2e7d32 !important;
    }

    .status-inactive {
      background-color: #ffebee !important;
      color: #c62828 !important;
    }

    .status-active mat-icon,
    .status-inactive mat-icon {
      font-size: 16px !important;
      width: 16px !important;
      height: 16px !important;
      margin-right: 4px;
    }

    /* 2FA icons */
    .twofa-on { color: #4caf50; }
    .twofa-off { color: #ccc; }

    /* Roles reference */
    .roles-card mat-card-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 18px;
    }

    .roles-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 16px;
      margin-top: 8px;
    }

    .role-info {
      padding: 12px;
      border: 1px solid #eee;
      border-radius: 8px;
    }

    .role-info p {
      margin: 8px 0 0;
      font-size: 13px;
      color: #555;
    }
  `]
})
export class AdminPanelComponent implements OnInit {
  users: User[] = [];
  isLoading = true;
  dataSource = new MatTableDataSource<User>();
  displayedColumns = ['id', 'nombre', 'email', 'role', 'is_active', 'is_2fa_enabled', 'actions'];
  availableRoles: UserRole[] = ['ADMIN', 'MANAGER', 'USER', 'AUDITOR'];

  rolesInfo = [
    { name: 'ADMIN', label: 'Administrador', icon: 'admin_panel_settings',
      description: 'CRUD usuarios, grupos, auditorías globales, gestionar roles, backup/restore, CRUD secretos propios.' },
    { name: 'MANAGER', label: 'Gestor', icon: 'manage_accounts',
      description: 'Crear grupos, gestionar miembros de sus grupos, compartir secretos, CRUD secretos propios.' },
    { name: 'USER', label: 'Usuario', icon: 'person',
      description: 'CRUD secretos propios, compartir con usuarios/grupos donde participa, ver auditorías propias.' },
    { name: 'AUDITOR', label: 'Auditor', icon: 'visibility',
      description: 'Solo lectura de auditorías y logs (sin acceso a secretos), generar informes de actividad.' }
  ];

  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;

  private currentUserId: number | null = null;

  constructor(
    private authService: AuthService,
    private snackBar: MatSnackBar,
    private dialog: MatDialog
  ) { }

  ngOnInit(): void {
    this.authService.currentUser$.subscribe(u => {
      this.currentUserId = u?.id ?? null;
    });
    this.loadUsers();
  }

  loadUsers(): void {
    this.isLoading = true;
    this.authService.listUsers().subscribe({
      next: (res: any) => {
        this.users = res.users || [];
        this.dataSource.data = this.users;
        setTimeout(() => {
          this.dataSource.paginator = this.paginator;
          this.dataSource.sort = this.sort;
        });
        this.isLoading = false;
      },
      error: (err) => {
        this.isLoading = false;
        this.snackBar.open('Error cargando usuarios', 'Cerrar', { duration: 3000 });
      }
    });
  }

  isSelf(user: User): boolean {
    return user.id === this.currentUserId;
  }

  getActiveCount(): number {
    return this.users.filter(u => u.is_active).length;
  }

  getRoleCount(role: string): number {
    return this.users.filter(u => u.role === role).length;
  }

  get2FACount(): number {
    return this.users.filter(u => u.is_2fa_enabled).length;
  }

  getRoleIcon(role: string): string {
    const icons: Record<string, string> = {
      'ADMIN': 'admin_panel_settings',
      'MANAGER': 'manage_accounts',
      'USER': 'person',
      'AUDITOR': 'visibility'
    };
    return icons[role] || 'person';
  }

  getRoleLabel(role: string): string {
    const labels: Record<string, string> = {
      'ADMIN': 'Administrador',
      'MANAGER': 'Gestor',
      'USER': 'Usuario',
      'AUDITOR': 'Auditor'
    };
    return labels[role] || role;
  }

  changeRole(user: User, newRole: UserRole): void {
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      width: '400px',
      data: {
        title: 'Cambiar Rol',
        message: `¿Cambiar el rol de ${user.email} de ${this.getRoleLabel(user.role)} a ${this.getRoleLabel(newRole)}?`,
        confirmText: 'Cambiar',
        cancelText: 'Cancelar',
        confirmColor: 'primary',
        icon: 'swap_horiz'
      }
    });

    dialogRef.afterClosed().subscribe(confirmed => {
      if (confirmed) {
        this.authService.changeUserRole(user.id, newRole).subscribe({
          next: () => {
            this.snackBar.open(
              `✅ Rol de ${user.email} cambiado a ${this.getRoleLabel(newRole)}`,
              'Cerrar', { duration: 3000 }
            );
            this.loadUsers();
          },
          error: (err) => {
            const msg = err.error?.error || 'Error cambiando rol';
            this.snackBar.open(`❌ ${msg}`, 'Cerrar', { duration: 3000 });
          }
        });
      }
    });
  }

  toggleUserStatus(user: User): void {
    const action = user.is_active ? 'desactivar' : 'activar';
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      width: '400px',
      data: {
        title: `${user.is_active ? 'Desactivar' : 'Activar'} Usuario`,
        message: `¿Estás seguro de que deseas ${action} a ${user.email}?`,
        confirmText: user.is_active ? 'Desactivar' : 'Activar',
        cancelText: 'Cancelar',
        confirmColor: user.is_active ? 'warn' : 'primary',
        icon: user.is_active ? 'person_off' : 'person_add'
      }
    });

    dialogRef.afterClosed().subscribe(confirmed => {
      if (confirmed) {
        const obs = user.is_active
          ? this.authService.deactivateUser(user.id)
          : this.authService.activateUser(user.id);

        obs.subscribe({
          next: () => {
            this.snackBar.open(
              `✅ Usuario ${user.email} ${user.is_active ? 'desactivado' : 'activado'}`,
              'Cerrar', { duration: 3000 }
            );
            this.loadUsers();
          },
          error: (err) => {
            const msg = err.error?.error || `Error al ${action} usuario`;
            this.snackBar.open(`❌ ${msg}`, 'Cerrar', { duration: 3000 });
          }
        });
      }
    });
  }
}
