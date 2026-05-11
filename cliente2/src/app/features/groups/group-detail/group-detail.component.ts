import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { GroupsService, Group, GroupMember, GroupRole } from '../../../core/services/groups.service';
import { AuthService } from '../../../core/services/auth.service';
import { ConfirmDialogComponent } from '../../../shared/components/confirm-dialog/confirm-dialog.component';
import { GroupFormDialogComponent } from '../group-form-dialog/group-form-dialog.component';
import { AddMemberDialogComponent } from '../add-member-dialog/add-member-dialog.component';

@Component({
  selector: 'app-group-detail',
  template: `
    <div class="detail-container">
      <!-- Loading -->
      <div *ngIf="isLoading" class="loading-container">
        <mat-spinner diameter="50"></mat-spinner>
      </div>

      <ng-container *ngIf="!isLoading && group">
        <!-- Header card -->
        <mat-card class="header-card">
          <div class="breadcrumb">
            <button mat-button (click)="back()">
              <mat-icon>arrow_back</mat-icon>
              Grupos
            </button>
          </div>

          <div class="group-header">
            <mat-icon class="group-avatar">group</mat-icon>
            <div class="group-title-section">
              <h1 class="group-title">{{ group.name }}</h1>
              <p class="group-description" *ngIf="group.description">{{ group.description }}</p>
              <div class="group-meta">
                <mat-chip [class]="'role-chip role-' + myRole.toLowerCase()">
                  {{ getRoleLabel(myRole) }}
                </mat-chip>
                <span class="meta-item">
                  <mat-icon>people</mat-icon>
                  {{ members.length }} miembro{{ members.length !== 1 ? 's' : '' }}
                </span>
                <span class="meta-item">
                  <mat-icon>calendar_today</mat-icon>
                  Creado {{ group.created_at | date:'dd/MM/yyyy' }}
                </span>
              </div>
            </div>
            <div class="header-actions" *ngIf="canManage()">
              <button mat-stroked-button (click)="openEditDialog()">
                <mat-icon>edit</mat-icon>
                Editar
              </button>
              <button mat-stroked-button color="warn" (click)="confirmDelete()" *ngIf="myRole === 'OWNER'">
                <mat-icon>delete</mat-icon>
                Eliminar
              </button>
            </div>
          </div>
        </mat-card>

        <!-- Members card -->
        <mat-card class="members-card">
          <mat-card-header>
            <mat-card-title>
              <mat-icon>people</mat-icon>
              Miembros
            </mat-card-title>
            <button mat-raised-button color="primary"
                    *ngIf="canManage()"
                    (click)="openAddMemberDialog()"
                    class="add-member-btn">
              <mat-icon>person_add</mat-icon>
              Añadir Miembro
            </button>
          </mat-card-header>

          <mat-card-content>
            <mat-table [dataSource]="members" class="members-table">

              <ng-container matColumnDef="user">
                <mat-header-cell *matHeaderCellDef>Usuario</mat-header-cell>
                <mat-cell *matCellDef="let m">
                  <div class="user-cell">
                    <mat-icon class="user-avatar">account_circle</mat-icon>
                    <div>
                      <div class="user-name">{{ m.nombre }} {{ m.apellidos }}</div>
                      <div class="user-email">{{ m.email }}</div>
                    </div>
                  </div>
                </mat-cell>
              </ng-container>

              <ng-container matColumnDef="role">
                <mat-header-cell *matHeaderCellDef>Rol en grupo</mat-header-cell>
                <mat-cell *matCellDef="let m">
                  <mat-select
                    [value]="m.role_in_group"
                    [disabled]="!canChangeRole(m)"
                    (selectionChange)="changeRole(m, $event.value)"
                    class="role-select">
                    <mat-option value="OWNER">Propietario</mat-option>
                    <mat-option value="ADMIN">Admin</mat-option>
                    <mat-option value="MEMBER">Miembro</mat-option>
                    <mat-option value="READONLY">Solo lectura</mat-option>
                  </mat-select>
                </mat-cell>
              </ng-container>

              <ng-container matColumnDef="joined">
                <mat-header-cell *matHeaderCellDef>Añadido</mat-header-cell>
                <mat-cell *matCellDef="let m">{{ m.joined_at | date:'dd/MM/yyyy' }}</mat-cell>
              </ng-container>

              <ng-container matColumnDef="actions">
                <mat-header-cell *matHeaderCellDef></mat-header-cell>
                <mat-cell *matCellDef="let m">
                  <button mat-icon-button color="warn"
                          *ngIf="canRemoveMember(m)"
                          (click)="confirmRemoveMember(m)"
                          matTooltip="Eliminar miembro">
                    <mat-icon>person_remove</mat-icon>
                  </button>
                </mat-cell>
              </ng-container>

              <mat-header-row *matHeaderRowDef="displayedColumns"></mat-header-row>
              <mat-row *matRowDef="let row; columns: displayedColumns;"></mat-row>
            </mat-table>
          </mat-card-content>
        </mat-card>
      </ng-container>
    </div>
  `,
  styles: [`
    .detail-container {
      padding: 24px;
      max-width: 1000px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .loading-container {
      display: flex;
      justify-content: center;
      padding: 60px;
    }

    .breadcrumb {
      margin-bottom: 16px;
    }

    .group-header {
      display: flex;
      align-items: flex-start;
      gap: 20px;
    }

    .group-avatar {
      font-size: 56px;
      width: 56px;
      height: 56px;
      color: #3f51b5;
      flex-shrink: 0;
    }

    .group-title-section {
      flex: 1;
    }

    .group-title {
      margin: 0 0 4px;
      font-size: 26px;
    }

    .group-description {
      margin: 0 0 12px;
      color: rgba(0,0,0,0.6);
    }

    .group-meta {
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }

    .meta-item {
      display: flex;
      align-items: center;
      gap: 4px;
      font-size: 13px;
      color: rgba(0,0,0,0.6);
    }

    .meta-item mat-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
    }

    .header-actions {
      display: flex;
      gap: 8px;
      flex-shrink: 0;
    }

    mat-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }

    mat-card-title {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .add-member-btn {
      margin-left: auto;
    }

    .members-table {
      width: 100%;
    }

    .user-cell {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .user-avatar {
      font-size: 32px;
      width: 32px;
      height: 32px;
      color: #9e9e9e;
    }

    .user-name {
      font-weight: 500;
    }

    .user-email {
      font-size: 12px;
      color: rgba(0,0,0,0.5);
    }

    .role-select {
      width: 140px;
    }

    .role-chip {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }

    .role-chip.role-owner { background: #ffd700; color: #333; }
    .role-chip.role-admin { background: #ff5722; color: white; }
    .role-chip.role-member { background: #4caf50; color: white; }
    .role-chip.role-readonly { background: #9e9e9e; color: white; }
  `]
})
export class GroupDetailComponent implements OnInit {
  group: Group | null = null;
  members: GroupMember[] = [];
  myRole: GroupRole = 'MEMBER';
  isLoading = false;
  displayedColumns = ['user', 'role', 'joined', 'actions'];

  private groupId!: string;
  private currentUserId!: number;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private groupsService: GroupsService,
    private authService: AuthService,
    private dialog: MatDialog,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    this.groupId = this.route.snapshot.paramMap.get('id')!;
    this.authService.currentUser$.subscribe(user => {
      if (user) this.currentUserId = user.id;
    });
    this.loadGroup();
  }

  loadGroup(): void {
    this.isLoading = true;
    this.groupsService.getGroup(this.groupId).subscribe({
      next: ({ group }) => {
        this.group = group;
        this.members = group.members || [];
        const me = this.members.find(m => m.user_id === this.currentUserId);
        this.myRole = (me?.role_in_group) || 'MEMBER';
        this.isLoading = false;
      },
      error: () => {
        this.snackBar.open('Error al cargar el grupo', 'Cerrar', { duration: 3000 });
        this.isLoading = false;
      }
    });
  }

  back(): void {
    this.router.navigate(['/groups']);
  }

  canManage(): boolean {
    return this.myRole === 'OWNER' || this.myRole === 'ADMIN';
  }

  canChangeRole(member: GroupMember): boolean {
    if (this.myRole !== 'OWNER') return false;
    return member.user_id !== this.currentUserId;
  }

  canRemoveMember(member: GroupMember): boolean {
    if (!this.canManage()) return false;
    if (member.role_in_group === 'OWNER' && this.myRole !== 'OWNER') return false;
    return true;
  }

  openEditDialog(): void {
    const ref = this.dialog.open(GroupFormDialogComponent, {
      width: '480px',
      data: { group: this.group }
    });
    ref.afterClosed().subscribe(result => {
      if (result) this.loadGroup();
    });
  }

  confirmDelete(): void {
    const ref = this.dialog.open(ConfirmDialogComponent, {
      data: {
        title: 'Eliminar grupo',
        message: `¿Eliminar el grupo "${this.group?.name}"? Esta acción no se puede deshacer.`,
        confirmText: 'Eliminar',
        cancelText: 'Cancelar'
      }
    });
    ref.afterClosed().subscribe(confirmed => {
      if (!confirmed) return;
      this.groupsService.deleteGroup(this.groupId).subscribe({
        next: () => {
          this.snackBar.open('Grupo eliminado', '', { duration: 3000 });
          this.router.navigate(['/groups']);
        },
        error: (err) => {
          this.snackBar.open(err.error?.error || 'Error al eliminar', 'Cerrar', { duration: 4000 });
        }
      });
    });
  }

  openAddMemberDialog(): void {
    const existingIds = this.members.map(m => m.user_id);
    const ref = this.dialog.open(AddMemberDialogComponent, {
      width: '500px',
      data: { groupId: this.groupId, existingUserIds: existingIds }
    });
    ref.afterClosed().subscribe(result => {
      if (result) this.loadGroup();
    });
  }

  changeRole(member: GroupMember, newRole: GroupRole): void {
    this.groupsService.changeMemberRole(this.groupId, member.user_id, newRole).subscribe({
      next: () => {
        this.snackBar.open('Rol actualizado', '', { duration: 2000 });
        member.role_in_group = newRole;
      },
      error: (err) => {
        this.snackBar.open(err.error?.error || 'Error al cambiar rol', 'Cerrar', { duration: 4000 });
        this.loadGroup();
      }
    });
  }

  confirmRemoveMember(member: GroupMember): void {
    const ref = this.dialog.open(ConfirmDialogComponent, {
      data: {
        title: 'Eliminar miembro',
        message: `¿Eliminar a ${member.nombre} ${member.apellidos} del grupo?`,
        confirmText: 'Eliminar',
        cancelText: 'Cancelar'
      }
    });
    ref.afterClosed().subscribe(confirmed => {
      if (!confirmed) return;
      this.groupsService.removeMember(this.groupId, member.user_id).subscribe({
        next: () => {
          this.snackBar.open('Miembro eliminado', '', { duration: 2000 });
          this.loadGroup();
        },
        error: (err) => {
          this.snackBar.open(err.error?.error || 'Error al eliminar miembro', 'Cerrar', { duration: 4000 });
        }
      });
    });
  }

  getRoleLabel(role: string): string {
    const labels: Record<string, string> = {
      OWNER: 'Propietario', ADMIN: 'Admin', MEMBER: 'Miembro', READONLY: 'Solo lectura'
    };
    return labels[role] || role;
  }
}
