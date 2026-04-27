import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { PageEvent } from '@angular/material/paginator';
import { GroupsService, Group } from '../../../core/services/groups.service';
import { AuthService } from '../../../core/services/auth.service';
import { ConfirmDialogComponent } from '../../../shared/components/confirm-dialog/confirm-dialog.component';
import { GroupFormDialogComponent } from '../group-form-dialog/group-form-dialog.component';

@Component({
  selector: 'app-groups-list',
  template: `
    <div class="groups-container">
      <mat-card>
        <mat-card-header>
          <mat-card-title>
            <mat-icon>group</mat-icon>
            Grupos
          </mat-card-title>
          <div class="header-actions">
            <button mat-raised-button color="primary"
                    *ngIf="canCreateGroup()"
                    (click)="openCreateDialog()">
              <mat-icon>group_add</mat-icon>
              Nuevo Grupo
            </button>
            <button mat-icon-button (click)="loadGroups()" [disabled]="isLoading" matTooltip="Actualizar">
              <mat-icon>refresh</mat-icon>
            </button>
          </div>
        </mat-card-header>

        <mat-card-content>
          <!-- Loading -->
          <div *ngIf="isLoading" class="loading-container">
            <mat-spinner diameter="50"></mat-spinner>
            <p>Cargando grupos...</p>
          </div>

          <!-- Empty state -->
          <div *ngIf="!isLoading && groups.length === 0" class="empty-state">
            <mat-icon class="empty-icon">group_off</mat-icon>
            <h3>No perteneces a ningún grupo</h3>
            <p>Los grupos permiten compartir secretos con múltiples usuarios a la vez</p>
            <button mat-raised-button color="primary" *ngIf="canCreateGroup()" (click)="openCreateDialog()">
              <mat-icon>group_add</mat-icon>
              Crear Primer Grupo
            </button>
          </div>

          <!-- Groups grid -->
          <div *ngIf="!isLoading && groups.length > 0" class="groups-grid">
            <mat-card *ngFor="let group of groups"
                      class="group-card"
                      (click)="goToDetail(group)">
              <div class="group-card-header">
                <mat-icon class="group-icon">group</mat-icon>
                <div class="group-info">
                  <h3 class="group-name">{{ group.name }}</h3>
                  <span class="group-description" *ngIf="group.description">{{ group.description }}</span>
                  <span class="group-description empty" *ngIf="!group.description">Sin descripción</span>
                </div>
                <button mat-icon-button [matMenuTriggerFor]="groupMenu"
                        (click)="$event.stopPropagation()"
                        *ngIf="canManageGroup(group)">
                  <mat-icon>more_vert</mat-icon>
                </button>
                <mat-menu #groupMenu="matMenu">
                  <button mat-menu-item (click)="openEditDialog(group)">
                    <mat-icon>edit</mat-icon>
                    <span>Editar</span>
                  </button>
                  <button mat-menu-item (click)="confirmDelete(group)" class="delete-item"
                          *ngIf="group.my_role === 'OWNER'">
                    <mat-icon>delete</mat-icon>
                    <span>Eliminar</span>
                  </button>
                </mat-menu>
              </div>

              <div class="group-card-footer">
                <mat-chip [class]="'role-chip role-' + (group.my_role || 'member').toLowerCase()">
                  {{ getRoleLabel(group.my_role) }}
                </mat-chip>
                <span class="member-count">
                  <mat-icon>people</mat-icon>
                  {{ group.member_count ?? '?' }} miembros
                </span>
              </div>
            </mat-card>
          </div>

          <!-- Paginator -->
          <mat-paginator
            *ngIf="total > perPage"
            [length]="total"
            [pageSize]="perPage"
            [pageSizeOptions]="[10, 20, 50]"
            (page)="onPageChange($event)">
          </mat-paginator>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .groups-container {
      padding: 24px;
      max-width: 1200px;
      margin: 0 auto;
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
      font-size: 22px;
    }

    .header-actions {
      display: flex;
      gap: 8px;
      align-items: center;
      margin-left: auto;
    }

    .loading-container, .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 60px 20px;
      gap: 16px;
      color: rgba(0,0,0,0.5);
    }

    .empty-icon {
      font-size: 72px;
      width: 72px;
      height: 72px;
      opacity: 0.3;
    }

    .groups-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 16px;
      margin-top: 16px;
    }

    .group-card {
      cursor: pointer;
      transition: box-shadow 0.2s;
      padding: 16px;
    }

    .group-card:hover {
      box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    }

    .group-card-header {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 12px;
    }

    .group-icon {
      font-size: 36px;
      width: 36px;
      height: 36px;
      color: #3f51b5;
      flex-shrink: 0;
    }

    .group-info {
      flex: 1;
      min-width: 0;
    }

    .group-name {
      margin: 0 0 4px;
      font-size: 16px;
      font-weight: 500;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .group-description {
      font-size: 13px;
      color: rgba(0,0,0,0.6);
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }

    .group-description.empty {
      font-style: italic;
    }

    .group-card-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-top: 8px;
      border-top: 1px solid rgba(0,0,0,0.08);
    }

    .member-count {
      display: flex;
      align-items: center;
      gap: 4px;
      font-size: 13px;
      color: rgba(0,0,0,0.6);
    }

    .member-count mat-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
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

    .delete-item { color: #f44336; }
  `]
})
export class GroupsListComponent implements OnInit {
  groups: Group[] = [];
  isLoading = false;
  total = 0;
  page = 1;
  perPage = 20;

  constructor(
    private groupsService: GroupsService,
    private authService: AuthService,
    private dialog: MatDialog,
    private snackBar: MatSnackBar,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.loadGroups();
  }

  loadGroups(): void {
    this.isLoading = true;
    this.groupsService.listGroups({ page: this.page, per_page: this.perPage }).subscribe({
      next: (res) => {
        this.groups = res.groups;
        this.total = res.total;
        this.isLoading = false;
      },
      error: (err) => {
        this.snackBar.open('Error al cargar grupos', 'Cerrar', { duration: 3000 });
        this.isLoading = false;
      }
    });
  }

  goToDetail(group: Group): void {
    this.router.navigate(['/groups', group.id]);
  }

  openCreateDialog(): void {
    const ref = this.dialog.open(GroupFormDialogComponent, {
      width: '480px',
      data: { group: null }
    });
    ref.afterClosed().subscribe(result => {
      if (result) this.loadGroups();
    });
  }

  openEditDialog(group: Group): void {
    const ref = this.dialog.open(GroupFormDialogComponent, {
      width: '480px',
      data: { group }
    });
    ref.afterClosed().subscribe(result => {
      if (result) this.loadGroups();
    });
  }

  confirmDelete(group: Group): void {
    const ref = this.dialog.open(ConfirmDialogComponent, {
      data: {
        title: 'Eliminar grupo',
        message: `¿Eliminar el grupo "${group.name}"? Esta acción no se puede deshacer y eliminará todas las membresías.`,
        confirmText: 'Eliminar',
        cancelText: 'Cancelar'
      }
    });
    ref.afterClosed().subscribe(confirmed => {
      if (!confirmed) return;
      this.groupsService.deleteGroup(group.id).subscribe({
        next: () => {
          this.snackBar.open('Grupo eliminado', '', { duration: 3000 });
          this.loadGroups();
        },
        error: (err) => {
          this.snackBar.open(err.error?.error || 'Error al eliminar', 'Cerrar', { duration: 4000 });
        }
      });
    });
  }

  onPageChange(event: PageEvent): void {
    this.page = event.pageIndex + 1;
    this.perPage = event.pageSize;
    this.loadGroups();
  }

  canCreateGroup(): boolean {
    return this.authService.hasRole('ADMIN', 'MANAGER');
  }

  canManageGroup(group: Group): boolean {
    return group.my_role === 'OWNER' || group.my_role === 'ADMIN';
  }

  getRoleLabel(role?: string): string {
    const labels: Record<string, string> = {
      OWNER: 'Propietario', ADMIN: 'Admin', MEMBER: 'Miembro', READONLY: 'Solo lectura'
    };
    return labels[role || ''] || role || '';
  }
}
