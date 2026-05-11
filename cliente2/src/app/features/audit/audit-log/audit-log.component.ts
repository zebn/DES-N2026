import { Component, OnInit, ViewChild } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { MatPaginator, PageEvent } from '@angular/material/paginator';
import { MatSnackBar } from '@angular/material/snack-bar';
import { AuditService, AuditLogEntry, AuditLogFilters } from '../../../core/services/audit.service';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-audit-log',
  template: `
    <div class="audit-log-container">
      <div class="page-header">
        <h1>
          <mat-icon>policy</mat-icon>
          Registro de Auditoría
        </h1>
        <p class="subtitle" *ngIf="isPrivileged">Eventos globales del sistema</p>
        <p class="subtitle" *ngIf="!isPrivileged">Mis eventos de actividad</p>
      </div>

      <!-- Filters -->
      <mat-card class="filters-card">
        <mat-card-content>
          <form [formGroup]="filterForm" class="filters-form">
            <mat-form-field appearance="outline">
              <mat-label>Acción</mat-label>
              <mat-select formControlName="action">
                <mat-option value="">Todas</mat-option>
                <mat-option *ngFor="let a of actionTypes" [value]="a.value">
                  {{ a.label }}
                </mat-option>
              </mat-select>
            </mat-form-field>

            <mat-form-field appearance="outline" *ngIf="isPrivileged">
              <mat-label>Tipo de recurso</mat-label>
              <mat-select formControlName="resource_type">
                <mat-option value="">Todos</mat-option>
                <mat-option value="USER">Usuario</mat-option>
                <mat-option value="SECRET">Secreto</mat-option>
                <mat-option value="GROUP">Grupo</mat-option>
                <mat-option value="SESSION">Sesión</mat-option>
              </mat-select>
            </mat-form-field>

            <mat-form-field appearance="outline">
              <mat-label>Resultado</mat-label>
              <mat-select formControlName="success">
                <mat-option value="">Todos</mat-option>
                <mat-option value="true">Exitoso</mat-option>
                <mat-option value="false">Fallido</mat-option>
              </mat-select>
            </mat-form-field>

            <mat-form-field appearance="outline">
              <mat-label>Desde</mat-label>
              <input matInput type="date" formControlName="from_date">
            </mat-form-field>

            <mat-form-field appearance="outline">
              <mat-label>Hasta</mat-label>
              <input matInput type="date" formControlName="to_date">
            </mat-form-field>

            <div class="filter-actions">
              <button mat-raised-button color="primary" (click)="applyFilters()">
                <mat-icon>filter_list</mat-icon>
                Filtrar
              </button>
              <button mat-button (click)="clearFilters()">
                <mat-icon>clear</mat-icon>
                Limpiar
              </button>
              <button mat-button color="accent" *ngIf="isAdmin" (click)="exportLogs()">
                <mat-icon>download</mat-icon>
                Exportar
              </button>
            </div>
          </form>
        </mat-card-content>
      </mat-card>

      <!-- Loading -->
      <div class="loading-container" *ngIf="loading">
        <mat-spinner diameter="40"></mat-spinner>
        <span>Cargando registros...</span>
      </div>

      <!-- Logs Table -->
      <mat-card class="logs-card" *ngIf="!loading">
        <mat-card-content>
          <div class="table-container" *ngIf="logs.length > 0">
            <table class="audit-table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th *ngIf="isPrivileged">Usuario</th>
                  <th>Acción</th>
                  <th>Recurso</th>
                  <th>Resultado</th>
                  <th>IP</th>
                  <th>Detalles</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let log of logs" [class.failed-row]="!log.success">
                  <td class="timestamp-cell">
                    {{ formatDate(log.timestamp) }}
                  </td>
                  <td *ngIf="isPrivileged" class="user-cell">
                    <mat-icon class="cell-icon">person</mat-icon>
                    {{ log.user_id }}
                  </td>
                  <td>
                    <mat-chip-listbox>
                      <mat-chip [class]="getActionClass(log.action)" selected>
                        <mat-icon class="chip-icon">{{ getActionIcon(log.action) }}</mat-icon>
                        {{ formatAction(log.action) }}
                      </mat-chip>
                    </mat-chip-listbox>
                  </td>
                  <td class="resource-cell">
                    <span *ngIf="log.resource_type" class="resource-badge">
                      {{ log.resource_type }}
                    </span>
                    <span *ngIf="log.resource_id" class="resource-id">
                      #{{ truncateId(log.resource_id) }}
                    </span>
                    <span *ngIf="!log.resource_type">—</span>
                  </td>
                  <td>
                    <mat-icon [class]="log.success ? 'success-icon' : 'error-icon'">
                      {{ log.success ? 'check_circle' : 'cancel' }}
                    </mat-icon>
                  </td>
                  <td class="ip-cell">{{ log.ip_address || '—' }}</td>
                  <td class="details-cell">
                    <span *ngIf="log.details" [matTooltip]="log.details" class="details-text">
                      {{ truncateDetails(log.details) }}
                    </span>
                    <span *ngIf="!log.details">—</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="empty-state" *ngIf="logs.length === 0">
            <mat-icon class="empty-icon">receipt_long</mat-icon>
            <h3>Sin registros</h3>
            <p>No se encontraron eventos de auditoría con los filtros aplicados.</p>
          </div>

          <mat-paginator
            *ngIf="totalLogs > 0"
            [length]="totalLogs"
            [pageSize]="perPage"
            [pageSizeOptions]="[10, 20, 50, 100]"
            (page)="onPageChange($event)"
            showFirstLastButtons>
          </mat-paginator>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .audit-log-container {
      max-width: 1200px;
      margin: 0 auto;
    }

    .page-header {
      margin-bottom: 24px;
    }

    .page-header h1 {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 28px;
      font-weight: 500;
      color: #333;
      margin: 0;
    }

    .page-header h1 mat-icon {
      font-size: 32px;
      width: 32px;
      height: 32px;
      color: #3f51b5;
    }

    .subtitle {
      color: #666;
      margin: 4px 0 0 44px;
      font-size: 14px;
    }

    .filters-card {
      margin-bottom: 20px;
    }

    .filters-form {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: flex-start;
    }

    .filters-form mat-form-field {
      flex: 1;
      min-width: 150px;
    }

    .filter-actions {
      display: flex;
      gap: 8px;
      align-items: center;
      padding-top: 4px;
    }

    .loading-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 16px;
      padding: 48px 0;
      color: #666;
    }

    .logs-card {
      overflow: hidden;
    }

    .table-container {
      overflow-x: auto;
    }

    .audit-table {
      width: 100%;
      border-collapse: collapse;
    }

    .audit-table thead th {
      text-align: left;
      padding: 12px 16px;
      font-weight: 600;
      color: #555;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 2px solid #e0e0e0;
      background: #fafafa;
      white-space: nowrap;
    }

    .audit-table tbody tr {
      transition: background 0.15s ease;
    }

    .audit-table tbody tr:hover {
      background: #f5f5f5;
    }

    .audit-table tbody tr.failed-row {
      background: #fff5f5;
    }

    .audit-table tbody tr.failed-row:hover {
      background: #ffebee;
    }

    .audit-table tbody td {
      padding: 10px 16px;
      border-bottom: 1px solid #eee;
      font-size: 13px;
      vertical-align: middle;
    }

    .timestamp-cell {
      white-space: nowrap;
      color: #666;
      font-family: 'Roboto Mono', monospace;
      font-size: 12px;
    }

    .user-cell {
      display: flex;
      align-items: center;
      gap: 4px;
    }

    .cell-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
      color: #999;
    }

    .chip-icon {
      font-size: 14px !important;
      width: 14px !important;
      height: 14px !important;
      margin-right: 4px;
    }

    .resource-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      background: #e8eaf6;
      color: #3f51b5;
      margin-right: 6px;
    }

    .resource-id {
      font-family: 'Roboto Mono', monospace;
      font-size: 12px;
      color: #888;
    }

    .success-icon {
      color: #4caf50;
      font-size: 20px;
    }

    .error-icon {
      color: #f44336;
      font-size: 20px;
    }

    .ip-cell {
      font-family: 'Roboto Mono', monospace;
      font-size: 12px;
      color: #888;
    }

    .details-cell {
      max-width: 200px;
    }

    .details-text {
      cursor: help;
      color: #666;
    }

    .action-auth { --mdc-chip-elevated-container-color: #e3f2fd; }
    .action-secret { --mdc-chip-elevated-container-color: #fff3e0; }
    .action-share { --mdc-chip-elevated-container-color: #e8f5e9; }
    .action-admin { --mdc-chip-elevated-container-color: #fce4ec; }
    .action-group { --mdc-chip-elevated-container-color: #f3e5f5; }
    .action-default { --mdc-chip-elevated-container-color: #f5f5f5; }

    .empty-state {
      text-align: center;
      padding: 48px 24px;
      color: #999;
    }

    .empty-icon {
      font-size: 64px;
      width: 64px;
      height: 64px;
      color: #ccc;
    }

    .empty-state h3 {
      margin: 16px 0 8px;
      color: #666;
    }
  `]
})
export class AuditLogComponent implements OnInit {
  @ViewChild(MatPaginator) paginator!: MatPaginator;

  logs: AuditLogEntry[] = [];
  totalLogs = 0;
  perPage = 20;
  currentPage = 1;
  loading = false;

  filterForm: FormGroup;
  isPrivileged = false;
  isAdmin = false;

  actionTypes = [
    { value: 'LOGIN_SUCCESS', label: 'Login exitoso' },
    { value: 'LOGIN_FAILED', label: 'Login fallido' },
    { value: 'LOGOUT', label: 'Logout' },
    { value: 'PASSWORD_CHANGE', label: 'Cambio de contraseña' },
    { value: '2FA_SETUP', label: 'Configuración 2FA' },
    { value: '2FA_VERIFY', label: 'Verificación 2FA' },
    { value: 'SECRET_CREATED', label: 'Secreto creado' },
    { value: 'SECRET_READ', label: 'Secreto leído' },
    { value: 'SECRET_UPDATED', label: 'Secreto actualizado' },
    { value: 'SECRET_DELETED', label: 'Secreto eliminado' },
    { value: 'SECRET_ROTATED', label: 'Secreto rotado' },
    { value: 'SECRET_SHARED', label: 'Secreto compartido' },
    { value: 'SHARE_REVOKED', label: 'Compartición revocada' },
    { value: 'GROUP_CREATED', label: 'Grupo creado' },
    { value: 'GROUP_UPDATED', label: 'Grupo actualizado' },
    { value: 'GROUP_DELETED', label: 'Grupo eliminado' },
    { value: 'MEMBER_ADDED', label: 'Miembro añadido' },
    { value: 'MEMBER_REMOVED', label: 'Miembro eliminado' },
    { value: 'ROLE_CHANGED', label: 'Rol cambiado' },
    { value: 'USER_CREATED', label: 'Usuario creado' },
    { value: 'USER_DEACTIVATED', label: 'Usuario desactivado' },
  ];

  constructor(
    private auditService: AuditService,
    private authService: AuthService,
    private fb: FormBuilder,
    private snackBar: MatSnackBar
  ) {
    this.filterForm = this.fb.group({
      action: [''],
      resource_type: [''],
      success: [''],
      from_date: [''],
      to_date: [''],
    });
  }

  ngOnInit(): void {
    this.isAdmin = this.authService.hasRole('ADMIN');
    this.isPrivileged = this.authService.hasRole('ADMIN', 'AUDITOR');
    this.loadLogs();
  }

  loadLogs(): void {
    this.loading = true;
    const filters = this.buildFilters();

    const request$ = this.isPrivileged
      ? this.auditService.getGlobalLogs(filters)
      : this.auditService.getMyLogs(filters);

    request$.subscribe({
      next: (response) => {
        this.logs = response.logs;
        this.totalLogs = response.total;
        this.loading = false;
      },
      error: (err) => {
        this.loading = false;
        this.snackBar.open(
          'Error al cargar los registros de auditoría',
          'Cerrar',
          { duration: 4000 }
        );
        console.error('[Audit] Error loading logs:', err);
      }
    });
  }

  applyFilters(): void {
    this.currentPage = 1;
    this.loadLogs();
  }

  clearFilters(): void {
    this.filterForm.reset({
      action: '',
      resource_type: '',
      success: '',
      from_date: '',
      to_date: '',
    });
    this.currentPage = 1;
    this.loadLogs();
  }

  onPageChange(event: PageEvent): void {
    this.currentPage = event.pageIndex + 1;
    this.perPage = event.pageSize;
    this.loadLogs();
  }

  exportLogs(): void {
    const filters: any = {};
    const from = this.filterForm.get('from_date')?.value;
    const to = this.filterForm.get('to_date')?.value;
    if (from) filters.from_date = from;
    if (to) filters.to_date = to;
    filters.format = 'json';

    this.auditService.exportLogs(filters).subscribe({
      next: (data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-export-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        this.snackBar.open('Exportación completada', 'Cerrar', { duration: 3000 });
      },
      error: () => {
        this.snackBar.open('Error al exportar los logs', 'Cerrar', { duration: 4000 });
      }
    });
  }

  // ─── Formatting helpers ─────────────────────────────────────────

  formatDate(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleDateString('es-ES', {
      day: '2-digit', month: '2-digit', year: 'numeric'
    }) + ' ' + d.toLocaleTimeString('es-ES', {
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  }

  formatAction(action: string): string {
    const item = this.actionTypes.find(a => a.value === action);
    return item ? item.label : action.replace(/_/g, ' ');
  }

  getActionIcon(action: string): string {
    const icons: Record<string, string> = {
      LOGIN_SUCCESS: 'login',
      LOGIN_FAILED: 'error',
      LOGOUT: 'logout',
      PASSWORD_CHANGE: 'key',
      '2FA_SETUP': 'security',
      '2FA_VERIFY': 'verified',
      SECRET_CREATED: 'add_circle',
      SECRET_READ: 'visibility',
      SECRET_UPDATED: 'edit',
      SECRET_DELETED: 'delete',
      SECRET_ROTATED: 'autorenew',
      SECRET_SHARED: 'share',
      SHARE_REVOKED: 'link_off',
      GROUP_CREATED: 'group_add',
      GROUP_UPDATED: 'group',
      GROUP_DELETED: 'group_remove',
      MEMBER_ADDED: 'person_add',
      MEMBER_REMOVED: 'person_remove',
      ROLE_CHANGED: 'admin_panel_settings',
      USER_CREATED: 'person_add',
      USER_DEACTIVATED: 'person_off',
    };
    return icons[action] || 'info';
  }

  getActionClass(action: string): string {
    if (action.startsWith('LOGIN') || action.startsWith('LOGOUT') || action.startsWith('PASSWORD') || action.startsWith('2FA')) {
      return 'action-auth';
    }
    if (action.startsWith('SECRET')) return 'action-secret';
    if (action.startsWith('SHARE') || action.includes('SHARED')) return 'action-share';
    if (action.startsWith('GROUP') || action.startsWith('MEMBER')) return 'action-group';
    if (action.startsWith('USER') || action.startsWith('ROLE')) return 'action-admin';
    return 'action-default';
  }

  truncateId(id: string): string {
    return id.length > 8 ? id.substring(0, 8) + '…' : id;
  }

  truncateDetails(details: string): string {
    return details.length > 40 ? details.substring(0, 40) + '…' : details;
  }

  private buildFilters(): AuditLogFilters {
    const f: AuditLogFilters = {
      page: this.currentPage,
      per_page: this.perPage,
    };

    const action = this.filterForm.get('action')?.value;
    if (action) f.action = action;

    const resourceType = this.filterForm.get('resource_type')?.value;
    if (resourceType) f.resource_type = resourceType;

    const success = this.filterForm.get('success')?.value;
    if (success !== '' && success !== null) f.success = success === 'true';

    const from = this.filterForm.get('from_date')?.value;
    if (from) f.from_date = from;

    const to = this.filterForm.get('to_date')?.value;
    if (to) f.to_date = to;

    return f;
  }
}
