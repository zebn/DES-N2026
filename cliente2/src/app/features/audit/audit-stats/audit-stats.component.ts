import { Component, OnInit } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { AuditService, AuditStats } from '../../../core/services/audit.service';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-audit-stats',
  template: `
    <div class="audit-stats-container">
      <div class="page-header">
        <h1>
          <mat-icon>analytics</mat-icon>
          Estadísticas de Auditoría
        </h1>
        <p class="subtitle">Panel de actividad del sistema</p>
      </div>

      <!-- Period selector -->
      <div class="period-selector">
        <button mat-stroked-button *ngFor="let p of periods"
                [color]="selectedPeriod === p.days ? 'primary' : ''"
                (click)="changePeriod(p.days)">
          {{ p.label }}
        </button>
      </div>

      <!-- Loading -->
      <div class="loading-container" *ngIf="loading">
        <mat-spinner diameter="40"></mat-spinner>
        <span>Calculando estadísticas...</span>
      </div>

      <div class="stats-grid" *ngIf="!loading && stats">
        <!-- Summary Cards -->
        <div class="summary-row">
          <mat-card class="summary-card">
            <div class="summary-value">{{ stats.total_events | number }}</div>
            <div class="summary-label">Eventos Totales</div>
            <mat-icon class="summary-icon">receipt_long</mat-icon>
          </mat-card>

          <mat-card class="summary-card success-card">
            <div class="summary-value">{{ stats.success_rate | number:'1.1-1' }}%</div>
            <div class="summary-label">Tasa de Éxito</div>
            <mat-icon class="summary-icon">check_circle</mat-icon>
          </mat-card>

          <mat-card class="summary-card">
            <div class="summary-value">{{ getUniqueActions() }}</div>
            <div class="summary-label">Tipos de Acción</div>
            <mat-icon class="summary-icon">category</mat-icon>
          </mat-card>

          <mat-card class="summary-card">
            <div class="summary-value">{{ stats.top_users.length }}</div>
            <div class="summary-label">Usuarios Activos</div>
            <mat-icon class="summary-icon">people</mat-icon>
          </mat-card>
        </div>

        <!-- Actions Chart (bar chart via CSS) -->
        <mat-card class="chart-card">
          <mat-card-header>
            <mat-card-title>
              <mat-icon>bar_chart</mat-icon>
              Eventos por Tipo de Acción
            </mat-card-title>
          </mat-card-header>
          <mat-card-content>
            <div class="bar-chart">
              <div class="bar-row" *ngFor="let item of actionsSorted">
                <div class="bar-label" [matTooltip]="item.action">
                  {{ formatActionName(item.action) }}
                </div>
                <div class="bar-track">
                  <div class="bar-fill" [style.width.%]="getBarWidth(item.count)"
                       [class]="getBarColorClass(item.action)">
                  </div>
                </div>
                <div class="bar-value">{{ item.count }}</div>
              </div>
            </div>
          </mat-card-content>
        </mat-card>

        <!-- Two-column layout -->
        <div class="two-col">
          <!-- Top Users -->
          <mat-card class="chart-card">
            <mat-card-header>
              <mat-card-title>
                <mat-icon>leaderboard</mat-icon>
                Usuarios Más Activos
              </mat-card-title>
            </mat-card-header>
            <mat-card-content>
              <div class="users-list" *ngIf="stats.top_users.length > 0">
                <div class="user-row" *ngFor="let user of stats.top_users; let i = index">
                  <div class="user-rank">{{ i + 1 }}</div>
                  <div class="user-info">
                    <mat-icon class="user-icon">person</mat-icon>
                    <span class="user-email">{{ user.email }}</span>
                  </div>
                  <div class="user-count">
                    <strong>{{ user.count }}</strong> eventos
                  </div>
                </div>
              </div>
              <div class="empty-mini" *ngIf="stats.top_users.length === 0">
                Sin datos de usuarios
              </div>
            </mat-card-content>
          </mat-card>

          <!-- Activity Timeline -->
          <mat-card class="chart-card">
            <mat-card-header>
              <mat-card-title>
                <mat-icon>timeline</mat-icon>
                Actividad por Día
              </mat-card-title>
            </mat-card-header>
            <mat-card-content>
              <div class="timeline" *ngIf="stats.events_by_day.length > 0">
                <div class="timeline-row" *ngFor="let day of stats.events_by_day">
                  <div class="timeline-date">{{ formatShortDate(day.date) }}</div>
                  <div class="timeline-bar-track">
                    <div class="timeline-bar-fill"
                         [style.width.%]="getDayBarWidth(day.count)">
                    </div>
                  </div>
                  <div class="timeline-value">{{ day.count }}</div>
                </div>
              </div>
              <div class="empty-mini" *ngIf="stats.events_by_day.length === 0">
                Sin datos de actividad diaria
              </div>
            </mat-card-content>
          </mat-card>
        </div>
      </div>

      <!-- No permission -->
      <div class="empty-state" *ngIf="!loading && !stats">
        <mat-icon class="empty-icon">lock</mat-icon>
        <h3>Sin datos disponibles</h3>
        <p>No se pudieron cargar las estadísticas.</p>
      </div>
    </div>
  `,
  styles: [`
    .audit-stats-container {
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

    .period-selector {
      display: flex;
      gap: 8px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }

    .loading-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 16px;
      padding: 48px 0;
      color: #666;
    }

    /* Summary Cards */
    .summary-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .summary-card {
      padding: 24px;
      position: relative;
      overflow: hidden;
    }

    .summary-value {
      font-size: 36px;
      font-weight: 700;
      color: #333;
      line-height: 1;
    }

    .summary-label {
      font-size: 14px;
      color: #888;
      margin-top: 8px;
    }

    .summary-icon {
      position: absolute;
      top: 16px;
      right: 16px;
      font-size: 40px;
      width: 40px;
      height: 40px;
      color: rgba(63, 81, 181, 0.15);
    }

    .success-card .summary-value {
      color: #4caf50;
    }

    /* Chart Cards */
    .chart-card {
      margin-bottom: 24px;
    }

    .chart-card mat-card-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 18px;
    }

    .chart-card mat-card-title mat-icon {
      color: #3f51b5;
    }

    /* Bar Chart */
    .bar-chart {
      padding: 16px 0;
    }

    .bar-row {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
    }

    .bar-label {
      min-width: 140px;
      font-size: 13px;
      color: #555;
      text-align: right;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .bar-track {
      flex: 1;
      height: 24px;
      background: #f0f0f0;
      border-radius: 4px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.5s ease;
      min-width: 2px;
    }

    .bar-fill.bar-auth { background: #42a5f5; }
    .bar-fill.bar-secret { background: #ff9800; }
    .bar-fill.bar-share { background: #66bb6a; }
    .bar-fill.bar-group { background: #ab47bc; }
    .bar-fill.bar-admin { background: #ef5350; }
    .bar-fill.bar-default { background: #78909c; }

    .bar-value {
      min-width: 40px;
      font-weight: 600;
      font-size: 13px;
      color: #333;
      text-align: right;
    }

    /* Two-column layout */
    .two-col {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }

    @media (max-width: 768px) {
      .two-col {
        grid-template-columns: 1fr;
      }
    }

    /* Users List */
    .users-list {
      padding: 8px 0;
    }

    .user-row {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 0;
      border-bottom: 1px solid #f0f0f0;
    }

    .user-row:last-child {
      border-bottom: none;
    }

    .user-rank {
      width: 28px;
      height: 28px;
      border-radius: 50%;
      background: #e8eaf6;
      color: #3f51b5;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 13px;
    }

    .user-info {
      flex: 1;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .user-icon {
      color: #999;
      font-size: 20px;
      width: 20px;
      height: 20px;
    }

    .user-email {
      font-size: 13px;
      color: #333;
    }

    .user-count {
      font-size: 13px;
      color: #666;
    }

    /* Timeline */
    .timeline {
      padding: 8px 0;
    }

    .timeline-row {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 6px;
    }

    .timeline-date {
      min-width: 60px;
      font-size: 12px;
      color: #888;
      font-family: 'Roboto Mono', monospace;
    }

    .timeline-bar-track {
      flex: 1;
      height: 18px;
      background: #f0f0f0;
      border-radius: 3px;
      overflow: hidden;
    }

    .timeline-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #3f51b5, #7986cb);
      border-radius: 3px;
      transition: width 0.5s ease;
      min-width: 2px;
    }

    .timeline-value {
      min-width: 30px;
      font-size: 12px;
      font-weight: 600;
      color: #333;
      text-align: right;
    }

    .empty-mini {
      text-align: center;
      padding: 24px;
      color: #999;
      font-size: 14px;
    }

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
  `]
})
export class AuditStatsComponent implements OnInit {
  stats: AuditStats | null = null;
  loading = false;
  selectedPeriod = 30;
  maxActionCount = 0;
  maxDayCount = 0;
  actionsSorted: Array<{ action: string; count: number }> = [];

  periods = [
    { days: 7, label: 'Última semana' },
    { days: 30, label: 'Último mes' },
    { days: 90, label: 'Últimos 3 meses' },
    { days: 365, label: 'Último año' },
  ];

  constructor(
    private auditService: AuditService,
    private authService: AuthService,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    this.loadStats();
  }

  changePeriod(days: number): void {
    this.selectedPeriod = days;
    this.loadStats();
  }

  loadStats(): void {
    this.loading = true;
    this.auditService.getStats(this.selectedPeriod).subscribe({
      next: (data) => {
        this.stats = data;
        this.processStats();
        this.loading = false;
      },
      error: (err) => {
        this.loading = false;
        this.stats = null;
        this.snackBar.open('Error al cargar estadísticas', 'Cerrar', { duration: 4000 });
        console.error('[AuditStats] Error:', err);
      }
    });
  }

  private processStats(): void {
    if (!this.stats) return;

    // Sort actions by count descending
    const actionsObj = this.stats.actions_count || {};
    this.actionsSorted = Object.entries(actionsObj)
      .map(([action, count]) => ({ action, count }))
      .sort((a, b) => b.count - a.count);

    this.maxActionCount = this.actionsSorted.length > 0
      ? this.actionsSorted[0].count : 1;

    const days = this.stats.events_by_day || [];
    this.maxDayCount = days.length > 0
      ? Math.max(...days.map(d => d.count)) : 1;
  }

  getUniqueActions(): number {
    return this.stats?.actions_count ? Object.keys(this.stats.actions_count).length : 0;
  }

  getBarWidth(count: number): number {
    return (count / this.maxActionCount) * 100;
  }

  getDayBarWidth(count: number): number {
    return (count / this.maxDayCount) * 100;
  }

  getBarColorClass(action: string): string {
    if (action.startsWith('LOGIN') || action.startsWith('LOGOUT') || action.startsWith('PASSWORD') || action.startsWith('2FA')) {
      return 'bar-auth';
    }
    if (action.startsWith('SECRET')) return 'bar-secret';
    if (action.startsWith('SHARE') || action.includes('SHARED')) return 'bar-share';
    if (action.startsWith('GROUP') || action.startsWith('MEMBER')) return 'bar-group';
    if (action.startsWith('USER') || action.startsWith('ROLE')) return 'bar-admin';
    return 'bar-default';
  }

  formatActionName(action: string): string {
    const names: Record<string, string> = {
      LOGIN_SUCCESS: 'Login exitoso',
      LOGIN_FAILED: 'Login fallido',
      LOGOUT: 'Logout',
      PASSWORD_CHANGE: 'Cambio contraseña',
      '2FA_SETUP': 'Config. 2FA',
      '2FA_VERIFY': 'Verif. 2FA',
      SECRET_CREATED: 'Secreto creado',
      SECRET_READ: 'Secreto leído',
      SECRET_UPDATED: 'Secreto updating',
      SECRET_DELETED: 'Secreto eliminado',
      SECRET_ROTATED: 'Secreto rotado',
      SECRET_SHARED: 'Secreto compartido',
      SHARE_REVOKED: 'Comp. revocada',
      GROUP_CREATED: 'Grupo creado',
      GROUP_UPDATED: 'Grupo actualizado',
      GROUP_DELETED: 'Grupo eliminado',
      MEMBER_ADDED: 'Miembro añadido',
      MEMBER_REMOVED: 'Miembro eliminado',
      ROLE_CHANGED: 'Rol cambiado',
      USER_CREATED: 'Usuario creado',
      USER_DEACTIVATED: 'Usuario desactiv.',
    };
    return names[action] || action.replace(/_/g, ' ');
  }

  formatShortDate(dateStr: string): string {
    const d = new Date(dateStr);
    return d.toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit' });
  }
}
