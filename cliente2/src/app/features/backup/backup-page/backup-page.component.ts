import { Component } from '@angular/core';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-backup-page',
  template: `
    <div class="backup-page">
      <div class="page-header">
        <mat-icon class="page-icon">backup</mat-icon>
        <div>
          <h1>Backup y Restauración</h1>
          <p class="page-subtitle">
            Exporta e importa tus secretos en un archivo cifrado con Argon2id + AES-256-CTR.
            El servidor nunca accede al contenido de tus secretos.
          </p>
        </div>
      </div>

      <mat-tab-group animationDuration="200ms" mat-stretch-tabs="false">

        <!-- Exportar -->
        <mat-tab>
          <ng-template mat-tab-label>
            <mat-icon class="tab-icon">download</mat-icon>
            Exportar
          </ng-template>
          <div class="tab-content">
            <app-export-backup></app-export-backup>
          </div>
        </mat-tab>

        <!-- Importar -->
        <mat-tab>
          <ng-template mat-tab-label>
            <mat-icon class="tab-icon">restore</mat-icon>
            Importar
          </ng-template>
          <div class="tab-content">
            <app-import-backup></app-import-backup>
          </div>
        </mat-tab>

        <!-- Backup del sistema (solo ADMIN) -->
        <mat-tab *ngIf="isAdmin">
          <ng-template mat-tab-label>
            <mat-icon class="tab-icon admin-tab-icon">admin_panel_settings</mat-icon>
            Sistema
          </ng-template>
          <div class="tab-content">
            <app-system-backup></app-system-backup>
          </div>
        </mat-tab>

      </mat-tab-group>
    </div>
  `,
  styles: [`
    .backup-page { padding: 24px; max-width: 720px; margin: 0 auto; }

    .page-header {
      display: flex; align-items: flex-start; gap: 16px; margin-bottom: 28px;
    }
    .page-icon {
      font-size: 40px; height: 40px; width: 40px;
      color: var(--mdc-theme-primary, #3f51b5); flex-shrink: 0;
    }
    h1 { margin: 0 0 4px; font-size: 24px; font-weight: 500; }
    .page-subtitle { margin: 0; font-size: 14px; color: rgba(0,0,0,.6); }

    .tab-icon { margin-right: 6px; vertical-align: middle; font-size: 18px; }
    .admin-tab-icon { color: #f44336; }

    .tab-content { padding-top: 20px; }

    ::ng-deep .backup-card {
      border-radius: 8px;
    }
    ::ng-deep .backup-card mat-card-header {
      margin-bottom: 12px;
    }
    ::ng-deep .section-icon {
      font-size: 30px !important;
      height: 30px !important;
      width: 30px !important;
      color: var(--mdc-theme-primary, #3f51b5);
    }
  `]
})
export class BackupPageComponent {
  isAdmin: boolean;

  constructor(private auth: AuthService) {
    this.isAdmin = this.auth.isAdmin();
  }
}
