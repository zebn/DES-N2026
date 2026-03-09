import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';

// Material Modules
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { MatPaginatorModule } from '@angular/material/paginator';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDividerModule } from '@angular/material/divider';

import { AuditRoutingModule } from './audit-routing.module';
import { AuditLogComponent } from './audit-log/audit-log.component';
import { AuditStatsComponent } from './audit-stats/audit-stats.component';
import { SharedModule } from '../../shared/shared.module';

@NgModule({
  declarations: [
    AuditLogComponent,
    AuditStatsComponent,
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    AuditRoutingModule,
    SharedModule,
    MatCardModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatProgressSpinnerModule,
    MatSnackBarModule,
    MatPaginatorModule,
    MatChipsModule,
    MatTooltipModule,
    MatDividerModule,
  ]
})
export class AuditModule { }
