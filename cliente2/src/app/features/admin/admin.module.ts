import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';

import { AdminRoutingModule } from './admin-routing.module';
import { SharedModule } from '../../shared/shared.module';
import { AdminPanelComponent } from './admin-panel/admin-panel.component';

// Material
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatDividerModule } from '@angular/material/divider';
import { MatMenuModule } from '@angular/material/menu';
import { MatDialogModule } from '@angular/material/dialog';
import { MatPaginatorModule } from '@angular/material/paginator';
import { MatSortModule } from '@angular/material/sort';

@NgModule({
  declarations: [AdminPanelComponent],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    AdminRoutingModule,
    SharedModule,
    MatCardModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatChipsModule,
    MatTooltipModule,
    MatSelectModule,
    MatFormFieldModule,
    MatSnackBarModule,
    MatProgressSpinnerModule,
    MatDividerModule,
    MatMenuModule,
    MatDialogModule,
    MatPaginatorModule,
    MatSortModule
  ]
})
export class AdminModule { }
