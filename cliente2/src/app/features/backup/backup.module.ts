import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';

// Angular Material
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatRadioModule } from '@angular/material/radio';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTabsModule } from '@angular/material/tabs';
import { MatTooltipModule } from '@angular/material/tooltip';

import { BackupRoutingModule } from './backup-routing.module';

import { BackupPageComponent }   from './backup-page/backup-page.component';
import { ExportBackupComponent } from './export-backup/export-backup.component';
import { ImportBackupComponent } from './import-backup/import-backup.component';
import { SystemBackupComponent } from './system-backup/system-backup.component';

@NgModule({
  declarations: [
    BackupPageComponent,
    ExportBackupComponent,
    ImportBackupComponent,
    SystemBackupComponent,
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    BackupRoutingModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatFormFieldModule,
    MatInputModule,
    MatCheckboxModule,
    MatRadioModule,
    MatProgressSpinnerModule,
    MatSnackBarModule,
    MatTabsModule,
    MatTooltipModule,
  ]
})
export class BackupModule {}
