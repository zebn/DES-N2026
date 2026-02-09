import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';

// Material Modules
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { MatDialogModule } from '@angular/material/dialog';
import { MatMenuModule } from '@angular/material/menu';
import { MatPaginatorModule } from '@angular/material/paginator';
import { MatDividerModule } from '@angular/material/divider';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatAutocompleteModule } from '@angular/material/autocomplete';

import { FilesRoutingModule } from './files-routing.module';
import { FileListComponent } from './file-list/file-list.component';
import { FileUploadComponent } from './file-upload/file-upload.component';
import { ShareFileDialogComponent } from './share-file-dialog/share-file-dialog.component';
import { SharedFilesComponent } from './shared-files/shared-files.component';
import { SharedModule } from '../../shared/shared.module';

@NgModule({
  declarations: [
    FileListComponent,
    FileUploadComponent,
    ShareFileDialogComponent,
    SharedFilesComponent
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    FilesRoutingModule,
    SharedModule,
    MatCardModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatChipsModule,
    MatTooltipModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatProgressBarModule,
    MatSnackBarModule,
    MatDialogModule,
    MatMenuModule,
    MatPaginatorModule,
    MatDividerModule,
    MatCheckboxModule,
    MatAutocompleteModule
  ]
})
export class FilesModule { }
