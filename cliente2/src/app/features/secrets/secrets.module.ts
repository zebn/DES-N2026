import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';

// Material Modules
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { MatDialogModule } from '@angular/material/dialog';
import { MatMenuModule } from '@angular/material/menu';
import { MatPaginatorModule } from '@angular/material/paginator';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatRadioModule } from '@angular/material/radio';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatTabsModule } from '@angular/material/tabs';

import { SecretsRoutingModule } from './secrets-routing.module';
import { SecretsListComponent } from './secrets-list/secrets-list.component';
import { SecretCreateDialogComponent } from './secret-create-dialog/secret-create-dialog.component';
import { SecretDetailDialogComponent } from './secret-detail-dialog/secret-detail-dialog.component';
import { SecretShareDialogComponent } from './secret-share-dialog/secret-share-dialog.component';
import { SharedWithMeComponent } from './shared-with-me/shared-with-me.component';
import { SharedModule } from '../../shared/shared.module';

@NgModule({
  declarations: [
    SecretsListComponent,
    SecretCreateDialogComponent,
    SecretDetailDialogComponent,
    SecretShareDialogComponent,
    SharedWithMeComponent,
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    FormsModule,
    SecretsRoutingModule,
    SharedModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatProgressSpinnerModule,
    MatProgressBarModule,
    MatSnackBarModule,
    MatDialogModule,
    MatMenuModule,
    MatPaginatorModule,
    MatChipsModule,
    MatTooltipModule,
    MatRadioModule,
    MatCheckboxModule,
    MatTabsModule,
  ]
})
export class SecretsModule { }
