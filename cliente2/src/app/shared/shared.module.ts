import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';

// Material Modules
import { MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

import { ConfirmDialogComponent } from './components/confirm-dialog/confirm-dialog.component';
import { UnlockDialogComponent } from './components/unlock-dialog/unlock-dialog.component';

@NgModule({
    declarations: [
        ConfirmDialogComponent,
        UnlockDialogComponent
    ],
    imports: [
        CommonModule,
        ReactiveFormsModule,
        MatDialogModule,
        MatButtonModule,
        MatIconModule,
        MatFormFieldModule,
        MatInputModule
    ],
    exports: [
        ConfirmDialogComponent,
        UnlockDialogComponent
    ]
})
export class SharedModule { }
