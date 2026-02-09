import { Component, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';

export interface ConfirmDialogData {
    title: string;
    message: string;
    confirmText?: string;
    cancelText?: string;
    confirmColor?: 'primary' | 'accent' | 'warn';
    icon?: string;
}

@Component({
    selector: 'app-confirm-dialog',
    template: `
    <h2 mat-dialog-title>
      <mat-icon [class]="data.confirmColor || 'warn'">{{ data.icon || 'warning' }}</mat-icon>
      {{ data.title }}
    </h2>
    <mat-dialog-content>
      <p>{{ data.message }}</p>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button (click)="onCancel()">
        {{ data.cancelText || 'Cancelar' }}
      </button>
      <button mat-raised-button [color]="data.confirmColor || 'warn'" (click)="onConfirm()">
        <mat-icon>{{ data.icon || 'check' }}</mat-icon>
        {{ data.confirmText || 'Confirmar' }}
      </button>
    </mat-dialog-actions>
  `,
    styles: [`
    h2 {
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0;
    }

    h2 mat-icon {
      font-size: 28px;
      width: 28px;
      height: 28px;
    }

    h2 mat-icon.warn {
      color: #f44336;
    }

    h2 mat-icon.primary {
      color: #3f51b5;
    }

    p {
      margin: 16px 0;
      font-size: 14px;
      color: #555;
    }

    mat-dialog-actions {
      padding: 16px 0 0 0;
    }
  `]
})
export class ConfirmDialogComponent {
    constructor(
        public dialogRef: MatDialogRef<ConfirmDialogComponent>,
        @Inject(MAT_DIALOG_DATA) public data: ConfirmDialogData
    ) { }

    onCancel(): void {
        this.dialogRef.close(false);
    }

    onConfirm(): void {
        this.dialogRef.close(true);
    }
}
