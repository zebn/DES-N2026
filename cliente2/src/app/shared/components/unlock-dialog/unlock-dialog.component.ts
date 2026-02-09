import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { FormControl, Validators } from '@angular/forms';

@Component({
    selector: 'app-unlock-dialog',
    template: `
    <h2 mat-dialog-title>
      <mat-icon>lock</mat-icon>
      Desbloquear Clave Privada
    </h2>
    <mat-dialog-content>
      <p class="description">
        Para realizar operaciones criptográficas, necesitas desbloquear tu clave privada con tu contraseña.
      </p>
      
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Contraseña</mat-label>
        <input matInput type="password" [formControl]="passwordControl" 
               (keyup.enter)="onSubmit()" autofocus>
        <mat-icon matPrefix>key</mat-icon>
        <mat-error *ngIf="passwordControl.hasError('required')">
          La contraseña es requerida
        </mat-error>
      </mat-form-field>

      <div class="info-box">
        <mat-icon>info</mat-icon>
        <span>Tu contraseña nunca sale de este dispositivo y solo se usa para descifrar tu clave privada en memoria.</span>
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button (click)="onCancel()">Cancelar</button>
      <button mat-raised-button color="primary" (click)="onSubmit()" 
              [disabled]="!passwordControl.valid">
        <mat-icon>lock_open</mat-icon>
        Desbloquear
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

    .description {
      margin-bottom: 20px;
      color: #666;
    }

    .full-width {
      width: 100%;
    }

    .info-box {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      padding: 12px;
      background-color: #e3f2fd;
      border-radius: 4px;
      margin-top: 16px;
      font-size: 13px;
      color: #1565c0;
    }

    .info-box mat-icon {
      font-size: 18px;
      width: 18px;
      height: 18px;
      margin-top: 2px;
    }

    mat-dialog-content {
      min-width: 400px;
      padding: 20px;
    }
  `]
})
export class UnlockDialogComponent {
    passwordControl = new FormControl('', Validators.required);

    constructor(
        private dialogRef: MatDialogRef<UnlockDialogComponent>
    ) { }

    onSubmit(): void {
        if (this.passwordControl.valid) {
            this.dialogRef.close(this.passwordControl.value);
        }
    }

    onCancel(): void {
        this.dialogRef.close(null);
    }
}
