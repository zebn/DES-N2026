import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { FormControl, Validators } from '@angular/forms';
import { CryptoService } from '../../../core/services/crypto.service';

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
               (keyup.enter)="onSubmit()" autofocus [disabled]="loading">
        <mat-icon matPrefix>key</mat-icon>
        <mat-error *ngIf="passwordControl.hasError('required')">
          La contraseña es requerida
        </mat-error>
      </mat-form-field>

      <mat-error *ngIf="errorMessage" style="display:block; margin-top: 8px;">
        {{ errorMessage }}
      </mat-error>

      <div class="info-box">
        <mat-icon>info</mat-icon>
        <span>Tu contraseña nunca sale de este dispositivo y solo se usa para descifrar tu clave privada en memoria.</span>
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button (click)="onCancel()" [disabled]="loading">Cancelar</button>
      <button mat-raised-button color="primary" (click)="onSubmit()" 
              [disabled]="!passwordControl.valid || loading">
        <mat-icon>lock_open</mat-icon>
        {{ loading ? 'Desbloqueando...' : 'Desbloquear' }}
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
    loading = false;
    errorMessage = '';

    constructor(
        private dialogRef: MatDialogRef<UnlockDialogComponent>,
        private cryptoService: CryptoService
    ) { }

    async onSubmit(): Promise<void> {
        if (!this.passwordControl.valid || this.loading) return;

        this.loading = true;
        this.errorMessage = '';

        try {
            await this.cryptoService.unlockPrivateKey(this.passwordControl.value as string);
            this.dialogRef.close(true);
        } catch (err: any) {
            this.errorMessage = 'Contraseña incorrecta. Inténtalo de nuevo.';
            this.passwordControl.setValue('');
        } finally {
            this.loading = false;
        }
    }

    onCancel(): void {
        this.dialogRef.close(false);
    }
}
