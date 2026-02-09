import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';
import { NotificationService } from '../../../core/services/notification.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent {
  loginForm: FormGroup;
  loading = false;
  hidePassword = true;
  requires2FA = false;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    private notificationService: NotificationService
  ) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]],
      totpCode: ['']
    });
  }

  onSubmit() {
    if (this.loginForm.invalid) {
      this.notificationService.warning(
        '⚠️ Formulario Incompleto',
        'Por favor completa todos los campos requeridos',
        ['Email válido requerido', 'Contraseña requerida']
      );
      return;
    }

    // If 2FA is required but code not provided, show error
    if (this.requires2FA && !this.loginForm.value.totpCode) {
      this.notificationService.warning(
        '⚠️ Código 2FA Requerido',
        'Por favor ingresa el código de tu aplicación de autenticación',
        ['Abre tu app de autenticación', 'Ingresa el código de 6 dígitos']
      );
      return;
    }

    this.loading = true;
    const { email, password, totpCode } = this.loginForm.value;

    this.notificationService.info(
      '🔄 Autenticando Usuario',
      'Verificando credenciales en el servidor...',
      ['Conectando con servidor Zero Trust', 'Validando email y contraseña']
    );

    this.authService.login(email, password, totpCode).subscribe({
      next: (response) => {
        // Check if 2FA is required (server returns 200 with requires_2fa)
        if (response.requires_2fa) {
          this.loading = false;
          this.requires2FA = true;
          this.notificationService.twoFactorRequired();
          return;
        }

        const userName = response.user?.nombre || email;
        this.notificationService.loginSuccess(userName);
        setTimeout(() => {
          this.router.navigate(['/files']);
        }, 2000);
      },
      error: (error) => {
        this.loading = false;
        const errorMsg = error.error?.error || error.message || 'Error de conexión con el servidor';
        this.notificationService.error(
          '❌ Error de Autenticación',
          errorMsg,
          [
            'Verifica tu email y contraseña',
            this.requires2FA ? 'Verifica el código 2FA' : '',
            'Asegúrate de estar conectado al servidor',
            error.status ? `Código de error: ${error.status}` : 'Sin conexión al servidor'
          ].filter(m => m)
        );
      }
    });
  }
}
