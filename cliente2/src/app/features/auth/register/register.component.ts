import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';
import { NotificationService } from '../../../core/services/notification.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent {
  registerForm: FormGroup;
  loading = false;
  hidePassword = true;
  hidePasswordConfirm = true;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    private notificationService: NotificationService
  ) {
    this.registerForm = this.fb.group({
      nombre: ['', [Validators.required]],
      apellidos: ['', [Validators.required]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]],
      passwordConfirm: ['', [Validators.required]],
      clearance_level: ['CONFIDENTIAL']
    }, { validators: this.passwordMatchValidator });
  }

  passwordMatchValidator(g: FormGroup) {
    return g.get('password')?.value === g.get('passwordConfirm')?.value
      ? null : { 'mismatch': true };
  }

  async onSubmit() {
    if (this.registerForm.invalid) {
      if (this.registerForm.hasError('mismatch')) {
        this.notificationService.error(
          '❌ Las Contraseñas No Coinciden',
          'Por favor verifica que ambas contraseñas sean idénticas',
          ['Revisa el campo de contraseña', 'Revisa el campo de confirmación']
        );
      } else {
        this.notificationService.warning(
          '⚠️ Formulario Incompleto',
          'Por favor completa todos los campos requeridos',
          [
            'Nombre y apellidos son obligatorios',
            'Email válido requerido',
            'Contraseña mínimo 6 caracteres',
            'Nivel de clasificación requerido'
          ]
        );
      }
      return;
    }

    this.loading = true;
    const { nombre, apellidos, email, password, clearance_level } = this.registerForm.value;
    const fullName = `${nombre} ${apellidos}`;

    try {
      // Mostrar notificación de inicio de proceso
      this.notificationService.rsaKeyGeneration();
      
      // Esperar un momento para que se vea la notificación
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      await this.authService.register({
        nombre,
        apellidos,
        email,
        password,
        clearance_level
      });

      this.notificationService.registrationSuccess(fullName);
      
      // Redirigir después de mostrar la notificación
      setTimeout(() => {
        this.router.navigate(['/auth/login']);
      }, 3000);
    } catch (error: any) {
      this.loading = false;
      const errorMsg = error.error?.error || error.message || 'Error al procesar el registro';
      this.notificationService.error(
        '❌ Error en el Registro',
        errorMsg,
        [
          'Verifica que el email no esté registrado',
          'Asegúrate de tener conexión al servidor',
          'Intenta con un email diferente',
          error.status ? `Código de error: ${error.status}` : 'Sin conexión al servidor'
        ]
      );
    }
  }
}
