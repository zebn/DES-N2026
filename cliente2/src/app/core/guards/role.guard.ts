import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, Router, UrlTree } from '@angular/router';
import { Observable } from 'rxjs';
import { map, take } from 'rxjs/operators';
import { AuthService, UserRole } from '../services/auth.service';

/**
 * Guard que protege rutas requiriendo un rol específico.
 * Se configura en la ruta con `data: { roles: ['ADMIN', 'MANAGER'] }`.
 *
 * Ejemplo de uso en routing:
 * ```
 * {
 *   path: 'admin',
 *   component: AdminComponent,
 *   canActivate: [AuthGuard, RoleGuard],
 *   data: { roles: ['ADMIN'] }
 * }
 * ```
 */
@Injectable({
  providedIn: 'root'
})
export class RoleGuard implements CanActivate {

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  canActivate(route: ActivatedRouteSnapshot): Observable<boolean | UrlTree> {
    const requiredRoles = route.data['roles'] as UserRole[];

    return this.authService.currentUser$.pipe(
      take(1),
      map(user => {
        if (!user) {
          return this.router.createUrlTree(['/auth/login']);
        }

        if (requiredRoles && requiredRoles.length > 0) {
          if (requiredRoles.includes(user.role)) {
            return true;
          }
          // Sin permisos — redirigir a la página principal
          return this.router.createUrlTree(['/secrets']);
        }

        return true;
      })
    );
  }
}
