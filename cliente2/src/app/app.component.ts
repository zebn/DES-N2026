import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './core/services/auth.service';

@Component({
  selector: 'app-root',
  template: `
    <!-- Splash Screen -->
    <app-splash-screen *ngIf="showSplash" (completed)="onSplashCompleted()"></app-splash-screen>

    <div class="app-container" *ngIf="!showSplash">
      <mat-toolbar color="primary" class="app-toolbar">
        <button mat-icon-button (click)="sidenav.toggle()" *ngIf="isAuthenticated">
          <mat-icon>menu</mat-icon>
        </button>
        
        <span class="app-title">
          <mat-icon class="shield-icon">shield</mat-icon>
          MILCOM secure exchange - Inteligencia militar "Zero Trust"
        </span>
        
        <span class="spacer"></span>
        
        <div class="user-menu" *ngIf="isAuthenticated">
          <button mat-icon-button [matMenuTriggerFor]="menu">
            <mat-icon>account_circle</mat-icon>
          </button>
          <mat-menu #menu="matMenu">
            <button mat-menu-item (click)="viewProfile()">
              <mat-icon>person</mat-icon>
              <span>Perfil</span>
            </button>
            <button mat-menu-item (click)="logout()">
              <mat-icon>logout</mat-icon>
              <span>Cerrar Sesión</span>
            </button>
          </mat-menu>
        </div>
      </mat-toolbar>

      <mat-sidenav-container class="sidenav-container">
        <mat-sidenav #sidenav mode="side" [opened]="isAuthenticated" class="app-sidenav">
          <mat-nav-list>
            <a mat-list-item routerLink="/files" routerLinkActive="active-link">
              <mat-icon matListItemIcon>folder</mat-icon>
              <span matListItemTitle>Mis Archivos</span>
            </a>
            
            <a mat-list-item routerLink="/files/upload" routerLinkActive="active-link">
              <mat-icon matListItemIcon>cloud_upload</mat-icon>
              <span matListItemTitle>Subir Archivo</span>
            </a>
            
            <a mat-list-item routerLink="/files/shared" routerLinkActive="active-link">
              <mat-icon matListItemIcon>people</mat-icon>
              <span matListItemTitle>Compartidos</span>
            </a>
            
            <mat-divider></mat-divider>

            <a mat-list-item routerLink="/secrets" routerLinkActive="active-link">
              <mat-icon matListItemIcon>lock</mat-icon>
              <span matListItemTitle>Bóveda de Secretos</span>
            </a>
            
            <mat-divider></mat-divider>
            
            <a mat-list-item routerLink="/profile" routerLinkActive="active-link">
              <mat-icon matListItemIcon>person</mat-icon>
              <span matListItemTitle>Perfil</span>
            </a>
            
            <a mat-list-item (click)="logout()">
              <mat-icon matListItemIcon>logout</mat-icon>
              <span matListItemTitle>Cerrar Sesión</span>
            </a>
          </mat-nav-list>
        </mat-sidenav>

        <mat-sidenav-content class="main-content">
          <router-outlet></router-outlet>
        </mat-sidenav-content>
      </mat-sidenav-container>
    </div>
  `,
  styles: [`
    .app-container {
      height: 100vh;
      display: flex;
      flex-direction: column;
    }

    .app-toolbar {
      z-index: 2;
      position: sticky;
      top: 0;
    }

    .app-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 500;
      font-size: 20px;
    }

    .shield-icon {
      color: #ffd700;
    }

    .spacer {
      flex: 1 1 auto;
    }

    .sidenav-container {
      flex: 1;
      overflow: hidden;
    }

    .app-sidenav {
      width: 250px;
      padding: 16px 0;
    }

    .main-content {
      padding: 20px;
      background-color: #fafafa;
    }

    .active-link {
      background-color: rgba(63, 81, 181, 0.1);
      color: #3f51b5;
    }

    ::ng-deep .mat-mdc-list-item-title {
      margin-left: 16px;
    }
  `]
})
export class AppComponent implements OnInit {
  isAuthenticated = false;
  showSplash = true;

  constructor(
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit() {
    // Splash screen will hide itself when both phases complete

    // Subscribe to auth state
    this.authService.currentUser$.subscribe((user: any) => {
      this.isAuthenticated = !!user;
      if (!user && !this.router.url.includes('/auth')) {
        this.router.navigate(['/auth/login']);
      }
    });
  }

  onSplashCompleted() {
    console.log('[App] Splash completed, hiding splash screen');
    this.showSplash = false;
  }

  viewProfile() {
    this.router.navigate(['/profile']);
  }

  logout() {
    this.authService.logout();
    this.router.navigate(['/auth/login']);
  }
}
