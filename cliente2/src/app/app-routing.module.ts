import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AuthGuard } from './core/guards/auth.guard';
import { RoleGuard } from './core/guards/role.guard';

const routes: Routes = [
  {
    path: '',
    redirectTo: '/secrets',
    pathMatch: 'full'
  },
  {
    path: 'auth',
    loadChildren: () => import('./features/auth/auth.module').then(m => m.AuthModule)
  },
  {
    path: 'files',
    loadChildren: () => import('./features/files/files.module').then(m => m.FilesModule),
    canActivate: [AuthGuard]
  },
  {
    path: 'secrets',
    loadChildren: () => import('./features/secrets/secrets.module').then(m => m.SecretsModule),
    canActivate: [AuthGuard]
  },
  {
    path: 'folders',
    loadChildren: () => import('./features/folders/folders.module').then(m => m.FoldersModule),
    canActivate: [AuthGuard]
  },
  {
    path: 'profile',
    loadChildren: () => import('./features/profile/profile.module').then(m => m.ProfileModule),
    canActivate: [AuthGuard]
  },
  {
    path: 'admin',
    loadChildren: () => import('./features/admin/admin.module').then(m => m.AdminModule),
    canActivate: [AuthGuard, RoleGuard],
    data: { roles: ['ADMIN'] }
  },
  {
    path: 'audit',
    loadChildren: () => import('./features/audit/audit.module').then(m => m.AuditModule),
    canActivate: [AuthGuard, RoleGuard],
    data: { roles: ['ADMIN', 'AUDITOR'] }
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
