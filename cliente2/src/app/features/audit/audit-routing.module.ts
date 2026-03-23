import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AuditLogComponent } from './audit-log/audit-log.component';
import { AuditStatsComponent } from './audit-stats/audit-stats.component';

const routes: Routes = [
  { path: '', redirectTo: 'logs', pathMatch: 'full' },
  { path: 'logs', component: AuditLogComponent },
  { path: 'stats', component: AuditStatsComponent },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AuditRoutingModule { }
