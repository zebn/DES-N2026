import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { BackupPageComponent } from './backup-page/backup-page.component';

const routes: Routes = [
  { path: '', component: BackupPageComponent }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class BackupRoutingModule {}
