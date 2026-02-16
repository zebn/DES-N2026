import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { SecretsListComponent } from './secrets-list/secrets-list.component';

const routes: Routes = [
  { path: '', component: SecretsListComponent }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class SecretsRoutingModule { }
