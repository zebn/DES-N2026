import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { SecretsListComponent } from './secrets-list/secrets-list.component';
import { SharedWithMeComponent } from './shared-with-me/shared-with-me.component';

const routes: Routes = [
  { path: '', component: SecretsListComponent },
  { path: 'shared-with-me', component: SharedWithMeComponent },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class SecretsRoutingModule { }
