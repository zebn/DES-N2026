import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { FileListComponent } from './file-list/file-list.component';
import { FileUploadComponent } from './file-upload/file-upload.component';
import { SharedFilesComponent } from './shared-files/shared-files.component';

const routes: Routes = [
  { path: '', component: FileListComponent },
  { path: 'upload', component: FileUploadComponent },
  { path: 'shared', component: SharedFilesComponent }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class FilesRoutingModule { }
