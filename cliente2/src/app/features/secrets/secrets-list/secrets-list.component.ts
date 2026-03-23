import { Component, OnInit } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatDialog } from '@angular/material/dialog';
import { PageEvent } from '@angular/material/paginator';
import {
  SecretsService, Secret, Folder,
  SecretType, SECRET_TYPE_LABELS, SECRET_TYPE_ICONS
} from '../../../core/services/secrets.service';
import { CryptoService } from '../../../core/services/crypto.service';
import { UnlockDialogComponent } from '../../../shared/components/unlock-dialog/unlock-dialog.component';
import { ConfirmDialogComponent } from '../../../shared/components/confirm-dialog/confirm-dialog.component';
import { SecretCreateDialogComponent } from '../secret-create-dialog/secret-create-dialog.component';
import { SecretDetailDialogComponent } from '../secret-detail-dialog/secret-detail-dialog.component';
