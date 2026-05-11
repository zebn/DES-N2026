import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface KdfParams {
  algorithm: string;
  time_cost: number;
  memory_cost: number;
  parallelism: number;
  salt: string;
  hash_len: number;
}

export interface VaultEnvelope {
  format_version: string;
  created_at: string;
  user_id?: number;
  user_email?: string;
  scope: 'personal' | 'system';
  secret_count?: number;
  total_users?: number;
  total_secrets?: number;
  kdf_params: KdfParams;
  iv: string;
  encrypted_payload: string;
  payload_hash: string;
}

export interface ExportRequest {
  backup_password: string;
  totp_code?: string;
  include_versions?: boolean;
}

export interface ImportRequest {
  vault: VaultEnvelope;
  backup_password: string;
  totp_code?: string;
  merge?: boolean;
}

export interface ImportResult {
  message: string;
  imported: number;
  skipped: number;
  overwritten: number;
  errors: string[] | null;
}

export interface SystemBackupRequest {
  backup_password: string;
  totp_code?: string;
}

@Injectable({
  providedIn: 'root'
})
export class BackupService {
  private apiUrl = `${environment.apiUrl}/api/backup`;

  constructor(private http: HttpClient) {}

  /**
   * Solicita exportación de secretos propios; el servidor devuelve un blob JSON (.vault).
   */
  exportBackup(payload: ExportRequest): Observable<Blob> {
    return this.http.post(`${this.apiUrl}/export`, payload, {
      responseType: 'blob'
    });
  }

  /**
   * Importa un vault previamente exportado.
   */
  importBackup(payload: ImportRequest): Observable<ImportResult> {
    return this.http.post<ImportResult>(`${this.apiUrl}/import`, payload);
  }

  /**
   * Exportación completa del sistema (solo ADMIN).
   */
  systemBackup(payload: SystemBackupRequest): Observable<Blob> {
    return this.http.post(`${this.apiUrl}/system`, payload, {
      responseType: 'blob'
    });
  }

  /** Dispara descarga del blob como archivo .vault en el navegador. */
  downloadBlob(blob: Blob, filename: string): void {
    const url  = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href  = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }
}
