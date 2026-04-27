import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface Secret {
  id: string;
  owner_id: number;
  title: string;
  url?: string;
  secret_type: string;
  tags: string | null;
  folder_id: string | null;
  version: number;
  content_hash: string;
  expires_at: string | null;
  rotation_period_days: number | null;
  last_rotated_at: string | null;
  created_at: string;
  updated_at: string;
  // Only when include_encrypted
  encrypted_data?: string;
  encrypted_aes_key?: string;
  digital_signature?: string;
}

export interface SecretListResponse {
  secrets: Secret[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface Folder {
  id: string;
  owner_id?: number;
  name: string;
  parent_id: string | null;
  created_at: string;
  updated_at?: string;
}

export interface SecretVersion {
  id: string;
  secret_id: string;
  version_number: number;
  content_hash: string;
  changed_by_id: number;
  change_reason: string | null;
  created_at: string;
}

export interface SecretShare {
  id: string;
  secret_id: string;
  shared_by_id: number;
  shared_by_email: string | null;
  shared_with_user_id: number;
  shared_with_user_email: string | null;
  shared_with_user_name: string | null;
  shared_with_group_id: string | null;
  shared_with_group_name: string | null;
  can_read: boolean;
  can_edit: boolean;
  can_share: boolean;
  shared_at: string;
  expires_at: string | null;
  is_revoked: boolean;
  revoked_at: string | null;
  is_active: boolean;
  encrypted_aes_key_for_recipient?: string;
  secret?: {
    id: string;
    title: string;
    url?: string | null;
    secret_type: string;
    version: number;
    content_hash: string;
    updated_at: string;
    owner_id: number;
    owner_public_key: string;
  };
}

export interface ShareRecipient {
  user_id: number;
  encrypted_aes_key_for_recipient: string;
}

export interface SharePermissions {
  can_read?: boolean;
  can_edit?: boolean;
  can_share?: boolean;
  expires_at?: string;
}

export type SecretType = 'PASSWORD' | 'API_KEY' | 'CERTIFICATE' | 'SSH_KEY' | 'NOTE' | 'DATABASE' | 'ENV_VARIABLE' | 'IDENTITY';

export const SECRET_TYPE_LABELS: Record<SecretType, string> = {
  PASSWORD: 'Contraseña',
  API_KEY: 'Clave API',
  CERTIFICATE: 'Certificado',
  SSH_KEY: 'Clave SSH',
  NOTE: 'Nota segura',
  DATABASE: 'Base de datos',
  ENV_VARIABLE: 'Variable de entorno',
  IDENTITY: 'Identidad',
};

export const SECRET_TYPE_ICONS: Record<SecretType, string> = {
  PASSWORD: 'password',
  API_KEY: 'vpn_key',
  CERTIFICATE: 'verified_user',
  SSH_KEY: 'terminal',
  NOTE: 'sticky_note_2',
  DATABASE: 'storage',
  ENV_VARIABLE: 'code',
  IDENTITY: 'badge',
};

@Injectable({
  providedIn: 'root'
})
export class SecretsService {
  private apiUrl = `${environment.apiUrl}/api/secrets`;
  private foldersUrl = `${environment.apiUrl}/api/folders`;

  constructor(private http: HttpClient) {}

  // ─── Secrets CRUD ──────────────────────────────────────────────────

  listSecrets(params?: {
    type?: string;
    folder_id?: string;
    search?: string;
    page?: number;
    per_page?: number;
  }): Observable<SecretListResponse> {
    let httpParams = new HttpParams();
    if (params?.type) httpParams = httpParams.set('type', params.type);
    if (params?.folder_id) httpParams = httpParams.set('folder_id', params.folder_id);
    if (params?.search) httpParams = httpParams.set('search', params.search);
    if (params?.page) httpParams = httpParams.set('page', params.page.toString());
    if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());

    return this.http.get<SecretListResponse>(this.apiUrl, { params: httpParams });
  }

  getSecret(id: string): Observable<{ secret: Secret }> {
    return this.http.get<{ secret: Secret }>(`${this.apiUrl}/${id}`);
  }

  decryptSecret(id: string): Observable<{ secret: Secret }> {
    return this.http.post<{ secret: Secret }>(`${this.apiUrl}/${id}/decrypt`, {});
  }

  createSecret(data: {
    title: string;
    secret_type: string;
    encrypted_data: string;
    encrypted_aes_key: string;
    content_hash: string;
    digital_signature: string;
    tags?: string;
    folder_id?: string;
    expires_at?: string;
    rotation_period_days?: number;
  }): Observable<{ message: string; secret: Secret }> {
    return this.http.post<{ message: string; secret: Secret }>(this.apiUrl, data);
  }

  updateSecret(id: string, data: {
    encrypted_data: string;
    encrypted_aes_key: string;
    content_hash: string;
    digital_signature: string;
    title?: string;
    tags?: string;
    folder_id?: string;
    change_reason?: string;
    expires_at?: string;
    rotation_period_days?: number;
  }): Observable<{ message: string; secret: Secret; version: number }> {
    return this.http.put<{ message: string; secret: Secret; version: number }>(`${this.apiUrl}/${id}`, data);
  }

  deleteSecret(id: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/${id}`);
  }

  getVersions(id: string): Observable<{ versions: SecretVersion[]; total: number }> {
    return this.http.get<{ versions: SecretVersion[]; total: number }>(`${this.apiUrl}/${id}/versions`);
  }

  verifyIntegrity(id: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/${id}/verify`, {});
  }

  // ─── Compartición (RF04) ──────────────────────────────────────────

  shareSecret(
    secretId: string,
    payload: {
      target_type: 'user' | 'group';
      target_id: number | string;
      recipients: ShareRecipient[];
      can_read?: boolean;
      can_edit?: boolean;
      can_share?: boolean;
      expires_at?: string;
    }
  ): Observable<{ message: string; share_ids: string[]; recipient_count: number }> {
    return this.http.post<{ message: string; share_ids: string[]; recipient_count: number }>(
      `${this.apiUrl}/${secretId}/share`,
      payload
    );
  }

  listSharedWithMe(params?: { page?: number; per_page?: number }):
      Observable<{ shares: SecretShare[]; total: number; page: number; per_page: number; pages: number }> {
    let httpParams = new HttpParams();
    if (params?.page) httpParams = httpParams.set('page', params.page.toString());
    if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
    return this.http.get<{ shares: SecretShare[]; total: number; page: number; per_page: number; pages: number }>(
      `${this.apiUrl}/shared-with-me`, { params: httpParams }
    );
  }

  listShares(secretId: string): Observable<{ shares: SecretShare[]; total: number }> {
    return this.http.get<{ shares: SecretShare[]; total: number }>(
      `${this.apiUrl}/${secretId}/shares`
    );
  }

  revokeShare(shareId: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/shares/${shareId}`);
  }

  accessSharedSecret(shareId: string): Observable<{
    share: SecretShare;
    secret: {
      id: string;
      title: string;
      url?: string | null;
      secret_type: string;
      version: number;
      content_hash: string;
      encrypted_data: string;
      digital_signature: string;
      tags: string | null;
      expires_at: string | null;
      updated_at: string;
      owner_id: number;
      owner_public_key: string;
    };
  }> {
    return this.http.post<any>(`${this.apiUrl}/shares/${shareId}/access`, {});
  }

  // ─── Folders ───────────────────────────────────────────────────────

  listFolders(): Observable<{ folders: Folder[] }> {
    return this.http.get<{ folders: Folder[] }>(this.foldersUrl);
  }

  createFolder(name: string, parentId?: string): Observable<{ message: string; folder: Folder }> {
    return this.http.post<{ message: string; folder: Folder }>(this.foldersUrl, {
      name,
      parent_id: parentId
    });
  }

  updateFolder(id: string, data: { name?: string; parent_id?: string }): Observable<{ message: string; folder: Folder }> {
    return this.http.put<{ message: string; folder: Folder }>(`${this.foldersUrl}/${id}`, data);
  }

  deleteFolder(id: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.foldersUrl}/${id}`);
  }
}
