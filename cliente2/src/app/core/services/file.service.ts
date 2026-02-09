import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface SecureFile {
  id: number;
  title: string;
  filename: string;
  file_size: number;
  mime_type: string;
  classification_level: string;
  uploaded_at: string;
  owner_id: number;
  encrypted_content: string;
  encrypted_aes_key: string;
  counter: string;
  file_hash: string;
}

@Injectable({
  providedIn: 'root'
})
export class FileService {

  constructor(private http: HttpClient) { }

  uploadFile(fileData: {
    title: string;
    original_filename: string;
    file_size: number;
    mime_type: string;
    classification_level: string;
    encrypted_content: string;
    encrypted_aes_key: string;
    counter: string;
    file_hash: string;
    digital_signature?: string;
    description?: string;
  }): Observable<any> {
    return this.http.post(`${environment.apiUrl}/api/files/upload`, fileData);
  }

  listFiles(): Observable<{ files: SecureFile[] }> {
    return this.http.get<{ files: SecureFile[] }>(`${environment.apiUrl}/api/files/`);
  }

  getFileInfo(fileId: number): Observable<any> {
    return this.http.get(`${environment.apiUrl}/api/files/${fileId}`);
  }

  downloadFile(fileId: number): Observable<any> {
    return this.http.post(`${environment.apiUrl}/api/files/${fileId}/download`, {});
  }

  deleteFile(fileId: number): Observable<any> {
    return this.http.delete(`${environment.apiUrl}/api/files/${fileId}`);
  }

  shareFile(fileId: number, shareData: {
    recipient_email: string;
    password: string;
    encrypted_aes_key_for_recipient: string;
    can_download?: boolean;
    can_share?: boolean;
    expires_at?: string;
  }): Observable<any> {
    return this.http.post(`${environment.apiUrl}/api/files/${fileId}/share`, shareData);
  }

  listSharedFiles(): Observable<any> {
    return this.http.get(`${environment.apiUrl}/api/files/shared-with-me`);
  }

  downloadSharedFile(shareId: number, totpCode?: string): Observable<any> {
    return this.http.post(`${environment.apiUrl}/api/files/shared/${shareId}/download`, {
      totp_code: totpCode
    });
  }
}
