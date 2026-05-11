import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface UserSession {
  id: string;
  ip_address: string | null;
  user_agent: string | null;
  device_info: string | null;
  created_at: string;
  last_activity: string;
  expires_at: string;
  is_revoked: boolean;
  revoked_at: string | null;
  revoked_reason: string | null;
  is_current: boolean;
}

@Injectable({ providedIn: 'root' })
export class SessionsService {
  private readonly base = `${environment.apiUrl}/api/auth/sessions`;

  constructor(private http: HttpClient) {}

  list(includeRevoked = false): Observable<{ sessions: UserSession[] }> {
    const params = new HttpParams().set('include_revoked', includeRevoked ? 'true' : 'false');
    return this.http.get<{ sessions: UserSession[] }>(this.base, { params });
  }

  revoke(sessionId: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.base}/${sessionId}`);
  }

  revokeAll(): Observable<{ message: string; revoked_count: number }> {
    return this.http.delete<{ message: string; revoked_count: number }>(this.base);
  }
}
