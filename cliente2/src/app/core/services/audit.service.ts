import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface AuditLogEntry {
  id: number;
  user_id: number;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  details: string | null;
  ip_address: string | null;
  success: boolean;
  timestamp: string;
}

export interface AuditLogResponse {
  logs: AuditLogEntry[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface SecretAccessLogEntry {
  id: number;
  user_id: number;
  secret_id: string;
  action: string;
  ip_address: string | null;
  timestamp: string;
}

export interface AuditStats {
  total_events: number;
  period_days: number;
  actions_count: Record<string, number>;
  top_users: Array<{ user_id: number; email: string; count: number }>;
  success_rate: number;
  events_by_day: Array<{ date: string; count: number }>;
}

export interface AuditLogFilters {
  action?: string;
  resource_type?: string;
  user_id?: number;
  success?: boolean;
  from_date?: string;
  to_date?: string;
  page?: number;
  per_page?: number;
}

@Injectable({
  providedIn: 'root'
})
export class AuditService {
  private apiUrl = `${environment.apiUrl}/api/audit`;

  constructor(private http: HttpClient) {}

  // ─── Global Logs (ADMIN, AUDITOR) ───────────────────────────────

  getGlobalLogs(filters?: AuditLogFilters): Observable<AuditLogResponse> {
    const params = this.buildParams(filters);
    return this.http.get<AuditLogResponse>(`${this.apiUrl}/logs`, { params });
  }

  // ─── User Logs ──────────────────────────────────────────────────

  getUserLogs(userId: number, filters?: AuditLogFilters): Observable<AuditLogResponse> {
    const params = this.buildParams(filters);
    return this.http.get<AuditLogResponse>(`${this.apiUrl}/logs/user/${userId}`, { params });
  }

  // ─── My Logs ────────────────────────────────────────────────────

  getMyLogs(filters?: AuditLogFilters): Observable<AuditLogResponse> {
    const params = this.buildParams(filters);
    return this.http.get<AuditLogResponse>(`${this.apiUrl}/logs/me`, { params });
  }

  // ─── Secret Logs ────────────────────────────────────────────────

  getSecretLogs(secretId: string, filters?: AuditLogFilters): Observable<{
    logs: SecretAccessLogEntry[];
    total: number;
    page: number;
    per_page: number;
    pages: number;
  }> {
    const params = this.buildParams(filters);
    return this.http.get<any>(`${this.apiUrl}/logs/secret/${secretId}`, { params });
  }

  // ─── Stats (ADMIN, AUDITOR) ─────────────────────────────────────

  getStats(days?: number): Observable<AuditStats> {
    let params = new HttpParams();
    if (days) params = params.set('days', days.toString());
    return this.http.get<AuditStats>(`${this.apiUrl}/stats`, { params });
  }

  // ─── Export (ADMIN) ─────────────────────────────────────────────

  exportLogs(filters?: { from_date?: string; to_date?: string; format?: string }): Observable<any> {
    return this.http.post(`${this.apiUrl}/export`, filters || {});
  }

  // ─── Helpers ────────────────────────────────────────────────────

  private buildParams(filters?: AuditLogFilters): HttpParams {
    let params = new HttpParams();
    if (!filters) return params;

    if (filters.action) params = params.set('action', filters.action);
    if (filters.resource_type) params = params.set('resource_type', filters.resource_type);
    if (filters.user_id) params = params.set('user_id', filters.user_id.toString());
    if (filters.success !== undefined) params = params.set('success', filters.success.toString());
    if (filters.from_date) params = params.set('from_date', filters.from_date);
    if (filters.to_date) params = params.set('to_date', filters.to_date);
    if (filters.page) params = params.set('page', filters.page.toString());
    if (filters.per_page) params = params.set('per_page', filters.per_page.toString());

    return params;
  }
}
