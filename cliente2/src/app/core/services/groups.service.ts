import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export type GroupRole = 'OWNER' | 'ADMIN' | 'MEMBER' | 'READONLY';

export interface GroupMember {
  membership_id: string;
  user_id: number;
  email: string;
  nombre: string;
  apellidos: string;
  role_in_group: GroupRole;
  added_by_id: number;
  joined_at: string;
}

export interface Group {
  id: string;
  name: string;
  description: string | null;
  created_by_id: number;
  created_at: string;
  updated_at: string;
  member_count?: number;
  my_role?: GroupRole;
  members?: GroupMember[];
}

export interface GroupListResponse {
  groups: Group[];
  page: number;
  per_page: number;
  total: number;
  pages: number;
}

@Injectable({
  providedIn: 'root'
})
export class GroupsService {
  private apiUrl = `${environment.apiUrl}/api/groups`;

  constructor(private http: HttpClient) {}

  listGroups(params?: { page?: number; per_page?: number }): Observable<GroupListResponse> {
    let httpParams = new HttpParams();
    if (params?.page) httpParams = httpParams.set('page', params.page.toString());
    if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
    return this.http.get<GroupListResponse>(this.apiUrl, { params: httpParams });
  }

  getGroup(id: string): Observable<{ group: Group }> {
    return this.http.get<{ group: Group }>(`${this.apiUrl}/${id}`);
  }

  createGroup(data: { name: string; description?: string }): Observable<{ group: Group }> {
    return this.http.post<{ group: Group }>(this.apiUrl, data);
  }

  updateGroup(id: string, data: { name?: string; description?: string }): Observable<{ group: Group }> {
    return this.http.put<{ group: Group }>(`${this.apiUrl}/${id}`, data);
  }

  deleteGroup(id: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/${id}`);
  }

  addMember(groupId: string, data: { user_id: number; role_in_group?: GroupRole }): Observable<{ membership: GroupMember }> {
    return this.http.post<{ membership: GroupMember }>(`${this.apiUrl}/${groupId}/members`, data);
  }

  removeMember(groupId: string, userId: number): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/${groupId}/members/${userId}`);
  }

  changeMemberRole(groupId: string, userId: number, role: GroupRole): Observable<{ membership: GroupMember }> {
    return this.http.put<{ membership: GroupMember }>(`${this.apiUrl}/${groupId}/members/${userId}/role`, { role_in_group: role });
  }
}
