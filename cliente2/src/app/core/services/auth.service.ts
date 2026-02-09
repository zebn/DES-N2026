import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { CryptoService } from './crypto.service';
import { environment } from '../../../environments/environment';

export interface User {
  id: number;
  email: string;
  nombre: string;
  apellidos: string;
  clearance_level: string;
  is_admin: boolean;
  is_active: boolean;
  is_2fa_enabled: boolean;
  public_key: string;
  encrypted_private_key: string;
  key_derivation_params: string;
}

export interface Setup2FAResponse {
  secret: string;
  qr_code: string;
  setup_uri: string;
  message: string;
}

export interface Verify2FAResponse {
  message: string;
  backup_codes: string[];
  warning: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  private accessToken: string | null = null;

  constructor(
    private http: HttpClient,
    private crypto: CryptoService
  ) {
    // Load token from localStorage on init
    this.loadToken();
  }

  private loadToken() {
    const token = localStorage.getItem('access_token');
    if (token) {
      this.accessToken = token;
      // Load user profile
      this.loadProfile().subscribe();
    }
  }

  async register(userData: {
    email: string;
    password: string;
    nombre: string;
    apellidos: string;
    clearance_level: string;
  }): Promise<void> {
    // 1. Generate RSA keys
    const keyPair = await this.crypto.generateRSAKeyPair();

    // 2. Export public key
    const publicKey = await this.crypto.exportPublicKey(keyPair.publicKey);

    // 3. Export and encrypt private key
    const privateKey = await this.crypto.exportPrivateKey(keyPair.privateKey);
    const encrypted = await this.crypto.encryptPrivateKey(
      privateKey,
      userData.password
    );

    // 4. Send to server
    await this.http.post(`${environment.apiUrl}/api/auth/register`, {
      ...userData,
      public_key: publicKey,
      encrypted_private_key: encrypted.encryptedKey,
      key_derivation_params: JSON.stringify({
        algorithm: 'Argon2id',
        time_cost: 3,
        memory_cost: 65536,
        parallelism: 4,
        salt: encrypted.salt,
        counter: encrypted.counter,
        hash_len: 32
      })
    }).toPromise();
  }

  login(email: string, password: string, totpCode?: string): Observable<any> {
    return this.http.post(`${environment.apiUrl}/api/auth/login`, {
      email,
      password,
      totp_code: totpCode
    }).pipe(
      tap(async (response: any) => {
        this.accessToken = response.access_token;
        localStorage.setItem('access_token', response.access_token);
        if (response.refresh_token) {
          localStorage.setItem('refresh_token', response.refresh_token);
        }

        // Guardar las claves criptográficas del usuario
        if (response.user) {
          console.log('[AuthService] Saving crypto keys:', {
            hasPublicKey: !!response.user.public_key,
            hasEncryptedPrivateKey: !!response.user.encrypted_private_key,
            hasKeyDerivationParams: !!response.user.key_derivation_params,
            paramsType: typeof response.user.key_derivation_params,
            paramsPreview: response.user.key_derivation_params?.substring?.(0, 50) || response.user.key_derivation_params
          });

          if (response.user.public_key) {
            localStorage.setItem('publicKey', response.user.public_key);
          }
          if (response.user.encrypted_private_key) {
            localStorage.setItem('encryptedPrivateKey', response.user.encrypted_private_key);
          }
          if (response.user.key_derivation_params) {
            // Asegurarse de que sea una cadena JSON
            const paramsStr = typeof response.user.key_derivation_params === 'string'
              ? response.user.key_derivation_params
              : JSON.stringify(response.user.key_derivation_params);
            localStorage.setItem('keyDerivationParams', paramsStr);
            console.log('[AuthService] Saved keyDerivationParams:', paramsStr.substring(0, 100));
          }

          // Desbloquear la clave privada en memoria
          try {
            await this.crypto.unlockPrivateKey(password);
            console.log('[AuthService] Private key unlocked successfully');
          } catch (error) {
            console.error('[AuthService] Error desbloqueando clave privada:', error);
          }
        }

        this.currentUserSubject.next(response.user);
      })
    );
  }

  logout(): void {
    this.accessToken = null;
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('publicKey');
    localStorage.removeItem('encryptedPrivateKey');
    localStorage.removeItem('keyDerivationParams');

    // Limpiar caché de claves en memoria
    this.crypto.clearKeyCache();

    this.currentUserSubject.next(null);
  }

  loadProfile(): Observable<any> {
    return this.http.get(`${environment.apiUrl}/api/auth/profile`).pipe(
      tap((response: any) => {
        // Guardar las claves criptográficas si vienen en la respuesta
        if (response.user) {
          if (response.user.public_key) {
            localStorage.setItem('publicKey', response.user.public_key);
          }
          if (response.user.encrypted_private_key) {
            localStorage.setItem('encryptedPrivateKey', response.user.encrypted_private_key);
          }
          if (response.user.key_derivation_params) {
            // Asegurarse de que sea una cadena JSON
            const paramsStr = typeof response.user.key_derivation_params === 'string'
              ? response.user.key_derivation_params
              : JSON.stringify(response.user.key_derivation_params);
            localStorage.setItem('keyDerivationParams', paramsStr);
          }
        }
        this.currentUserSubject.next(response.user);
      })
    );
  }

  getToken(): string | null {
    return this.accessToken;
  }

  isAuthenticated(): boolean {
    return !!this.accessToken;
  }

  getUsers(): Observable<{ users: User[] }> {
    return this.http.get<{ users: User[] }>(`${environment.apiUrl}/api/auth/users`);
  }

  getUserPublicKey(email: string): Observable<{ email: string; public_key: string; is_active: boolean; clearance_level: string }> {
    return this.http.post<{ email: string; public_key: string; is_active: boolean; clearance_level: string }>(
      `${environment.apiUrl}/api/auth/user/public-key`,
      { email }
    );
  }

  // ===== 2FA Methods =====

  /**
   * Iniciar configuración de 2FA - obtiene secreto y QR code
   */
  setup2FA(): Observable<Setup2FAResponse> {
    return this.http.post<Setup2FAResponse>(`${environment.apiUrl}/api/auth/setup-2fa`, {});
  }

  /**
   * Verificar y habilitar 2FA con código TOTP
   */
  verify2FA(totpCode: string): Observable<Verify2FAResponse> {
    return this.http.post<Verify2FAResponse>(`${environment.apiUrl}/api/auth/verify-2fa`, {
      totp_code: totpCode
    }).pipe(
      tap(() => {
        // Actualizar estado del usuario actual
        const currentUser = this.currentUserSubject.value;
        if (currentUser) {
          this.currentUserSubject.next({
            ...currentUser,
            is_2fa_enabled: true
          });
        }
      })
    );
  }

  /**
   * Deshabilitar 2FA (requiere código TOTP actual)
   */
  disable2FA(totpCode: string): Observable<any> {
    return this.http.post(`${environment.apiUrl}/api/auth/disable-2fa`, {
      totp_code: totpCode
    }).pipe(
      tap(() => {
        // Actualizar estado del usuario actual
        const currentUser = this.currentUserSubject.value;
        if (currentUser) {
          this.currentUserSubject.next({
            ...currentUser,
            is_2fa_enabled: false
          });
        }
      })
    );
  }

  /**
   * Obtener usuario actual
   */
  getCurrentUser(): User | null {
    return this.currentUserSubject.value;
  }
}
