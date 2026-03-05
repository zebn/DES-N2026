import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { AuthService, User } from './auth.service';
import { CryptoService } from './crypto.service';
import { environment } from '../../../environments/environment';

describe('AuthService', () => {
  let service: AuthService;
  let httpMock: HttpTestingController;
  let cryptoSpy: jasmine.SpyObj<CryptoService>;

  beforeEach(() => {
    // Crear un spy parcial de CryptoService (sólo métodos usados por AuthService)
    cryptoSpy = jasmine.createSpyObj('CryptoService', [
      'generateRSAKeyPair',
      'exportPublicKey',
      'exportPrivateKey',
      'encryptPrivateKey',
      'unlockPrivateKey',
      'clearKeyCache',
    ]);

    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [
        AuthService,
        { provide: CryptoService, useValue: cryptoSpy },
      ],
    });

    service = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);

    // Limpiar localStorage antes de cada test
    localStorage.clear();
  });

  afterEach(() => {
    httpMock.verify(); // asegurar que no quedan requests pendientes
    localStorage.clear();
  });

  // ─── Estado inicial ────────────────────────────────────────────────

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should not be authenticated by default', () => {
    expect(service.isAuthenticated()).toBeFalse();
    expect(service.getToken()).toBeNull();
  });

  it('currentUser$ should emit null initially', (done) => {
    service.currentUser$.subscribe((user) => {
      expect(user).toBeNull();
      done();
    });
  });

  // ─── Login ─────────────────────────────────────────────────────────

  it('login() should store token and emit user', () => {
    const mockResponse = {
      access_token: 'jwt-token-123',
      refresh_token: 'refresh-456',
      user: {
        id: 1,
        email: 'test@test.com',
        nombre: 'Test',
        apellidos: 'User',
        role: 'USER',
        public_key: 'pk',
        encrypted_private_key: 'epk',
        key_derivation_params: '{"algo":"Argon2id"}',
      } as unknown as User,
    };

    cryptoSpy.unlockPrivateKey.and.returnValue(Promise.resolve());

    service.login('test@test.com', 'pass123').subscribe((resp) => {
      expect(resp.access_token).toBe('jwt-token-123');
    });

    const req = httpMock.expectOne(`${environment.apiUrl}/api/auth/login`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body.email).toBe('test@test.com');
    req.flush(mockResponse);

    expect(service.isAuthenticated()).toBeTrue();
    expect(service.getToken()).toBe('jwt-token-123');
    expect(localStorage.getItem('access_token')).toBe('jwt-token-123');
    expect(localStorage.getItem('refresh_token')).toBe('refresh-456');
  });

  it('login() should send totp_code when provided', () => {
    cryptoSpy.unlockPrivateKey.and.returnValue(Promise.resolve());

    service.login('a@b.com', 'pw', '123456').subscribe();

    const req = httpMock.expectOne(`${environment.apiUrl}/api/auth/login`);
    expect(req.request.body.totp_code).toBe('123456');
    req.flush({ access_token: 'x', user: null });
  });

  // ─── Logout ────────────────────────────────────────────────────────

  it('logout() should clear token and localStorage', () => {
    // Simular estado autenticado
    localStorage.setItem('access_token', 'tok');
    localStorage.setItem('refresh_token', 'ref');

    service.logout();

    expect(service.isAuthenticated()).toBeFalse();
    expect(localStorage.getItem('access_token')).toBeNull();
    expect(localStorage.getItem('refresh_token')).toBeNull();
    expect(cryptoSpy.clearKeyCache).toHaveBeenCalled();
  });

  // ─── Profile ───────────────────────────────────────────────────────

  it('loadProfile() should GET /api/auth/profile', () => {
    const mockUser: Partial<User> = {
      id: 5,
      email: 'profile@test.com',
      role: 'ADMIN',
    };

    service.loadProfile().subscribe((resp) => {
      expect(resp.user.email).toBe('profile@test.com');
    });

    const req = httpMock.expectOne(`${environment.apiUrl}/api/auth/profile`);
    expect(req.request.method).toBe('GET');
    req.flush({ user: mockUser });
  });

  // ─── RBAC helpers ──────────────────────────────────────────────────

  it('hasRole() should return false when no user', () => {
    expect(service.hasRole('ADMIN')).toBeFalse();
  });

  it('isAdmin() should delegate to hasRole(ADMIN)', () => {
    // Sin usuario
    expect(service.isAdmin()).toBeFalse();
  });

  // ─── Users ─────────────────────────────────────────────────────────

  it('getUsers() should GET /api/auth/users', () => {
    service.getUsers().subscribe((resp) => {
      expect(resp.users.length).toBe(1);
    });

    const req = httpMock.expectOne(`${environment.apiUrl}/api/auth/users`);
    expect(req.request.method).toBe('GET');
    req.flush({ users: [{ id: 1, email: 'u@t.com' }] });
  });

  it('changeUserRole() should PUT the new role', () => {
    service.changeUserRole(42, 'MANAGER').subscribe();

    const req = httpMock.expectOne(`${environment.apiUrl}/api/auth/users/42/role`);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body.role).toBe('MANAGER');
    req.flush({ message: 'ok' });
  });
});
