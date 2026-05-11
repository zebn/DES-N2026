import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import {
  SecretsService,
  Secret,
  SecretListResponse,
  Folder,
  SecretVersion,
  SECRET_TYPE_LABELS,
  SECRET_TYPE_ICONS,
} from './secrets.service';
import { environment } from '../../../environments/environment';

describe('SecretsService', () => {
  let service: SecretsService;
  let httpMock: HttpTestingController;
  const apiUrl = `${environment.apiUrl}/api/secrets`;
  const foldersUrl = `${environment.apiUrl}/api/folders`;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [SecretsService],
    });

    service = TestBed.inject(SecretsService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  // ─── Creación ──────────────────────────────────────────────────────

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // ─── Constantes ────────────────────────────────────────────────────

  it('SECRET_TYPE_LABELS should contain all types', () => {
    const types = ['PASSWORD', 'API_KEY', 'CERTIFICATE', 'SSH_KEY', 'NOTE', 'DATABASE', 'ENV_VARIABLE', 'IDENTITY'];
    types.forEach((t) => {
      expect(SECRET_TYPE_LABELS[t as keyof typeof SECRET_TYPE_LABELS]).toBeDefined();
    });
  });

  it('SECRET_TYPE_ICONS should contain all types', () => {
    expect(SECRET_TYPE_ICONS['PASSWORD']).toBe('password');
    expect(SECRET_TYPE_ICONS['NOTE']).toBe('sticky_note_2');
  });

  // ─── listSecrets ──────────────────────────────────────────────────

  it('listSecrets() should GET /api/secrets', () => {
    const mockResp: SecretListResponse = {
      secrets: [],
      total: 0,
      page: 1,
      per_page: 20,
      pages: 0,
    };

    service.listSecrets().subscribe((resp) => {
      expect(resp.total).toBe(0);
      expect(resp.secrets).toEqual([]);
    });

    const req = httpMock.expectOne(apiUrl);
    expect(req.request.method).toBe('GET');
    req.flush(mockResp);
  });

  it('listSecrets() should pass query params', () => {
    service.listSecrets({ type: 'PASSWORD', page: 2, per_page: 10 }).subscribe();

    const req = httpMock.expectOne((r) =>
      r.url === apiUrl &&
      r.params.get('type') === 'PASSWORD' &&
      r.params.get('page') === '2' &&
      r.params.get('per_page') === '10'
    );
    expect(req.request.method).toBe('GET');
    req.flush({ secrets: [], total: 0, page: 2, per_page: 10, pages: 0 });
  });

  // ─── getSecret ─────────────────────────────────────────────────────

  it('getSecret() should GET /api/secrets/:id', () => {
    const mockSecret: Partial<Secret> = {
      id: 'uuid-1',
      title: 'Test Secret',
      secret_type: 'NOTE',
    };

    service.getSecret('uuid-1').subscribe((resp) => {
      expect(resp.secret.id).toBe('uuid-1');
    });

    const req = httpMock.expectOne(`${apiUrl}/uuid-1`);
    expect(req.request.method).toBe('GET');
    req.flush({ secret: mockSecret });
  });

  // ─── decryptSecret ────────────────────────────────────────────────

  it('decryptSecret() should POST /api/secrets/:id/decrypt', () => {
    service.decryptSecret('uuid-2').subscribe();

    const req = httpMock.expectOne(`${apiUrl}/uuid-2/decrypt`);
    expect(req.request.method).toBe('POST');
    req.flush({ secret: { id: 'uuid-2', encrypted_data: 'enc' } });
  });

  // ─── createSecret ─────────────────────────────────────────────────

  it('createSecret() should POST to /api/secrets with all fields', () => {
    const payload = {
      title: 'New Secret',
      secret_type: 'API_KEY',
      encrypted_data: 'base64...',
      encrypted_aes_key: 'aeskey',
      content_hash: 'hash',
      digital_signature: 'sig',
      tags: '["prod"]',
    };

    service.createSecret(payload).subscribe((resp) => {
      expect(resp.message).toBe('created');
    });

    const req = httpMock.expectOne(apiUrl);
    expect(req.request.method).toBe('POST');
    expect(req.request.body.title).toBe('New Secret');
    expect(req.request.body.tags).toBe('["prod"]');
    req.flush({ message: 'created', secret: { id: 'x', ...payload } });
  });

  // ─── updateSecret ─────────────────────────────────────────────────

  it('updateSecret() should PUT /api/secrets/:id', () => {
    service.updateSecret('uuid-3', {
      encrypted_data: 'new_enc',
      encrypted_aes_key: 'new_key',
      content_hash: 'new_hash',
      digital_signature: 'new_sig',
      change_reason: 'rotation',
    }).subscribe((resp) => {
      expect(resp.version).toBe(2);
    });

    const req = httpMock.expectOne(`${apiUrl}/uuid-3`);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body.change_reason).toBe('rotation');
    req.flush({ message: 'updated', secret: { id: 'uuid-3' }, version: 2 });
  });

  // ─── deleteSecret ─────────────────────────────────────────────────

  it('deleteSecret() should DELETE /api/secrets/:id', () => {
    service.deleteSecret('uuid-4').subscribe((resp) => {
      expect(resp.message).toBe('deleted');
    });

    const req = httpMock.expectOne(`${apiUrl}/uuid-4`);
    expect(req.request.method).toBe('DELETE');
    req.flush({ message: 'deleted' });
  });

  // ─── getVersions ──────────────────────────────────────────────────

  it('getVersions() should GET /api/secrets/:id/versions', () => {
    const mockVersions: Partial<SecretVersion>[] = [
      { id: 'v1', version_number: 1 },
      { id: 'v2', version_number: 2 },
    ];

    service.getVersions('uuid-5').subscribe((resp) => {
      expect(resp.versions.length).toBe(2);
    });

    const req = httpMock.expectOne(`${apiUrl}/uuid-5/versions`);
    expect(req.request.method).toBe('GET');
    req.flush({ versions: mockVersions, total: 2 });
  });

  // ─── verifyIntegrity ──────────────────────────────────────────────

  it('verifyIntegrity() should POST /api/secrets/:id/verify', () => {
    service.verifyIntegrity('uuid-6').subscribe((resp) => {
      expect(resp.valid).toBeTrue();
    });

    const req = httpMock.expectOne(`${apiUrl}/uuid-6/verify`);
    expect(req.request.method).toBe('POST');
    req.flush({ valid: true });
  });

  // ═══════════════════════════════════════════════════════════════════
  // Folders
  // ═══════════════════════════════════════════════════════════════════

  it('listFolders() should GET /api/folders', () => {
    service.listFolders().subscribe((resp) => {
      expect(resp.folders.length).toBe(1);
    });

    const req = httpMock.expectOne(foldersUrl);
    expect(req.request.method).toBe('GET');
    req.flush({ folders: [{ id: 'f1', name: 'Prod' }] });
  });

  it('createFolder() should POST /api/folders', () => {
    service.createFolder('Staging').subscribe((resp) => {
      expect(resp.folder.name).toBe('Staging');
    });

    const req = httpMock.expectOne(foldersUrl);
    expect(req.request.method).toBe('POST');
    expect(req.request.body.name).toBe('Staging');
    req.flush({ message: 'created', folder: { id: 'f2', name: 'Staging' } });
  });

  it('updateFolder() should PUT /api/folders/:id', () => {
    service.updateFolder('f1', { name: 'Renamed' }).subscribe();

    const req = httpMock.expectOne(`${foldersUrl}/f1`);
    expect(req.request.method).toBe('PUT');
    req.flush({ message: 'updated', folder: { id: 'f1', name: 'Renamed' } });
  });

  it('deleteFolder() should DELETE /api/folders/:id', () => {
    service.deleteFolder('f1').subscribe((resp) => {
      expect(resp.message).toBe('deleted');
    });

    const req = httpMock.expectOne(`${foldersUrl}/f1`);
    expect(req.request.method).toBe('DELETE');
    req.flush({ message: 'deleted' });
  });
});
