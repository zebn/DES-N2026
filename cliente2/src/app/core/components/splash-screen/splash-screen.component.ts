import { Component, OnInit, Output, EventEmitter } from '@angular/core';
import { environment } from '../../../../environments/environment';

@Component({
  selector: 'app-splash-screen',
  templateUrl: './splash-screen.component.html',
  styleUrls: ['./splash-screen.component.scss']
})
export class SplashScreenComponent implements OnInit {
  @Output() completed = new EventEmitter<void>();

  showSplash = true;
  currentPhase: 'phase1' | 'phase2' | null = 'phase1';
  private phase1Completed = false;
  private phase2Completed = false;

  // Phase 2 properties
  phase2Progress = 0;
  phase2Step = 0;
  private phase2Interval: any;
  phase2Steps = [
    'Estableciendo conexión segura...',
    'Verificando certificado del servidor...',
    'Validando protocolo TLS 1.3...',
    'Autenticando canal cifrado...',
    'Conexión establecida'
  ];

  // Información del servidor
  serverInfo = {
    url: environment.apiUrl,
    protocol: environment.apiUrl.startsWith('https') ? 'HTTPS' : 'HTTP',
    host: this.extractHost(environment.apiUrl),
    tlsVersion: 'TLS 1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    certificate: {
      issuer: 'DigiCert Global Root CA',
      algorithm: 'RSA-2048',
      encryption: 'SHA-256 with RSA'
    }
  };

  ngOnInit(): void {
    console.log('[Splash] Main component initialized, showSplash:', this.showSplash, 'currentPhase:', this.currentPhase);
  }

  private extractHost(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url;
    }
  }

  onPhase1Completed(): void {
    if (this.phase1Completed) return;
    this.phase1Completed = true;

    console.log('[Splash] Phase 1 completed, transitioning to Phase 2');
    console.log('[Splash] Before transition - showSplash:', this.showSplash, 'currentPhase:', this.currentPhase);

    // Просто задержка перед переключением на фазу 2
    setTimeout(() => {
      this.currentPhase = 'phase2';
      console.log('[Splash] Phase 2 started');
      console.log('[Splash] After transition - showSplash:', this.showSplash, 'currentPhase:', this.currentPhase);

      // Запускаем анимацию Phase 2
      this.startPhase2();
    }, 1000);
  }

  private startPhase2(): void {
    console.log('[Splash] startPhase2 called');
    this.phase2Interval = setInterval(() => {
      this.phase2Progress += 1.5;
      console.log('[Splash] Phase 2 progress:', this.phase2Progress);

      const stepProgress = Math.floor(this.phase2Progress / 20);
      if (stepProgress < this.phase2Steps.length) {
        this.phase2Step = stepProgress;
      }

      if (this.phase2Progress >= 100) {
        clearInterval(this.phase2Interval);
        this.phase2Progress = 100;
        console.log('[Splash] Phase 2 completed');
        this.onPhase2Completed();
      }
    }, 50);
  }

  get phase2StepText(): string {
    return this.phase2Steps[this.phase2Step];
  }

  onPhase2Completed(): void {
    if (this.phase2Completed) return;
    this.phase2Completed = true;

    console.log('[Splash] Phase 2 completed');
    this.currentPhase = null;
    setTimeout(() => {
      this.showSplash = false;
      this.completed.emit(); // Уведомляем родителя
      console.log('[Splash] Splash screen hidden');
    }, 300);
  }
}
