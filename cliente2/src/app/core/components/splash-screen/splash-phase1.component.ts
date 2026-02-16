import { Component, OnInit, OnDestroy, Output, EventEmitter } from '@angular/core';

@Component({
    selector: 'app-splash-phase1',
    template: `
    <div class="splash-container phase1">
      <div class="content-wrapper">
        <!-- Shield Icon -->
        <div class="shield-icon-container">
          <div class="radar-ring"></div>
          <div class="radar-ring" style="animation-delay: 0.5s;"></div>
          <div class="shield-icon">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L4 6V12C4 16.5 7 20.5 12 22C17 20.5 20 16.5 20 12V6L12 2Z" 
                    stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <div class="lock-overlay">
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 17C10.9 17 10 16.1 10 15C10 13.9 10.9 13 12 13C13.1 13 14 13.9 14 15C14 16.1 13.1 17 12 17ZM18 8H17V6C17 3.24 14.76 1 12 1C9.24 1 7 3.24 7 6V8H6C4.9 8 4 8.9 4 10V20C4 21.1 4.9 22 6 22H18C19.1 22 20 21.1 20 20V10C20 8.9 19.1 8 18 8ZM12 3C13.66 3 15 4.34 15 6V8H9V6C9 4.34 10.34 3 12 3Z"/>
              </svg>
            </div>
          </div>
        </div>

        <!-- Title -->
        <h1 class="title">SENTRYVAULT</h1>
        <p class="subtitle">Inicializando módulos de seguridad</p>

        <!-- Crypto Badges -->
        <div class="crypto-badges">
          <div class="badge" [class.active]="progress >= 25">
            <span class="badge-icon">🔐</span>
            <span class="badge-text">RSA-4096</span>
          </div>
          <div class="badge" [class.active]="progress >= 50">
            <span class="badge-icon">🛡️</span>
            <span class="badge-text">AES-256</span>
          </div>
          <div class="badge" [class.active]="progress >= 75">
            <span class="badge-icon">✓</span>
            <span class="badge-text">SHA-512</span>
          </div>
          <div class="badge" [class.active]="progress >= 90">
            <span class="badge-icon">⚡</span>
            <span class="badge-text">ZERO TRUST</span>
          </div>
        </div>

        <!-- Progress Bar -->
        <div class="progress-container">
          <div class="progress-bar">
            <div class="progress-fill" [style.width.%]="progress"></div>
            <div class="progress-glow" [style.width.%]="progress"></div>
          </div>
          <div class="progress-text">{{ progress.toFixed(0) }}%</div>
        </div>

        <!-- Loading Step -->
        <div class="loading-step">{{ currentStepText }}</div>
      </div>
    </div>
  `,
    styles: [`
    .splash-container {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 9999;
    }

    .phase1 {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      animation: gradientShift 10s ease infinite;
    }

    @keyframes gradientShift {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }

    .content-wrapper {
      text-align: center;
      max-width: 600px;
      padding: 2rem;
    }

    /* Shield Icon */
    .shield-icon-container {
      position: relative;
      width: 150px;
      height: 150px;
      margin: 0 auto 2rem;
    }

    .radar-ring {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      width: 100%;
      height: 100%;
      border: 2px solid rgba(255, 215, 0, 0.3);
      border-radius: 50%;
      animation: radarPulse 2s ease-out infinite;
    }

    @keyframes radarPulse {
      0% {
        width: 100%;
        height: 100%;
        opacity: 1;
      }
      100% {
        width: 200%;
        height: 200%;
        opacity: 0;
      }
    }

    .shield-icon {
      position: relative;
      width: 100%;
      height: 100%;
      display: flex;
      justify-content: center;
      align-items: center;
    }

    .shield-icon svg {
      width: 80px;
      height: 80px;
      color: #ffd700;
      filter: drop-shadow(0 0 20px rgba(255, 215, 0, 0.5));
      animation: shieldFloat 3s ease-in-out infinite;
    }

    @keyframes shieldFloat {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-10px); }
    }

    .lock-overlay {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
    }

    .lock-overlay svg {
      width: 40px;
      height: 40px;
      color: #ff4081;
      animation: lockPulse 2s ease-in-out infinite;
    }

    @keyframes lockPulse {
      0%, 100% { opacity: 0.8; transform: scale(1); }
      50% { opacity: 1; transform: scale(1.1); }
    }

    /* Title */
    .title {
      font-size: 2rem;
      font-weight: 700;
      color: #ffd700;
      margin-bottom: 0.5rem;
      text-shadow: 0 0 20px rgba(255, 215, 0, 0.5);
      letter-spacing: 2px;
    }

    .subtitle {
      font-size: 1rem;
      color: #a0a0a0;
      margin-bottom: 2rem;
    }

    /* Crypto Badges */
    .crypto-badges {
      display: flex;
      justify-content: center;
      gap: 1rem;
      margin-bottom: 2rem;
      flex-wrap: wrap;
    }

    .badge {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 215, 0, 0.2);
      border-radius: 20px;
      opacity: 0.3;
      transition: all 0.5s ease;
    }

    .badge.active {
      opacity: 1;
      background: rgba(255, 215, 0, 0.1);
      border-color: rgba(255, 215, 0, 0.5);
      box-shadow: 0 0 20px rgba(255, 215, 0, 0.3);
    }

    .badge-icon {
      font-size: 1.2rem;
    }

    .badge-text {
      font-size: 0.9rem;
      font-weight: 600;
      color: #ffd700;
    }

    /* Progress Bar */
    .progress-container {
      margin-bottom: 1.5rem;
    }

    .progress-bar {
      position: relative;
      width: 100%;
      height: 8px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      overflow: hidden;
      margin-bottom: 0.5rem;
    }

    .progress-fill {
      position: absolute;
      top: 0;
      left: 0;
      height: 100%;
      background: linear-gradient(90deg, #ffd700 0%, #ff4081 100%);
      border-radius: 10px;
      transition: width 0.1s linear;
    }

    .progress-glow {
      position: absolute;
      top: 0;
      left: 0;
      height: 100%;
      background: linear-gradient(90deg, #ffd700 0%, #ff4081 100%);
      border-radius: 10px;
      filter: blur(10px);
      opacity: 0.5;
      transition: width 0.1s linear;
    }

    .progress-text {
      font-size: 1.2rem;
      font-weight: 700;
      color: #ffd700;
      text-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
    }

    /* Loading Step */
    .loading-step {
      font-size: 0.95rem;
      color: #ffffff;
      min-height: 24px;
      opacity: 0.8;
    }
  `]
})
export class SplashPhase1Component implements OnInit, OnDestroy {
    @Output() completed = new EventEmitter<void>();

    progress = 0;
    currentStep = 0;
    private intervalRef: any = null;
    private isLoading = false;

    loadingSteps = [
        'Inicializando sistema seguro...',
        'Cargando módulos criptográficos...',
        'Verificando integridad del sistema...',
        'Preparando interfaz Zero Trust...',
        'Sistema inicializado'
    ];

    ngOnInit(): void {
        if (!this.isLoading) {
            this.startLoading();
        }
    }

    ngOnDestroy(): void {
        if (this.intervalRef) {
            clearInterval(this.intervalRef);
        }
    }

    private startLoading(): void {
        this.isLoading = true;
        this.intervalRef = setInterval(() => {
            this.progress += 1.5;

            const stepProgress = Math.floor(this.progress / 20);
            if (stepProgress < this.loadingSteps.length) {
                this.currentStep = stepProgress;
            }

            if (this.progress >= 100) {
                if (this.intervalRef) {
                    clearInterval(this.intervalRef);
                    this.intervalRef = null;
                }
                this.progress = 100;
                setTimeout(() => {
                    this.completed.emit();
                }, 800);
            }
        }, 50);
    }

    get currentStepText(): string {
        return this.loadingSteps[this.currentStep];
    }
}
