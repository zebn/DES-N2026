import { Component, OnInit, OnDestroy, AfterViewInit, Output, EventEmitter, Input } from '@angular/core';

@Component({
    selector: 'app-splash-phase2',
    template: `
    <div class="splash-container">
      <div class="content-wrapper">
        <h1 class="title">FASE 2 - CONECTANDO AL SERVIDOR</h1>
        <div class="server-url">{{ serverInfo?.host || 'Cargando...' }}</div>
        <div class="progress-text">{{ progress.toFixed(0) }}%</div>
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
      background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
    }

    .content-wrapper {
      text-align: center;
      color: white;
      padding: 2rem;
    }

    .title {
      font-size: 2rem;
      color: #00e5ff;
      margin-bottom: 1rem;
      text-shadow: 0 0 20px rgba(0, 229, 255, 0.5);
    }

    .server-url {
      font-size: 1.2rem;
      color: #00ff00;
      margin-bottom: 2rem;
    }

    .progress-text {
      font-size: 4rem;
      font-weight: 700;
      color: #00e5ff;
      margin-bottom: 1rem;
      text-shadow: 0 0 30px rgba(0, 229, 255, 0.7);
    }

    .loading-step {
      font-size: 1.2rem;
      color: #ffffff;
      opacity: 0.9;
    }
  `]
})
export class SplashPhase2Component implements OnInit, AfterViewInit, OnDestroy {
    @Input() serverInfo: any;
    @Output() completed = new EventEmitter<void>();

    progress = 0;
    currentStep = 0;
    private intervalRef: any = null;

    loadingSteps = [
        'Estableciendo conexión segura...',
        'Verificando certificado del servidor...',
        'Validando protocolo TLS 1.3...',
        'Autenticando canal cifrado...',
        'Conexión establecida'
    ];

    constructor() {
        console.log('[Phase2] Constructor called');
    }

    ngOnInit(): void {
        console.log('[Phase2] ngOnInit called, starting loading immediately');
        this.startLoading();
    }

    ngAfterViewInit(): void {
        console.log('[Phase2] ngAfterViewInit called');
    }

    ngOnDestroy(): void {
        console.log('[Phase2] Component destroyed, progress was:', this.progress);
        if (this.intervalRef) {
            clearInterval(this.intervalRef);
        }
    }

    private startLoading(): void {
        console.log('[Phase2] Starting loading animation');
        this.intervalRef = setInterval(() => {
            this.progress += 1.5;
            console.log('[Phase2] Progress:', this.progress);

            const stepProgress = Math.floor(this.progress / 20);
            if (stepProgress < this.loadingSteps.length) {
                this.currentStep = stepProgress;
            }

            if (this.progress >= 100) {
                console.log('[Phase2] Progress reached 100%');
                if (this.intervalRef) {
                    clearInterval(this.intervalRef);
                    this.intervalRef = null;
                }
                this.progress = 100;
                setTimeout(() => {
                    console.log('[Phase2] Emitting completed event');
                    this.completed.emit();
                }, 800);
            }
        }, 50);
    }

    get currentStepText(): string {
        return this.loadingSteps[this.currentStep];
    }
}
