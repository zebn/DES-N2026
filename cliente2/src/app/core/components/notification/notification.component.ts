import { Component, Inject } from '@angular/core';
import { MAT_SNACK_BAR_DATA } from '@angular/material/snack-bar';

export interface NotificationData {
  title: string;
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
  details?: string[];
}

@Component({
  selector: 'app-notification',
  template: `
    <div class="custom-notification" [ngClass]="data.type">
      <div class="notification-header">
        <mat-icon class="notification-icon">{{ getIcon() }}</mat-icon>
        <h3 class="notification-title">{{ data.title }}</h3>
      </div>
      <p class="notification-message">{{ data.message }}</p>
      <div class="notification-details" *ngIf="data.details && data.details.length > 0">
        <div class="detail-item" *ngFor="let detail of data.details">
          <mat-icon class="detail-icon">check_circle</mat-icon>
          <span>{{ detail }}</span>
        </div>
      </div>
    </div>
  `,
  styles: []
})
export class NotificationComponent {
  constructor(@Inject(MAT_SNACK_BAR_DATA) public data: NotificationData) {}

  getIcon(): string {
    const icons: { [key: string]: string } = {
      success: 'check_circle',
      error: 'error',
      warning: 'warning',
      info: 'info'
    };
    return icons[this.data.type] || 'info';
  }
}
