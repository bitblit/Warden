import { NgModule } from '@angular/core';

import { UserProfileComponent } from './user-profile.component';
import { MatCardModule } from '@angular/material/card';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatIconModule } from '@angular/material/icon';

@NgModule({
  imports: [MatCardModule, CommonModule, MatButtonModule, MatTooltipModule, MatIconModule],
  declarations: [UserProfileComponent],
})
export class UserProfileModule {}
