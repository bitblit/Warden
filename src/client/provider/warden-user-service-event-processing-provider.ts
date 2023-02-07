import { WardenJwtToken } from '../../common';
import { WardenLoggedInUserWrapper } from './warden-logged-in-user-wrapper';

/**
 * Notifies the containing system when significant events happen
 */

export interface WardenUserServiceEventProcessingProvider<T> {
  onLogout(): Promise<void>;
  onSuccessfulLogin(newUser: WardenLoggedInUserWrapper<T>): Promise<void>;
  onLoginFailure(reason: string): Promise<void>;

  onAutomaticTokenRefresh(refreshUser: WardenLoggedInUserWrapper<T>): Promise<void>;
  onAutomaticLogout(): Promise<void>;
}
