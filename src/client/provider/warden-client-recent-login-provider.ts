import { WardenRecentLoginDescriptor } from './warden-recent-login-descriptor';
import { WardenContact } from '../../common';

export interface WardenClientRecentLoginProvider {
  addWebAuthnLogin(userId: string);
  addContactLogin(userId: string, contact: WardenContact): Promise<void>;
  clearLoginsForUserId(userId: string): Promise<void>;
  fetchAllLogins(): Promise<WardenRecentLoginDescriptor[]>;
  clearAllLogins(): Promise<void>;
}
