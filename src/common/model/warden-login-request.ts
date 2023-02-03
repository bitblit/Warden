import { WardenContact } from './warden-contact';
import { AuthenticationResponseJSON } from '@simplewebauthn/typescript-types';

export interface WardenLoginRequest {
  contact: WardenContact;
  webAuthn?: AuthenticationResponseJSON;
  expiringToken?: string;
  jwtTokenToRefresh?: string;
}
