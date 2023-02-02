import { WardenContactEntry } from './warden-contact-entry';
import { AuthenticationResponseJSON } from '@simplewebauthn/typescript-types';

export interface WardenLoginRequest {
  contact: WardenContactEntry;
  webAuthn?: AuthenticationResponseJSON;
  expiringToken?: string;
  jwtTokenToRefresh?: string;
}
