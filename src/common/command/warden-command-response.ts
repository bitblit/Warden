import { WebAuthnObjectWrapper } from './web-authn-object-wrapper';
import { WardenLoginResults } from '../model/warden-login-results';
import { WardenEntrySummary } from '../model/warden-entry-summary';

export interface WardenCommandResponse {
  createAccount?: string;
  generateWebAuthnAuthenticationChallengeForUserId?: WebAuthnObjectWrapper;
  generateWebAuthnRegistrationChallengeForLoggedInUser?: WebAuthnObjectWrapper;
  removeWebAuthnRegistration?: boolean;
  sendExpiringValidationToken?: boolean;
  addWebAuthnRegistrationToLoggedInUser?: WardenEntrySummary;
  addContactToLoggedInUser?: boolean;
  performLogin?: WardenLoginResults;
  refreshJwtToken?: string;

  error?: string;
}
