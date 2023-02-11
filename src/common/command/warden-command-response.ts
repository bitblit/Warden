import { WebAuthnObjectWrapper } from './web-authn-object-wrapper';
import { WardenLoginResults } from '../model/warden-login-results';

export interface WardenCommandResponse {
  createAccount?: string;
  generateWebAuthnAuthenticationChallenge?: WebAuthnObjectWrapper;
  generateWebAuthnRegistrationChallengeForLoggedInUser?: WebAuthnObjectWrapper;
  removeWebAuthnRegistration?: boolean;
  sendExpiringValidationToken?: boolean;
  addWebAuthnRegistrationToLoggedInUser?: boolean;
  addContactToLoggedInUser?: boolean;
  performLogin?: WardenLoginResults;
  refreshJwtToken?: string;

  error?: string;
}
