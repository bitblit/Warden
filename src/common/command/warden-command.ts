import { CreateAccount } from './create-account';
import { WardenContact } from '../model/warden-contact';
import { WebAuthnObjectWrapper } from './web-authn-object-wrapper';
import { RemoveWebAuthnRegistration } from './remove-web-authn-registration';
import { WardenLoginRequest } from '../model/warden-login-request';

export interface WardenCommand {
  createAccount?: CreateAccount;
  generateWebAuthnAuthenticationChallenge?: WardenContact;
  generateWebAuthnRegistrationChallengeForLoggedInUser?: boolean;
  removeWebAuthnRegistration?: RemoveWebAuthnRegistration;
  sendExpiringValidationToken?: WardenContact;
  addWebAuthnRegistrationToLoggedInUser?: WebAuthnObjectWrapper;

  performLogin?: WardenLoginRequest;
  refreshJwtToken?: string;
}
