import {CreateAccount} from "./create-account";
import {WardenContactEntry} from "../model/warden-contact-entry";
import {WebAuthnObjectWrapper} from "./web-authn-object-wrapper";
import {RemoveWebAuthnRegistration} from "./remove-web-authn-registration";
import {WardenLoginRequest} from "../model/warden-login-request";

export interface WardenCommand {
  createAccount?: CreateAccount;
  generateWebAuthnAuthenticationChallenge?: WardenContactEntry;
  generateWebAuthnRegistrationChallengeForLoggedInUser?: boolean;
  removeWebAuthnRegistration?: RemoveWebAuthnRegistration;
  sendExpiringValidationToken?: WardenContactEntry;
  addWebAuthnRegistrationToLoggedInUser?: WebAuthnObjectWrapper;

  performLogin?: WardenLoginRequest;
  refreshJwtToken?: string;
}
