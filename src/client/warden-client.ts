//    Service for interacting with positions for a given user
import { WardenCommand } from '../common/command/warden-command';
import { WardenContactEntry } from '../common/model/warden-contact-entry';
import { WardenCommandSender } from './warden-command-sender';
import { WardenCommandResponse } from '../common/command/warden-command-response';
import { ErrorRatchet, Logger, StringRatchet } from '@bitblit/ratchet/common';
import {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { WardenLoginResults } from '../common/model/warden-login-results';
import { WardenLoginRequest } from '../common/model/warden-login-request';

export class WardenClient {
  constructor(private commandSender: WardenCommandSender) {}

  public async exchangeCommand(cmd: WardenCommand, returnErrors?: boolean): Promise<WardenCommandResponse> {
    const asString: string = JSON.stringify(cmd);
    const resp: string = await this.commandSender.sendCommand(asString);
    const parsed: WardenCommandResponse = JSON.parse(resp);

    if (parsed?.error && !returnErrors) {
      ErrorRatchet.throwFormattedErr('%s', parsed.error);
    }
    return parsed;
  }

  public async createAccount(contact: WardenContactEntry, sendCode?: boolean, label?: string, tags?: string[]): Promise<string> {
    const cmd: WardenCommand = {
      createAccount: {
        contact: contact,
        sendCode: sendCode,
        label: label,
        tags: tags,
      },
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);
    return rval.createAccount;
  }

  public async generateWebAuthnAuthenticationChallenge(contact: WardenContactEntry): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const cmd: WardenCommand = {
      generateWebAuthnAuthenticationChallenge: contact,
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);
    const parsed: PublicKeyCredentialRequestOptionsJSON = JSON.parse(rval.generateWebAuthnAuthenticationChallenge.dataAsJson);
    return parsed;
  }

  public async generateWebAuthnRegistrationChallengeForLoggedInUser(): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const cmd: WardenCommand = {
      generateWebAuthnRegistrationChallengeForLoggedInUser: true,
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);
    const parsed: PublicKeyCredentialCreationOptionsJSON = JSON.parse(rval.generateWebAuthnAuthenticationChallenge.dataAsJson);
    return parsed;
  }

  public async removeWebAuthnRegistration(userId: string, credId: string): Promise<boolean> {
    const cmd: WardenCommand = {
      removeWebAuthnRegistration: {
        userId: userId,
        credentialId: credId,
      },
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);
    return rval.removeWebAuthnRegistration;
  }

  public async sendExpiringValidationToken(contact: WardenContactEntry): Promise<boolean> {
    const cmd: WardenCommand = {
      sendExpiringValidationToken: contact,
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);
    return rval.sendExpiringValidationToken;
  }

  public async addWebAuthnRegistrationToLoggedInUser(data: RegistrationResponseJSON): Promise<boolean> {
    const cmd: WardenCommand = {
      addWebAuthnRegistrationToLoggedInUser: {
        dataAsJson: JSON.stringify(data),
      },
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);
    return rval.addWebAuthnRegistrationToLoggedInUser;
  }

  public async saveCurrentDeviceAsWebAuthnForCurrentUser(): Promise<boolean> {
    const input: PublicKeyCredentialCreationOptionsJSON = await this.generateWebAuthnRegistrationChallengeForLoggedInUser();
    const creds: RegistrationResponseJSON = await startRegistration(input);
    const output: boolean = await this.addWebAuthnRegistrationToLoggedInUser(creds);
    return output;
  }

  public async performLoginCmd(login: WardenLoginRequest): Promise<WardenLoginResults> {
    const loginCmd: WardenCommand = {
      performLogin: login,
    };
    const cmdResponse: WardenCommandResponse = await this.exchangeCommand(loginCmd);
    return cmdResponse.performLogin;
  }

  public async executeWebAuthNLogin(contact: WardenContactEntry): Promise<WardenLoginResults> {
    let rval: WardenLoginResults = null;
    try {
      // Add it to the list
      //this.localStorageService.addCommonEmailAddress(emailAddress);
      const input: PublicKeyCredentialRequestOptionsJSON = await this.generateWebAuthnAuthenticationChallenge(contact);
      Logger.info('Got login challenge : %s', input);
      const creds: AuthenticationResponseJSON = await startAuthentication(input);
      Logger.info('Got creds: %j', creds);

      const loginCmd: WardenLoginRequest = {
        contact: contact,
        webAuthn: creds,
      };
      rval = await this.performLoginCmd(loginCmd);
      if (rval?.jwtToken) {
        //TODO: this.localStorageService.setJwtToken(req.jwtToken);
        //rval = true;
      }
    } catch (err) {
      Logger.error('WebauthN Failed : %s', err);
    }
    return rval;
  }

  public async refreshJwtToken(oldJwtToken: string): Promise<string> {
    let rval: string = null;
    if (StringRatchet.trimToNull(oldJwtToken)) {
      try {
        const resp: WardenCommandResponse = await this.exchangeCommand({ refreshJwtToken: oldJwtToken });
        rval = resp.refreshJwtToken;
      } catch (err) {
        Logger.error('JwtRefresh Failed : %s', err);
      }
    }
    return rval;
  }

  public async executeExpiringTokenBasedLogin(contact: WardenContactEntry, expiringToken: string): Promise<WardenLoginResults> {
    let rval: WardenLoginResults = null;
    try {
      // Add it to the list
      //this.localStorageService.addCommonEmailAddress(emailAddress);

      const loginCmd: WardenLoginRequest = {
        contact: contact,
        expiringToken: expiringToken,
      };
      rval = await this.performLoginCmd(loginCmd);
      if (rval?.jwtToken) {
        //TODO: this.localStorageService.setJwtToken(req.jwtToken);
        //rval = true;
      }
    } catch (err) {
      Logger.error('ExpiringToken login Failed : %s', err);
    }
    return rval;
  }
}
