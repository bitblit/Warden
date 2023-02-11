//    Service for interacting with positions for a given user
import { WardenCommand } from '../common/command/warden-command';
import { WardenContact } from '../common/model/warden-contact';
import { WardenCommandExchangeProvider } from './provider/warden-command-exchange-provider';
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
import { WardenClientRecentLoginProvider } from './provider/warden-client-recent-login-provider';

export class WardenClient {
  constructor(private commandSender: WardenCommandExchangeProvider, private _recentLoginProvider?: WardenClientRecentLoginProvider) {}

  public get recentLoginProvider(): WardenClientRecentLoginProvider {
    return this._recentLoginProvider;
  }

  public async exchangeCommand(cmd: WardenCommand, returnErrors?: boolean): Promise<WardenCommandResponse> {
    const asString: string = JSON.stringify(cmd);
    const resp: string = await this.commandSender.sendCommand(asString);
    const parsed: WardenCommandResponse = JSON.parse(resp);

    if (parsed?.error && !returnErrors) {
      ErrorRatchet.throwFormattedErr('%s', parsed.error);
    }
    return parsed;
  }

  public async createAccount(contact: WardenContact, sendCode?: boolean, label?: string, tags?: string[]): Promise<string> {
    const cmd: WardenCommand = {
      createAccount: {
        contact: contact,
        sendCode: sendCode,
        label: label,
        tags: tags,
      },
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);

    if (this.recentLoginProvider && StringRatchet.trimToNull(rval.createAccount)) {
      await this.recentLoginProvider.addContactLogin(rval.createAccount, contact);
    }

    return rval.createAccount;
  }

  public async generateWebAuthnAuthenticationChallenge(contact: WardenContact): Promise<PublicKeyCredentialRequestOptionsJSON> {
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

  public async sendExpiringValidationToken(contact: WardenContact): Promise<boolean> {
    const cmd: WardenCommand = {
      sendExpiringValidationToken: contact,
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);
    return rval.sendExpiringValidationToken;
  }

  public async addContactToLoggedInUser(contact: WardenContact): Promise<boolean> {
    const cmd: WardenCommand = {
      addContactToLoggedInUser: contact,
    };
    const rval: WardenCommandResponse = await this.exchangeCommand(cmd);
    return rval.addContactToLoggedInUser;
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
    // Only store if we have a provider, and it was a successful login
    if (this.recentLoginProvider && StringRatchet.trimToNull(cmdResponse.performLogin.jwtToken)) {
      if (login.contact) {
        await this.recentLoginProvider.addContactLogin(cmdResponse.performLogin.userId, login.contact);
      } else if (login.webAuthn) {
        await this.recentLoginProvider.addWebAuthnLogin(cmdResponse.performLogin.userId);
      }
    }

    return cmdResponse.performLogin;
  }

  public async executeWebAuthNLogin(contact: WardenContact): Promise<WardenLoginResults> {
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

  public async executeExpiringTokenBasedLogin(contact: WardenContact, expiringToken: string): Promise<WardenLoginResults> {
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
