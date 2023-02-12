import { Logger } from '@bitblit/ratchet/common/logger';
import { Subscription, timer } from 'rxjs';
import jwt_decode from 'jwt-decode';
import { WardenUserServiceOptions } from './provider/warden-user-service-options';
import { WardenLoggedInUserWrapper } from './provider/warden-logged-in-user-wrapper';
import { WardenContact } from '../common/model/warden-contact';
import { WardenJwtToken } from '../common/model/warden-jwt-token';
import { WardenLoginResults } from '../common/model/warden-login-results';
import { No, StringRatchet } from '@bitblit/ratchet/common';
import { WardenCommand, WardenCommandResponse, WardenLoginRequest } from '../common';

/**
 * A service that handles logging in, saving the current user, watching
 * for expiration, auto-refreshing the token, wrapped around a
 * warden-client.
 *
 * T is the type of user object contained in the
 */
export class WardenUserService<T> {
  private loggedInTimerSubscription: Subscription;
  private _autoRefreshEnabled: boolean = false;

  constructor(private options: WardenUserServiceOptions<T>) {
    Logger.info('Initializing user service');
    // Immediately read from storage if there is something there
    const stored: WardenLoggedInUserWrapper<T> = this.options.loggedInUserProvider.fetchLoggedInUserWrapper();
    if (WardenUserService.wrapperIsExpired(stored)) {
      // Not treating this as a logout since it basically never logged in, just clearing it
      Logger.info('Stored token is expired, removing it');
      this.options.loggedInUserProvider.logOutUser();
    } else {
      // Fire the login event in case anything needs to know about the current user
      this.options.eventProcessor.onSuccessfulLogin(stored);
    }

    const timerSeconds: number = this.options.loginCheckTimerPingSeconds || 2.5;
    this.loggedInTimerSubscription = timer(0, timerSeconds * 1000).subscribe((t) => this.checkForAutoLogoutOrRefresh(t));
  }

  public get serviceOptions(): WardenUserServiceOptions<T> {
    return this.options;
  }

  public async createAccount(contact: WardenContact, sendCode?: boolean, label?: string, tags?: string[]): Promise<string> {
    const rval: string = await this.options.wardenClient.createAccount(contact, sendCode, label, tags);

    if (this.options.recentLoginProvider && StringRatchet.trimToNull(rval)) {
      this.options.recentLoginProvider.saveNewUser(rval, label, contact);
    }

    return rval;
  }

  public async addContactToLoggedInUser(contact: WardenContact): Promise<boolean> {
    return this.options.wardenClient.addContactToLoggedInUser(contact);
  }

  public get autoRefreshEnabled(): boolean {
    return this._autoRefreshEnabled;
  }

  public set autoRefreshEnabled(newValue: boolean) {
    if (newValue) {
      if (this.options.allowAutoRefresh) {
        this._autoRefreshEnabled = true;
      } else {
        throw new Error('Cannot enable auto-refresh - this is disabled in the user service options');
      }
    } else {
      this._autoRefreshEnabled = false;
    }
  }

  public async checkForAutoLogoutOrRefresh(t: number): Promise<void> {
    Logger.debug('Checking for auto-logout or refresh : %s', t);
    // This code will cause an auto-logout if the token is already expired, but not if its CLOSE to expiration
    const current: WardenLoggedInUserWrapper<T> = this.fetchLoggedInUserWrapper();
    if (current) {
      const thresholdSeconds: number = this.options.autoLoginHandlingThresholdSeconds || 10; // Default to 10 seconds
      const secondsLeft: number = current.expirationEpochSeconds - Math.floor(Date.now() / 1000);
      if (secondsLeft < thresholdSeconds) {
        if (this.autoRefreshEnabled) {
          Logger.info('Under threshold, initiating auto-refresh');
          const result: WardenLoggedInUserWrapper<T> = await this.refreshToken();
          this.options.eventProcessor.onAutomaticTokenRefresh(result);
        } else {
          Logger.info('Under threshold, initiating auto-logout');
          this.logout();
        }
      }
    }
  }

  public logout(): void {
    this.options.loggedInUserProvider.logOutUser();
    this.options.eventProcessor.onLogout();
  }

  public static wrapperIsExpired(value: WardenLoggedInUserWrapper<any>): boolean {
    const rval: boolean = value?.userObject?.exp && value.expirationEpochSeconds < Date.now() / 1000;
    return rval;
  }

  public fetchLoggedInUserWrapper(): WardenLoggedInUserWrapper<T> {
    let tmp: WardenLoggedInUserWrapper<T> = this.options.loggedInUserProvider.fetchLoggedInUserWrapper();
    if (tmp) {
      if (WardenUserService.wrapperIsExpired(tmp)) {
        // This is belt-and-suspenders for when the window was not open - during normal operation either
        // auto-logout thread or auto-refresh thread would have handled this
        Logger.info('Token is expired - auto logout triggered');
        this.logout();
        tmp = null;
      }
    }
    return tmp;
  }

  public loggedInUserHasRole(role: string): boolean {
    let rval: boolean = false;
    if (StringRatchet.trimToNull(role)) {
      const t: WardenLoggedInUserWrapper<T> = this.fetchLoggedInUserWrapper();
      const testRole: string = role.toLowerCase();
      rval = t?.userObject?.roles && !!t.userObject.roles.find((r) => r.toLowerCase() === testRole);
    }
    return rval;
  }

  public isLoggedIn(): boolean {
    const t: WardenLoggedInUserWrapper<T> = this.fetchLoggedInUserWrapper();
    return !!t;
  }

  public fetchLoggedInUserJwtObject(): WardenJwtToken<T> {
    const t: WardenLoggedInUserWrapper<T> = this.fetchLoggedInUserWrapper();
    return t ? t.userObject : null;
  }

  public fetchLoggedInUserJwtToken(): string {
    const t: WardenLoggedInUserWrapper<T> = this.fetchLoggedInUserWrapper();
    return t ? t.jwtToken : null;
  }

  public fetchLoggedInUserObject(): T {
    const t: WardenJwtToken<T> = this.fetchLoggedInUserJwtObject();
    return t ? t.user : null;
  }

  public fetchLoggedInUserExpirationEpochSeconds(): number {
    const t: WardenJwtToken<T> = this.fetchLoggedInUserJwtObject();
    return t ? t.exp : null;
  }

  public fetchLoggedInUserRemainingSeconds(): number {
    const t: WardenJwtToken<T> = this.fetchLoggedInUserJwtObject();
    return t ? t.exp - Math.floor(Date.now() / 1000) : null;
  }

  private updateLoggedInUserFromTokenString(token: string): WardenLoggedInUserWrapper<T> {
    let rval: WardenLoggedInUserWrapper<T> = null;
    if (!StringRatchet.trimToNull(token)) {
      Logger.info('Called updateLoggedInUserFromTokenString with empty string - logging out');
      this.logout();
    } else {
      Logger.info('updateLoggedInUserFromTokenString : %s', token);
      const parsed: WardenJwtToken<T> = jwt_decode<WardenJwtToken<T>>(token);
      if (parsed) {
        rval = {
          userObject: parsed,
          jwtToken: token,
          expirationEpochSeconds: parsed.exp,
        };
        this.options.loggedInUserProvider.setLoggedInUserWrapper(rval);
        this.options.eventProcessor.onSuccessfulLogin(rval);
      } else {
        Logger.warn('Failed to parse token %s - ignoring login and triggering failure');
        this.options.eventProcessor.onLoginFailure('Could not parse token string');
      }
    }
    return rval;
  }

  public async refreshToken(): Promise<WardenLoggedInUserWrapper<T>> {
    let rval: WardenLoggedInUserWrapper<T> = null;
    const currentWrapper: WardenLoggedInUserWrapper<T> = this.fetchLoggedInUserWrapper();
    if (!currentWrapper) {
      Logger.info('Could not refresh - no token available');
    } else {
      const newToken: string = await this.options.wardenClient.refreshJwtToken(currentWrapper.jwtToken);
      rval = await this.updateLoggedInUserFromTokenString(newToken);
    }
    return rval;
  }

  // Passthru for convenience
  public async sendExpiringCode(contact: WardenContact): Promise<boolean> {
    return this.options.wardenClient.sendExpiringValidationToken(contact);
  }

  private async processWardenLoginResults(resp: WardenLoginResults): Promise<WardenLoggedInUserWrapper<T>> {
    let rval: WardenLoggedInUserWrapper<T> = null;
    if (resp) {
      Logger.info('Warden: response : %j ', resp);
      if (resp.jwtToken) {
        Logger.info('Applying login');
        rval = await this.updateLoggedInUserFromTokenString(resp.jwtToken);
      } else if (resp.error) {
        this.options.eventProcessor.onLoginFailure(resp.error);
      } else {
        Logger.error('Response contained neither token nor error');
        this.options.eventProcessor.onLoginFailure('Response contained neither token nor error');
      }
    } else {
      Logger.error('Login call failed');
      this.options.eventProcessor.onLoginFailure('Login call returned null');
    }
    return rval;
  }

  private updateRecentLoginsFromLoggedInUserWrapper(res: WardenLoggedInUserWrapper<T>): void {
    // Only store if we have a provider, and it was a successful login
    if (this.options.recentLoginProvider) {
      Logger.info('UserService : Saving recent login %j', res);
      this.options.recentLoginProvider.saveRecentLogin(res.userObject.loginData);
    } else {
      Logger.info('Not saving recent login - no storage configured');
    }
  }

  public async executeWebAuthnBasedLogin(contact: WardenContact): Promise<WardenLoggedInUserWrapper<T>> {
    const resp: WardenLoginResults = await this.options.wardenClient.executeWebAuthNLogin(contact);
    const rval: WardenLoggedInUserWrapper<T> = await this.processWardenLoginResults(resp);
    this.updateRecentLoginsFromLoggedInUserWrapper(rval);
    return rval;
  }

  public async executeValidationTokenBasedLogin(contact: WardenContact, token: string): Promise<WardenLoggedInUserWrapper<T>> {
    Logger.info('Warden: executeValidationTokenBasedLogin : %j : %s ', contact, token);
    const resp: WardenLoginResults = await this.options.wardenClient.performLoginCmd({ contact: contact, expiringToken: token });
    const rval: WardenLoggedInUserWrapper<T> = await this.processWardenLoginResults(resp);
    this.updateRecentLoginsFromLoggedInUserWrapper(rval);
    return rval;
  }
}
