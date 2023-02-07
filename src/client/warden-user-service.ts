import { Logger } from '@bitblit/ratchet/common/logger';
import { Subscription, timer } from 'rxjs';
import jwt_decode from 'jwt-decode';
import { WardenUserServiceOptions } from './provider/warden-user-service-options';
import { WardenLoggedInUserWrapper } from './provider/warden-logged-in-user-wrapper';
import { WardenContact } from '../common/model/warden-contact';
import { WardenJwtToken } from '../common/model/warden-jwt-token';
import { WardenLoginResults } from '../common/model/warden-login-results';
import { No, StringRatchet } from '@bitblit/ratchet/common';

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
      this.options.eventProcessor.onSuccessfulLogin(stored).then(No.op);
    }

    const timerSeconds: number = this.options.loginCheckTimerPingSeconds || 2.5;
    this.loggedInTimerSubscription = timer(0, timerSeconds * 1000).subscribe((t) => this.checkForAutoLogoutOrRefresh(t));
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
    const current: WardenLoggedInUserWrapper<T> = await this.fetchLoggedInUserWrapper();
    if (current) {
      const thresholdSeconds: number = this.options.autoLoginHandlingThresholdSeconds || 10; // Default to 10 seconds
      const secondsLeft: number = current.expirationEpochSeconds - Math.floor(Date.now() / 1000);
      if (secondsLeft < thresholdSeconds) {
        if (this.autoRefreshEnabled) {
          Logger.info('Under threshold, initiating auto-refresh');
          const result: WardenLoggedInUserWrapper<T> = await this.refreshToken();
          await this.options.eventProcessor.onAutomaticTokenRefresh(result);
        } else {
          Logger.info('Under threshold, initiating auto-logout');
          await this.logout();
        }
      }
    }
  }

  public async logout(): Promise<void> {
    this.options.loggedInUserProvider.logOutUser();
    await this.options.eventProcessor.onLogout();
  }

  public static wrapperIsExpired(value: WardenLoggedInUserWrapper<any>): boolean {
    const rval: boolean = value?.userObject?.exp && value.expirationEpochSeconds < Date.now() / 1000;
    return rval;
  }

  public async fetchLoggedInUserWrapper(): Promise<WardenLoggedInUserWrapper<T>> {
    let tmp: WardenLoggedInUserWrapper<T> = this.options.loggedInUserProvider.fetchLoggedInUserWrapper();
    if (tmp) {
      if (WardenUserService.wrapperIsExpired(tmp)) {
        // This is belt-and-suspenders for when the window was not open - during normal operation either
        // auto-logout thread or auto-refresh thread would have handled this
        Logger.info('Token is expired - auto logout triggered');
        await this.logout();
        tmp = null;
      }
    }
    return tmp;
  }

  public async loggedInUserHasRole(role: string): Promise<boolean> {
    let rval: boolean = false;
    if (StringRatchet.trimToNull(role)) {
      const t: WardenLoggedInUserWrapper<T> = await this.fetchLoggedInUserWrapper();
      const testRole: string = role.toLowerCase();
      rval = t?.userObject?.roles && !!t.userObject.roles.find((r) => r.toLowerCase() === testRole);
    }
    return rval;
  }

  public async isLoggedIn(): Promise<boolean> {
    const t: WardenLoggedInUserWrapper<T> = await this.fetchLoggedInUserWrapper();
    return !!t;
  }

  public async fetchLoggedInUserJwtObject(): Promise<WardenJwtToken<T>> {
    const t: WardenLoggedInUserWrapper<T> = await this.fetchLoggedInUserWrapper();
    return t ? t.userObject : null;
  }

  public async fetchLoggedInUserJwtToken(): Promise<string> {
    const t: WardenLoggedInUserWrapper<T> = await this.fetchLoggedInUserWrapper();
    return t ? t.jwtToken : null;
  }

  public async fetchLoggedInUserObject(): Promise<T> {
    const t: WardenJwtToken<T> = await this.fetchLoggedInUserJwtObject();
    return t ? t.user : null;
  }

  public async fetchLoggedInUserExpirationEpochSeconds(): Promise<number> {
    const t: WardenJwtToken<T> = await this.fetchLoggedInUserJwtObject();
    return t ? t.exp : null;
  }

  public async fetchLoggedInUserRemainingSeconds(): Promise<number> {
    const t: WardenJwtToken<T> = await this.fetchLoggedInUserJwtObject();
    return t ? t.exp - Math.floor(Date.now() / 1000) : null;
  }

  private async updateLoggedInUserFromTokenString(token: string): Promise<WardenLoggedInUserWrapper<T>> {
    let rval: WardenLoggedInUserWrapper<T> = null;
    if (StringRatchet.trimToNull(token)) {
      Logger.info('Called updateLoggedInUserFromTokenString with empty string - logging out');
      await this.logout();
    } else {
      const parsed: WardenJwtToken<T> = jwt_decode<WardenJwtToken<T>>(token);
      if (parsed) {
        rval = {
          userObject: parsed,
          jwtToken: token,
          expirationEpochSeconds: parsed.exp,
        };
        await this.options.eventProcessor.onSuccessfulLogin(rval);
      } else {
        Logger.warn('Failed to parse token %s - ignoring login and triggering failure');
        await this.options.eventProcessor.onLoginFailure('Could not parse token string');
      }
    }
    return rval;
  }

  public async refreshToken(): Promise<WardenLoggedInUserWrapper<T>> {
    let rval: WardenLoggedInUserWrapper<T> = null;
    const currentWrapper: WardenLoggedInUserWrapper<T> = await this.fetchLoggedInUserWrapper();
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

  public async executeValidationTokenBasedLogin(contact: WardenContact, token: string): Promise<WardenLoggedInUserWrapper<T>> {
    let rval: WardenLoggedInUserWrapper<T> = null;
    const resp: WardenLoginResults = await this.options.wardenClient.performLoginCmd({ contact: contact, expiringToken: token });
    if (resp) {
      if (resp.jwtToken) {
        rval = await this.updateLoggedInUserFromTokenString(resp.jwtToken);
      } else if (resp.error) {
        await this.options.eventProcessor.onLoginFailure(resp.error);
      } else {
        Logger.error('Response contained neither token nor error');
        await this.options.eventProcessor.onLoginFailure('Response contained neither token nor error');
      }
    } else {
      Logger.error('Login call failed');
      await this.options.eventProcessor.onLoginFailure('Login call returned null');
    }
    return rval;
  }
}
