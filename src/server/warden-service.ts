import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  verifyAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';
import { WardenServiceOptions } from '../common/model/warden-service-options';
import { WardenStorageProvider } from './provider/warden-storage-provider';
import { WardenContact } from '../common/model/warden-contact';
import { WardenEntry } from '../common/model/warden-entry';
import { WardenStoreRegistrationResponse } from '../common/model/warden-store-registration-response';
import { WardenWebAuthnEntry } from '../common/model/warden-web-authn-entry';
import { WardenMessageSendingProvider } from './provider/warden-message-sending-provider';
import { WardenLoginRequest } from '../common/model/warden-login-request';
import { WardenStoreRegistrationResponseType } from '../common/model/warden-store-registration-response-type';
import { WardenCustomerMessageType } from '../common/model/warden-customer-message-type';
import { ExpiringCode, ExpiringCodeProvider, ExpiringCodeRatchet } from '@bitblit/ratchet/aws';
import {
  Base64Ratchet,
  ErrorRatchet,
  ExpiredJwtHandling,
  JwtRatchetLike,
  Logger,
  RequireRatchet,
  StringRatchet,
} from '@bitblit/ratchet/common';
import { WardenCommandResponse } from '../common/command/warden-command-response';
import { WardenCommand } from '../common/command/warden-command';
import { WardenUtils } from '../common/util/warden-utils';
import { WardenUserTokenDataProvider } from './provider/warden-user-token-data-provider';
import { WardenDefaultUserTokenDataProvider } from './provider/warden-default-user-token-data-provider';
import { WardenJwtToken } from '../common/model/warden-jwt-token';
import { WardenLoginResults } from '../common';

export class WardenService {
  private expiringCodeRatchet: ExpiringCodeRatchet;

  constructor(
    private options: WardenServiceOptions,
    private storageProvider: WardenStorageProvider,
    private messageSendingProviders: WardenMessageSendingProvider<any>[],
    private expiringCodeProvider: ExpiringCodeProvider,
    private jwtRatchetLike: JwtRatchetLike,
    private userTokenDataProvider: WardenUserTokenDataProvider<any> = new WardenDefaultUserTokenDataProvider()
  ) {
    this.expiringCodeRatchet = new ExpiringCodeRatchet(this.expiringCodeProvider);
  }

  // A helper function for bridging across GraphQL as an embedded JSON command
  public async processCommandStringToString(cmdString: string, origin: string, loggedInUserId: string): Promise<string> {
    let rval: string = null;
    try {
      const cmd: WardenCommand = JSON.parse(cmdString);
      const resp: WardenCommandResponse = await this.processCommandToResponse(cmd, origin, loggedInUserId);
      if (resp === null) {
        Logger.warn('Response was null for %s %s %s', cmdString, origin, loggedInUserId);
      } else {
        rval = JSON.stringify(resp);
      }
    } catch (err) {
      // Just cast it directly
      const errString: string = ErrorRatchet.safeStringifyErr(err);
      Logger.error('Failed %s : %j', errString, cmdString, err);
      rval = JSON.stringify({ error: errString } as WardenCommandResponse);
    }
    return rval;
  }

  // A helper function for bridging across GraphQL as an embedded JSON command
  public async processCommandToResponse(cmd: WardenCommand, origin: string, loggedInUserId: string): Promise<WardenCommandResponse> {
    let rval: WardenCommandResponse = null;
    if (cmd) {
      Logger.info('Processing command : UserID: %s  Origin: %s Command: %j', loggedInUserId, origin, cmd);

      if (cmd.sendExpiringValidationToken) {
        rval = { sendExpiringValidationToken: await this.sendExpiringValidationToken(cmd.sendExpiringValidationToken) };
      } else if (cmd.generateWebAuthnAuthenticationChallenge) {
        const tmp: PublicKeyCredentialRequestOptionsJSON = await this.generateWebAuthnAuthenticationChallengeForContact(
          cmd.generateWebAuthnAuthenticationChallenge,
          origin
        );
        rval = { generateWebAuthnAuthenticationChallenge: { dataAsJson: JSON.stringify(tmp) } };
      } else if (cmd.createAccount) {
        rval = {
          createAccount: await this.createAccount(
            cmd.createAccount.contact,
            cmd.createAccount.sendCode,
            cmd.createAccount.label,
            cmd.createAccount.tags
          ),
        };
      } else if (cmd.generateWebAuthnRegistrationChallengeForLoggedInUser) {
        if (!StringRatchet.trimToNull(loggedInUserId)) {
          ErrorRatchet.throwFormattedErr('This requires a logged in user');
        }
        const tmp: PublicKeyCredentialCreationOptionsJSON = await this.generateWebAuthnRegistrationChallengeForLoggedInUser(
          loggedInUserId,
          origin
        );
        rval = { generateWebAuthnRegistrationChallengeForLoggedInUser: { dataAsJson: JSON.stringify(tmp) } };
      } else if (cmd.addWebAuthnRegistrationToLoggedInUser) {
        if (!StringRatchet.trimToNull(loggedInUserId)) {
          ErrorRatchet.throwFormattedErr('This requires a logged in user');
        }
        const data: RegistrationResponseJSON = JSON.parse(cmd.addWebAuthnRegistrationToLoggedInUser.dataAsJson);
        const out: WardenStoreRegistrationResponse = await this.storeAuthnRegistration(loggedInUserId, origin, data);
        rval = { addWebAuthnRegistrationToLoggedInUser: out.result === WardenStoreRegistrationResponseType.Verified };
      } else if (cmd.removeWebAuthnRegistration) {
        rval = {
          removeWebAuthnRegistration: !!(await this.removeSingleWebAuthnRegistration(
            cmd.removeWebAuthnRegistration.userId,
            cmd.removeWebAuthnRegistration.credentialId
          )),
        };
      }
    } else if (cmd.performLogin) {
      const loginData: WardenLoginRequest = cmd.performLogin;
      const loginOk: boolean = await this.processLogin(loginData, origin);
      Logger.info('Performing login - login auth check was : %s', loginOk);
      if (loginOk) {
        const user: WardenEntry = await this.storageProvider.findEntryByContact(loginData.contact);
        Logger.info('User: %j', user);
        const expirationSeconds: number = await this.userTokenDataProvider.fetchUserTokenExpirationSeconds(user);
        Logger.info('expirationSeconds: %j', expirationSeconds);
        const userData: any = await this.userTokenDataProvider.fetchUserTokenData(user);
        Logger.info('userData: %j', userData);
        const roles: string[] = await this.userTokenDataProvider.fetchUserRoles(user);
        Logger.info('roles: %j', roles);
        const wardenToken: WardenJwtToken<any> = { userId: user.userId, user: userData, roles: roles, proxy: null };
        Logger.info('wardenToken: %j', wardenToken);
        const jwtToken: string = await this.jwtRatchetLike.createTokenString(wardenToken, expirationSeconds);
        Logger.info('jwtToken: %j', jwtToken);
        const output: WardenLoginResults = {
          request: loginData,
          jwtToken: jwtToken,
        };
        Logger.info('output: %j', output);
        rval = { performLogin: output };
      } else {
        rval = { error: 'Login failed' };
      }
    } else if (cmd.refreshJwtToken) {
      const parsed: WardenJwtToken<any> = await this.jwtRatchetLike.decodeToken(cmd.refreshJwtToken, ExpiredJwtHandling.THROW_EXCEPTION);
      const user: WardenEntry = await this.storageProvider.findEntryById(parsed.userId);
      const expirationSeconds: number = await this.userTokenDataProvider.fetchUserTokenExpirationSeconds(user);
      const newToken: string = await this.jwtRatchetLike.refreshJWTString(cmd.refreshJwtToken, false, expirationSeconds);
      rval = {
        refreshJwtToken: newToken,
      };
    } else {
      rval = { error: 'No command sent' };
    }
    return rval;
  }

  // Creates a new account, returns the userId for that account upon success
  public async createAccount(contact: WardenContact, sendCode?: boolean, label?: string, tags?: string[]): Promise<string> {
    let rval: string = null;
    if (WardenUtils.validContact(contact)) {
      const old: WardenEntry = await this.storageProvider.findEntryByContact(contact);
      if (!!old) {
        ErrorRatchet.throwFormattedErr('Cannot create - account already exists for %j', contact);
      }

      const prov: WardenMessageSendingProvider<any> = this.senderForContact(contact);
      if (!prov) {
        ErrorRatchet.throwFormattedErr('Cannot create - no sending provider for type %s', contact.type);
      }
      const guid: string = StringRatchet.createType4Guid();
      const now: number = Date.now();
      const newUser: WardenEntry = {
        userId: guid,
        userLabel: label || 'User ' + guid, // Usually full name, could be something else
        contactMethods: [contact],
        tags: tags || [],
        webAuthnAuthenticators: [],
        createdEpochMS: now,
        updatedEpochMS: now,
      };
      const next: WardenEntry = await this.storageProvider.saveEntry(newUser);
      rval = next.userId;

      if (sendCode) {
        Logger.info('New user %j created and send requested - sending', next);
        await this.sendExpiringValidationToken(contact);
      }
    } else {
      ErrorRatchet.throwFormattedErr('Cannot create - invalid contact (missing or invalid fields)');
    }
    return rval;
  }

  // For an existing user, add another contact method
  // A given contact (eg, email address, phone number) can only associated with a single
  // userId at a time
  public async addContactMethodToUser(userId: string, contact: WardenContact): Promise<boolean> {
    let rval: boolean = false;
    if (StringRatchet.trimToNull(userId) && WardenUtils.validContact(contact)) {
      const otherUser: WardenEntry = await this.storageProvider.findEntryByContact(contact);
      if (otherUser && otherUser.userId !== userId) {
        ErrorRatchet.throwFormattedErr('Cannot add contact to this user, another user already has that contact');
      }
      const curUser: WardenEntry = await this.storageProvider.findEntryById(userId);
      if (!curUser) {
        ErrorRatchet.throwFormattedErr('Cannot add contact to this user, user does not exist');
      }
      curUser.contactMethods.push(contact);
      await this.storageProvider.saveEntry(curUser);
      rval = true;
    } else {
      ErrorRatchet.throwFormattedErr('Cannot add - invalid config : %s %j', userId, contact);
    }
    return rval;
  }

  /* CAW : I dont think anything uses this
  public async generateWebAuthnRegistrationOptionsForContact(
    contact: WardenContact,
    origin: string
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    // (Pseudocode) Retrieve the user from the database
    // after they've logged in
    let rval: any = null;
    if (WardenUtils.validContact(contact) && StringRatchet.trimToNull(origin)) {
      const entry: WardenEntry = await this.storageProvider.findEntryByContact(contact);
      rval = this.generateWebAuthnRegistrationChallengeForLoggedInUser(entry.userId, origin);
    } else {
      ErrorRatchet.throwFormattedErr('Cannot generate options - invalid contact');
    }
    return rval;
  }

   */

  // Used as the first step of adding a new WebAuthn device to an existing (logged in) user
  // Server creates a challenge that the device will sign
  public async generateWebAuthnRegistrationChallengeForLoggedInUser(
    userId: string,
    origin: string
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    if (!origin || !this.options.allowedOrigins.includes(origin)) {
      throw new Error('Invalid origin : ' + origin);
    }
    const asUrl: URL = new URL(origin);
    const rpID: string = asUrl.hostname;

    const entry: WardenEntry = await this.storageProvider.findEntryById(userId);
    const options = generateRegistrationOptions({
      rpName: this.options.relyingPartyName,
      rpID: rpID,
      userID: entry.userId,
      userName: entry.userLabel,
      // Don't prompt users for additional information about the authenticator
      // (Recommended for smoother UX)
      attestationType: 'none',
      // Prevent users from re-registering existing authenticators
      excludeCredentials: entry.webAuthnAuthenticators.map((authenticator) => ({
        id: Base64Ratchet.base64StringToBuffer(authenticator.credentialPublicKeyBase64),
        type: 'public-key',
        // Optional
        transports: authenticator.transports as unknown as AuthenticatorTransportFuture[],
      })),
    });

    await this.storageProvider.updateUserChallenge(entry.userId, rpID, options.challenge);

    return options;
  }

  // Given a new device's registration, add it to the specified user account as a valid login method
  public async storeAuthnRegistration(
    userId: string,
    origin: string,
    data: RegistrationResponseJSON
  ): Promise<WardenStoreRegistrationResponse> {
    Logger.info('Store authn data : %j', data);
    let rval: WardenStoreRegistrationResponse = null;
    try {
      if (!origin || !this.options.allowedOrigins.includes(origin)) {
        throw new Error('Invalid origin : ' + origin);
      }
      const asUrl: URL = new URL(origin);
      const rpID: string = asUrl.hostname;

      const user: WardenEntry = await this.storageProvider.findEntryById(userId);
      // (Pseudocode) Get `options.challenge` that was saved above
      const expectedChallenge: string = await this.storageProvider.fetchCurrentUserChallenge(user.userId, rpID);

      const vrOpts: VerifyRegistrationResponseOpts = {
        response: data,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      };

      const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse(vrOpts);
      Logger.info('Result : %j', verification);

      rval = {
        id: data.id,
        result: verification.verified ? WardenStoreRegistrationResponseType.Verified : WardenStoreRegistrationResponseType.Failed,
      };

      if (rval.result === WardenStoreRegistrationResponseType.Verified) {
        Logger.info('Storing registration');
        const newAuth: WardenWebAuthnEntry = {
          counter: verification.registrationInfo.counter,
          credentialBackedUp: verification.registrationInfo.credentialBackedUp,
          credentialDeviceType: verification.registrationInfo.credentialDeviceType,
          credentialIdBase64: data.id, //Base64Ratchet.generateBase64VersionOfBuffer(verification.registrationInfo.credentialID),
          credentialPublicKeyBase64: Base64Ratchet.generateBase64VersionOfBuffer(
            Buffer.from(verification.registrationInfo.credentialPublicKey)
          ),
          //transports: TBD
        };

        // (Pseudocode) Save the authenticator info so that we can
        // get it by user ID later
        user.webAuthnAuthenticators = (user.webAuthnAuthenticators || []).filter(
          (wa) => wa.credentialIdBase64 !== newAuth.credentialIdBase64
        );
        user.webAuthnAuthenticators.push(newAuth);
        const storedUser: WardenEntry = await this.storageProvider.saveEntry(user);
        Logger.info('Stored auth : %j', storedUser);
      }
    } catch (err) {
      rval = {
        id: data.id,
        result: WardenStoreRegistrationResponseType.Error,
        notes: ErrorRatchet.safeStringifyErr(err),
      };
    }

    return rval;
  }

  // Helper method that looks up the contact
  public async generateWebAuthnAuthenticationChallengeForContact(
    contact: WardenContact,
    origin: string
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    // (Pseudocode) Retrieve the user from the database
    // after they've logged in
    const user: WardenEntry = await this.storageProvider.findEntryByContact(contact);
    const rval: PublicKeyCredentialRequestOptionsJSON = await this.generateWebAuthnAuthenticationChallenge(user, origin);
    return rval;
  }

  // Part of the login process - for a given user, generate the challenge that the deviec will have to answer
  public async generateWebAuthnAuthenticationChallenge(user: WardenEntry, origin: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    // (Pseudocode) Retrieve any of the user's previously-
    // registered authenticators
    const userAuthenticators: WardenWebAuthnEntry[] = user.webAuthnAuthenticators;
    if (!origin || !this.options.allowedOrigins.includes(origin)) {
      throw new Error('Invalid origin : ' + origin);
    }
    const asUrl: URL = new URL(origin);
    const rpID: string = asUrl.hostname;

    const out: any[] = userAuthenticators.map((authenticator) => {
      const next: any = {
        id: Buffer.from(authenticator.credentialIdBase64, 'base64'),
        type: 'public-key',
        // Optional
        transports: authenticator.transports,
      };
      return next;
    });

    const options: PublicKeyCredentialRequestOptionsJSON = generateAuthenticationOptions({
      // Require users to use a previously-registered authenticator
      allowCredentials: out,
      userVerification: 'preferred',
    });

    // (Pseudocode) Remember this challenge for this user
    await this.storageProvider.updateUserChallenge(user.userId, rpID, options.challenge);

    return options;
  }

  // For a given contact type, find the sender that can be used to send messages to it
  public senderForContact(contact: WardenContact): WardenMessageSendingProvider<any> {
    let rval: WardenMessageSendingProvider<any> = null;
    if (contact?.type) {
      rval = (this.messageSendingProviders || []).find((p) => p.handlesContactType(contact.type));
    }
    return rval;
  }

  // Send a single use token to this contact
  public async sendExpiringValidationToken(request: WardenContact): Promise<boolean> {
    let rval: boolean = false;
    if (request?.type && StringRatchet.trimToNull(request?.value)) {
      const prov: WardenMessageSendingProvider<any> = this.senderForContact(request);
      if (prov) {
        const token: ExpiringCode = await this.expiringCodeRatchet.createNewCode({
          context: request.value,
          length: 6,
          alphabet: '0123456789',
          timeToLiveSeconds: 300,
          tags: ['Login'],
        });
        const msg: any = await prov.formatMessage(request, WardenCustomerMessageType.ExpiringCode, {
          code: token.code,
          relyingPartyName: this.options.relyingPartyName,
        });
        rval = await prov.sendMessage(request, msg);
      } else {
        ErrorRatchet.throwFormattedErr('No provider found for contact type %s', request.type);
      }
    } else {
      ErrorRatchet.throwFormattedErr('Cannot send - invalid request %j', request);
    }
    return rval;
  }

  // Perform a login using one of several methods
  // Delegates to functions that handle the specific methods
  public async processLogin(request: WardenLoginRequest, origin: string): Promise<boolean> {
    Logger.info('Processing login : %s : %j', origin, request);
    let rval: boolean = false;
    RequireRatchet.notNullOrUndefined(request, 'request');
    RequireRatchet.true(WardenUtils.validContact(request?.contact), 'Invalid contact');
    RequireRatchet.true(
      !!request?.webAuthn || !!StringRatchet.trimToNull(request?.expiringToken),
      'You must provide one of webAuthn or expiringToken'
    );
    RequireRatchet.true(
      !request?.webAuthn || !StringRatchet.trimToNull(request?.expiringToken),
      'WebAuthn and ExpiringToken may not BOTH be set'
    );

    const user: WardenEntry = await this.storageProvider.findEntryByContact(request.contact);
    if (!user) {
      ErrorRatchet.throwFormattedErr('No user found for %j', request.contact);
    }

    if (request.webAuthn) {
      rval = await this.loginWithWebAuthnRequest(user, origin, request.webAuthn);
    } else if (StringRatchet.trimToNull(request.expiringToken)) {
      const lookup: boolean = await this.expiringCodeRatchet.checkCode(
        StringRatchet.trimToEmpty(request.expiringToken),
        StringRatchet.trimToEmpty(request.contact.value),
        true
      );
      if (lookup) {
        rval = true;
      } else {
        ErrorRatchet.throwFormattedErr('Cannot login - token is invalid for this user');
      }
    }
    return rval;
  }

  // Perform a login using webAuthn
  public async loginWithWebAuthnRequest(user: WardenEntry, origin: string, data: AuthenticationResponseJSON): Promise<boolean> {
    let rval: boolean = false;
    const asUrl: URL = new URL(origin);
    const rpID: string = asUrl.hostname;
    const expectedChallenge: string = await this.storageProvider.fetchCurrentUserChallenge(user.userId, rpID);

    // (Pseudocode} Retrieve an authenticator from the DB that
    // should match the `id` in the returned credential
    //const b64id: string = Base64Ratchet.base64StringToString(data.id);
    const auth: WardenWebAuthnEntry = (user.webAuthnAuthenticators || []).find((s) => s.credentialIdBase64 === data.id);

    if (!auth) {
      throw new Error(`Could not find authenticator ${data.id} for user ${user.userId}`);
    }

    const authenticator: AuthenticatorDevice = {
      counter: auth.counter,
      credentialID: Base64Ratchet.base64StringToBuffer(auth.credentialIdBase64),
      credentialPublicKey: Base64Ratchet.base64StringToBuffer(auth.credentialPublicKeyBase64),
    };

    const vrOpts: VerifyAuthenticationResponseOpts = {
      response: data,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
    };

    const verification: VerifiedAuthenticationResponse = await verifyAuthenticationResponse(vrOpts);

    if (verification.verified) {
      rval = true;
    }
    return rval;
  }

  // Unregisters a device from a given user account
  public async removeSingleWebAuthnRegistration(userId: string, key: string): Promise<WardenEntry> {
    let ent: WardenEntry = await this.storageProvider.findEntryById(userId);
    if (ent) {
      ent.webAuthnAuthenticators = (ent.webAuthnAuthenticators || []).filter((s) => s.credentialIdBase64 !== key);
      ent = await this.storageProvider.saveEntry(ent);
    } else {
      Logger.info('Not removing - no such user as %s', userId);
    }
    return ent;
  }

  // Admin function - pass thru to the storage layer
  public async removeUser(userId: string): Promise<boolean> {
    const rval: boolean = StringRatchet.trimToNull(userId) ? await this.storageProvider.removeEntry(userId) : false;
    return rval;
  }
}
