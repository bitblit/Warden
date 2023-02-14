import { Component } from '@angular/core';
import { DurationRatchet, Logger } from '@bitblit/ratchet/common';
import { WardenLoggedInUserWrapper } from '../../../client/provider/warden-logged-in-user-wrapper';
import { WardenUserService } from '../../../client/warden-user-service';
import { WardenContact } from '../../../common/model/warden-contact';
import { WardenUtils } from '../../../common/util/warden-utils';

@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
  styleUrls: ['user-profile.component.scss'],
})
export class UserProfileComponent<T> {
  public user: WardenLoggedInUserWrapper<T>;
  public timeLeftMS: string;

  constructor(private userService: WardenUserService<T>) {
    Logger.info('Construct WardenUserProfileComponent');
    this.updateData();
  }

  private updateData(): void {
    Logger.info('Called updateData');
    const tok: WardenLoggedInUserWrapper<T> = this.userService.fetchLoggedInUserWrapper();
    this.user = tok;
    this.timeLeftMS = DurationRatchet.formatMsDuration(this.user.userObject.exp * 1000 - Date.now());
  }

  public async refreshToken(): Promise<void> {
    await this.userService.refreshToken();
    this.updateData();
  }

  public async addContact(): Promise<void> {
    const value: string = prompt('Please enter a phone number or email address to add');
    const newContact: WardenContact = WardenUtils.stringToWardenContact(value);
    if (newContact) {
      const rval: boolean = await this.userService.addContactToLoggedInUser(newContact);
      if (rval) {
        await this.userService.refreshToken();
      } else {
        Logger.info('Add contact failed : %s', value);
      }
    } else {
      Logger.info('No contact found for %s', value);
    }
  }

  public async addWebAuthnDevice(): Promise<void> {
    await this.userService.saveCurrentDeviceAsWebAuthnForCurrentUser();
    await this.userService.refreshToken();
  }

  public async removeContact(ct: WardenContact): Promise<void> {
    Logger.info('Remove %j', ct);
    await this.userService.removeContactFromLoggedInUser(ct);
    await this.userService.refreshToken();
  }

  public async removeWebAuthn(webId: string): Promise<void> {
    Logger.info('Remove webauthn: %s', webId);
    await this.userService.removeWebAuthnRegistrationFromLoggedInUser(webId);
    await this.userService.refreshToken();
  }
}