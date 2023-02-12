import { WardenClientRecentLoginProvider } from './warden-client-recent-login-provider';
import { WardenRecentLoginDescriptor } from './warden-recent-login-descriptor';
import { WardenContact, WardenEntrySummary, WardenUtils } from '../../common';
import { Logger, StringRatchet } from '@bitblit/ratchet/common';

export abstract class WardenClientAbstractRecentLoginProvider implements WardenClientRecentLoginProvider {
  public abstract fetchCache(): WardenRecentLoginDescriptor[];
  public abstract updateCache(newValue: WardenRecentLoginDescriptor[]);

  public saveRecentLogin(entry: WardenEntrySummary): void {
    if (entry?.userId) {
      Logger.info('Saving recent login : %j', entry);
      let list: WardenRecentLoginDescriptor[] = this.fetchCache();
      list = list.filter((s) => s.user.userId !== entry.userId);
      list.push({
        user: entry,
        lastLoginEpochMS: Date.now(),
      });
    } else {
      Logger.warn('Cannot save recent login - no login provided :  %s', entry);
    }
  }

  public saveNewUser(userId: string, label: string, contact: WardenContact): void {
    if (StringRatchet.trimToNull(userId) && WardenUtils.validContact(contact)) {
      this.saveRecentLogin({
        userId: userId,
        contactMethods: [contact],
        webAuthnAuthenticatorIds: [],
        userLabel: label,
      });
    } else {
      Logger.warn('Cannot save new user - invalid data : %s : %j', userId, contact);
    }
  }

  public removeUser(userId: string): void {
    let list: WardenRecentLoginDescriptor[] = this.fetchCache();
    list = list.filter((c) => c.user.userId !== userId);
    this.updateCache(list);
  }
  public fetchAllLogins(): WardenRecentLoginDescriptor[] {
    return Object.assign([], this.fetchCache());
  }
  public clearAllLogins(): void {
    this.updateCache([]);
  }
}
