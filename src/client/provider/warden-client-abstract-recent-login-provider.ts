import { WardenClientRecentLoginProvider } from './warden-client-recent-login-provider';
import { WardenRecentLoginDescriptor } from './warden-recent-login-descriptor';
import { WardenContact } from '../../common';

export abstract class WardenClientAbstractRecentLoginProvider implements WardenClientRecentLoginProvider {
  public abstract fetchCache(): WardenRecentLoginDescriptor[];
  public abstract updateCache(newValue: WardenRecentLoginDescriptor[]);

  private findOrAddDefaultUserEntry(userId: string, list: WardenRecentLoginDescriptor[]): WardenRecentLoginDescriptor {
    let current: WardenRecentLoginDescriptor = list.find((d) => d.userId === userId);
    if (!current) {
      current = {
        userId: userId,
        lastLoginEpochMS: null,
        contacts: [],
        webAuthn: false,
      };
      list.push(current);
    }
    return current;
  }

  public async addWebAuthnLogin(userId: string): Promise<void> {
    const list: WardenRecentLoginDescriptor[] = this.fetchCache();
    const current: WardenRecentLoginDescriptor = this.findOrAddDefaultUserEntry(userId, list);
    current.lastLoginEpochMS = Date.now();
    current.webAuthn = true;
    this.updateCache(list);
  }
  public async addContactLogin(userId: string, contact: WardenContact): Promise<void> {
    const list: WardenRecentLoginDescriptor[] = this.fetchCache();
    const current: WardenRecentLoginDescriptor = this.findOrAddDefaultUserEntry(userId, list);
    current.lastLoginEpochMS = Date.now();
    current.contacts = (current.contacts || []).filter((c) => c.type != contact.type || c.value != contact.value);
    current.contacts.push(contact);
    this.updateCache(list);
  }
  public async clearLoginsForUserId(userId: string): Promise<void> {
    let list: WardenRecentLoginDescriptor[] = this.fetchCache();
    list = list.filter((c) => c.userId !== userId);
    this.updateCache(list);
  }
  public async fetchAllLogins(): Promise<WardenRecentLoginDescriptor[]> {
    return Object.assign([], this.fetchCache());
  }
  public async clearAllLogins(): Promise<void> {
    this.updateCache([]);
  }
}
