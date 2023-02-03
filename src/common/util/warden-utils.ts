import { WardenContact } from '../model/warden-contact';
import { WardenContactType } from '../model/warden-contact-type';
import { StringRatchet } from '@bitblit/ratchet/common';
import { WardenEntrySummary } from '../model/warden-entry-summary';
import { WardenEntry } from '../model/warden-entry';

export class WardenUtils {
  // Prevent instantiation
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  constructor() {}

  public static validContact(contact: WardenContact): boolean {
    let rval: boolean = false;
    if (contact?.type && StringRatchet.trimToNull(contact?.value)) {
      switch (contact.type) {
        case WardenContactType.EmailAddress:
          rval = !!contact.value.match(/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/);
          break;
        case WardenContactType.TextCapablePhoneNumber:
          rval = !!contact.value.match(/^[\\+]?[(]?[0-9]{3}[)]?[-\\s\\.]?[0-9]{3}[-\\s\\.]?[0-9]{4,6}$/im);
          break;
        default:
          rval = false;
      }
    }

    return rval;
  }

  public static stripWardenEntryToSummary(we: WardenEntry): WardenEntrySummary {
    const rval: WardenEntrySummary = we
      ? {
          userId: we.userId,
          userLabel: we.userLabel,
          contactMethods: we.contactMethods,
        }
      : null;
    return rval;
  }
}
