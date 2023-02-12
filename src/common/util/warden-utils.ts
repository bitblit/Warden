import { WardenContact } from '../model/warden-contact';
import { WardenContactType } from '../model/warden-contact-type';
import { StringRatchet } from '@bitblit/ratchet/common';
import { WardenEntrySummary } from '../model/warden-entry-summary';
import { WardenEntry } from '../model/warden-entry';
import { WardenLoginRequest } from '../model/warden-login-request';

export class WardenUtils {
  // Prevent instantiation
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  constructor() {}

  public static validLoginRequest(req: WardenLoginRequest): boolean {
    let rval: boolean = false;
    if (req) {
      if (StringRatchet.trimToNull(req.userId) || WardenUtils.validContact(req.contact)) {
        if (StringRatchet.trimToNull(req.expiringToken) || StringRatchet.trimToNull(req.jwtTokenToRefresh) || req.webAuthn) {
          rval = true;
        }
      }
    }
    return rval;
  }

  public static stringToWardenContact(input: string): WardenContact {
    let rval: WardenContact = null;
    const type: WardenContactType = WardenUtils.stringToContactType(input);
    if (type) {
      rval = {
        type: type,
        value: input,
      };
    }
    return rval;
  }

  public static stringToContactType(input: string): WardenContactType {
    let rval: WardenContactType = null;
    if (StringRatchet.trimToNull(input)) {
      rval = WardenUtils.stringIsEmailAddress(input) ? WardenContactType.EmailAddress : null;
      rval = !rval && WardenUtils.stringIsPhoneNumber(input) ? WardenContactType.TextCapablePhoneNumber : null;
    }
    return rval;
  }

  public static validContact(contact: WardenContact): boolean {
    let rval: boolean = false;
    if (contact?.type && StringRatchet.trimToNull(contact?.value)) {
      switch (contact.type) {
        case WardenContactType.EmailAddress:
          rval = WardenUtils.stringIsEmailAddress(contact.value);
          break;
        case WardenContactType.TextCapablePhoneNumber:
          rval = WardenUtils.stringIsPhoneNumber(contact.value);
          break;
        default:
          rval = false;
      }
    }

    return rval;
  }

  public static stringIsEmailAddress(value: string): boolean {
    return !!value.match(/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/);
  }

  public static stringIsPhoneNumber(value: string): boolean {
    return !!value.match(/^[\\+]?[(]?[0-9]{3}[)]?[-\\s\\.]?[0-9]{3}[-\\s\\.]?[0-9]{4,6}$/im);
  }

  public static stripWardenEntryToSummary(we: WardenEntry): WardenEntrySummary {
    const rval: WardenEntrySummary = we
      ? {
          userId: we.userId,
          userLabel: we.userLabel,
          contactMethods: we.contactMethods,
          webAuthnAuthenticatorIds: (we.webAuthnAuthenticators || []).map((s) => s.credentialIdBase64),
        }
      : null;
    return rval;
  }
}
