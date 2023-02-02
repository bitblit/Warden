//    Service for interacting with positions for a given user
import { WardenMessageSendingProvider } from './warden-message-sending-provider';
import { WardenContactType } from '../../common/model/warden-contact-type';
import { WardenContactEntry } from '../../common/model/warden-contact-entry';
import { WardenTwilioTextMessageSendingProviderOptions } from './warden-twilio-text-message-sending-provider-options';
import { WardenCustomerMessageType } from '../../common/model/warden-customer-message-type';
import { Logger, TwilioRatchet } from '@bitblit/ratchet/common';

export class WardenTwilioTextMessageSendingProvider implements WardenMessageSendingProvider<string> {
  constructor(private optsPromise: Promise<WardenTwilioTextMessageSendingProviderOptions>) {}

  public async formatMessage(
    contact: WardenContactEntry,
    messageType: WardenCustomerMessageType,
    context: Record<string, any>
  ): Promise<string> {
    Logger.info('Creating text');
    // https://www.macrumors.com/2020/01/31/apple-standardized-format-sms-one-time-passcodes/
    const msg: string =
      context['code'] +
      ' is your ' +
      context['relyingPartyName'] +
      ' authentication code.\n@' +
      context['relyingPartyName'] + // should be domain name?
      ' #' +
      context['code'];
    return msg;
  }

  handlesContactType(type: WardenContactType): boolean {
    return type === WardenContactType.EmailAddress;
  }

  public async sendMessage(contact: WardenContactEntry, message: string): Promise<boolean> {
    const opts: WardenTwilioTextMessageSendingProviderOptions = await this.optsPromise;
    const rval: any[] = await TwilioRatchet.sendMessageDirect(
      opts.accountSID,
      opts.authToken,
      opts.outBoundNumber,
      [contact.value],
      message
    );
    Logger.debug('sendMessage was : %j', rval);
    return !!rval && rval.length > 0;
  }
}
