//    Service for interacting with positions for a given user
import { WardenMessageSendingProvider } from './warden-message-sending-provider';
import { WardenContactType } from '../../common/model/warden-contact-type';
import { WardenContactEntry } from '../../common/model/warden-contact-entry';
import { WardenMailerMessageSendingProviderOptions } from './warden-mailer-message-sending-provider-options';
import { SendRawEmailResponse } from 'aws-sdk/clients/ses';
import { WardenCustomerMessageType } from '../../common/model/warden-customer-message-type';
import { Mailer, ReadyToSendEmail } from '@bitblit/ratchet/aws';
import { Logger } from '@bitblit/ratchet/common';

export class WardenMailerMessageSendingProvider implements WardenMessageSendingProvider<ReadyToSendEmail> {
  private static defaultOptions(): WardenMailerMessageSendingProviderOptions {
    const rval: WardenMailerMessageSendingProviderOptions = {
      emailBaseLayoutName: undefined,
      expiringTokenHtmlTemplateName: 'expiring-token-request-email',
      expiringTokenTxtTemplateName: undefined,
    };
    return rval;
  }

  constructor(
    private mailer: Mailer,
    private options: WardenMailerMessageSendingProviderOptions = WardenMailerMessageSendingProvider.defaultOptions()
  ) {}

  public async formatMessage(
    contact: WardenContactEntry,
    messageType: WardenCustomerMessageType,
    context: Record<string, any>
  ): Promise<ReadyToSendEmail> {
    const rts: ReadyToSendEmail = {
      destinationAddresses: [contact.value],
      subject: 'Your login token',
    };

    await this.mailer.fillEmailBody(
      rts,
      context,
      this.options.expiringTokenHtmlTemplateName,
      this.options.expiringTokenTxtTemplateName,
      this.options.emailBaseLayoutName
    );

    return rts;
  }

  handlesContactType(type: WardenContactType): boolean {
    return type === WardenContactType.EmailAddress;
  }

  public async sendMessage(contact: WardenContactEntry, message: ReadyToSendEmail): Promise<boolean> {
    const rval: SendRawEmailResponse = await this.mailer.sendEmail(message);
    Logger.debug('SendRawEmailResponse was : %j', rval);
    return !!rval;
  }
}
