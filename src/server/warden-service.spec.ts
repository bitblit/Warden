import { WardenStorageProvider } from './provider/warden-storage-provider';
import { JestRatchet } from '@bitblit/ratchet/jest';
import { WardenService } from './warden-service';
import { WardenServiceOptions } from './warden-service-options';
import { WardenContactType } from '../common/model/warden-contact-type';
import { WardenMessageSendingProvider } from './provider/warden-message-sending-provider';
import { WardenEntry } from '../common/model/warden-entry';
import { ExpiringCodeProvider } from '@bitblit/ratchet/aws';
import { JwtRatchetLike } from '@bitblit/ratchet/common';
import { WardenUserTokenDataProvider } from './provider/warden-user-token-data-provider';
import { WardenEventProcessingProvider } from './provider/warden-event-processing-provider';

let mockWardenStorageProvider: jest.Mocked<WardenStorageProvider>;
let mockWardenEmailSender: jest.Mocked<WardenMessageSendingProvider<any>>;

describe('#WardenService', () => {
  beforeEach(() => {
    mockWardenStorageProvider = JestRatchet.mock<WardenStorageProvider>();
    mockWardenEmailSender = JestRatchet.mock<WardenMessageSendingProvider<any>>();
  });

  it('Should create account', async () => {
    const opts: WardenServiceOptions = {
      // Human-readable title for your website
      relyingPartyName: 'rp',
      allowedOrigins: ['origin'],

      storageProvider: mockWardenStorageProvider,
      messageSendingProviders: [mockWardenEmailSender],
      expiringCodeProvider: undefined,
      jwtRatchet: undefined,
      userTokenDataProvider: undefined,
      eventProcessor: undefined,
    };

    const svc: WardenService = new WardenService(opts);

    mockWardenStorageProvider.findEntryByContact.mockResolvedValue(null);
    mockWardenStorageProvider.saveEntry.mockResolvedValue({ userId: 'test' } as WardenEntry);
    mockWardenEmailSender.handlesContactType.mockReturnValue(true);

    const res: string = await svc.createAccount({ type: WardenContactType.EmailAddress, value: 'test@test.com' }, false, 'Test', []);
    expect(res).toEqual('test');
  });
});
