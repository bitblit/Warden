import { WardenStorageProvider } from './provider/warden-storage-provider';
import { JestRatchet } from '@bitblit/ratchet/jest';
import { WardenService } from './warden-service';
import { WardenServiceOptions } from './warden-service-options';
import { WardenContactType } from '../common/model/warden-contact-type';
import { WardenMessageSendingProvider } from './provider/warden-message-sending-provider';
import { WardenEntry } from '../common/model/warden-entry';
import { ExpiringCodeProvider } from '@bitblit/ratchet/aws';
import { JwtRatchetLike } from '@bitblit/ratchet/common';
import { WardenUserDecorationProvider } from './provider/warden-user-decoration-provider';
import { WardenEventProcessingProvider } from './provider/warden-event-processing-provider';

let mockJwtRatchet: jest.Mocked<JwtRatchetLike>;
let mockWardenStorageProvider: jest.Mocked<WardenStorageProvider>;
let mockExpiringCodeProvider: jest.Mocked<ExpiringCodeProvider>;
let mockWardenEmailSender: jest.Mocked<WardenMessageSendingProvider<any>>;

describe('#WardenService', () => {
  beforeEach(() => {
    mockJwtRatchet = JestRatchet.mock<JwtRatchetLike>();
    mockWardenStorageProvider = JestRatchet.mock<WardenStorageProvider>();
    mockWardenEmailSender = JestRatchet.mock<WardenMessageSendingProvider<any>>();
    mockExpiringCodeProvider = JestRatchet.mock<ExpiringCodeProvider>();
  });

  it('Should create account', async () => {
    const opts: WardenServiceOptions = {
      // Human-readable title for your website
      relyingPartyName: 'rp',
      allowedOrigins: ['origin'],

      storageProvider: mockWardenStorageProvider,
      messageSendingProviders: [mockWardenEmailSender],
      expiringCodeProvider: mockExpiringCodeProvider,
      jwtRatchet: mockJwtRatchet,
      userDecorationProvider: undefined,
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
