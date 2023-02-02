import {WardenStorageProvider} from "./provider/warden-storage-provider";
import {JestRatchet} from "@bitblit/ratchet/jest";
import {WardenService} from "./warden-service";
import {WardenServiceOptions} from "./model/warden-service-options";
import {WardenContactType} from "./model/warden-contact-type";
import {WardenMessageSendingProvider} from "./provider/warden-message-sending-provider";
import {WardenEntry} from "./model/warden-entry";

let mockWardenStorageProvider: jest.Mocked<WardenStorageProvider>;
let mockWardenEmailSender: jest.Mocked<WardenMessageSendingProvider<any>>;

describe('#WardenService', () => {
  beforeEach(() => {
    mockWardenStorageProvider = JestRatchet.mock<WardenStorageProvider>();
    mockWardenEmailSender = JestRatchet.mock<WardenMessageSendingProvider<any>>();
  });

  it('Should create account', async () => {
    const svc: WardenService = new WardenService({} as WardenServiceOptions, mockWardenStorageProvider, [mockWardenEmailSender], null);

    mockWardenStorageProvider.findEntryByContact.mockResolvedValue(null);
    mockWardenStorageProvider.saveEntry.mockResolvedValue({userId: 'test'} as WardenEntry);
    mockWardenEmailSender.handlesContactType.mockReturnValue(true);

    const res: string = await svc.createAccount({type: WardenContactType.EmailAddress, value:'test@test.com'}, false, 'Test', []);
    expect(res).toEqual('test')
  });

});
