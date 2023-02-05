import { WardenContact } from '../../common/model/warden-contact';

export interface WardenRecentLoginDescriptor {
  userId: string;
  lastLoginEpochMS: number;
  contacts: WardenContact[];
  webAuthn: boolean;
}
