import { WardenWebAuthnEntry } from './warden-web-authn-entry';
import { WardenContact } from './warden-contact';

export interface WardenEntry {
  userId: string;
  userLabel: string; // Usually full name, could be something else
  contactMethods: WardenContact[];
  tags: string[];
  webAuthnAuthenticators: WardenWebAuthnEntry[];
  createdEpochMS: number;
  updatedEpochMS: number;
}
