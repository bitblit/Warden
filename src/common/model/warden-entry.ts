import { WardenWebAuthnEntry } from './warden-web-authn-entry';
import { WardenEntrySummary } from './warden-entry-summary';

export interface WardenEntry extends WardenEntrySummary {
  tags: string[];
  webAuthnAuthenticators: WardenWebAuthnEntry[];
  createdEpochMS: number;
  updatedEpochMS: number;
}
