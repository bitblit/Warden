import { WardenEntrySummary, WardenJwtToken } from '../../common';

export interface WardenLoggedInUserWrapper<T> {
  userObject: WardenJwtToken<T>;
  jwtToken: string;
  expirationEpochSeconds: number;
}
