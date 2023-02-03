/**
 * The user details gets jammed into the JWT token upon login.  If one is not provided,
 * the default only puts the WardenEntrySummary in there
 */
import { WardenEntry } from '../../common/model/warden-entry';
import { WardenEntrySummary } from '../../common/model/warden-entry-summary';
import { WardenUtils } from '../../common/util/warden-utils';
import { WardenUserTokenDataProvider } from './warden-user-token-data-provider';

export class WardenDefaultUserTokenDataProvider implements WardenUserTokenDataProvider<WardenEntrySummary> {
  public async fetchUserTokenData(wardenUser: WardenEntry): Promise<WardenEntrySummary> {
    return WardenUtils.stripWardenEntryToSummary(wardenUser);
  }
  // Default to 1 hour
  public async fetchUserTokenExpirationSeconds(wardenUser: WardenEntry): Promise<number> {
    return 3600;
  }

  public async fetchUserRoles(wardenUser: WardenEntry): Promise<string[]> {
    return ['USER'];
  }
}
