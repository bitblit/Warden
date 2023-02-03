/**
 * The user details gets jammed into the JWT token upon login.  If one is not provided,
 * the default only puts the user id and label in there
 */
import { WardenEntry } from '../../common/model/warden-entry';

export interface WardenUserTokenDataProvider<T> {
  fetchUserTokenData(wardenUser: WardenEntry): Promise<T>;
  fetchUserTokenExpirationSeconds(wardenUser: WardenEntry): Promise<number>;
  fetchUserRoles(wardenUser: WardenEntry): Promise<string[]>;
}
