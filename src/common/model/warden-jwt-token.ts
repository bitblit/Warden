import { CommonJwtToken } from '@bitblit/ratchet/common';

export interface WardenJwtToken<T> extends CommonJwtToken<T> {
  userId: string;
}
