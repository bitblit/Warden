import { WardenLoggedInUserProvider } from './warden-logged-in-user-provider';
import { WardenClient } from '../warden-client';
import { WardenUserServiceEventProcessingProvider } from './warden-user-service-event-processing-provider';

export interface WardenUserServiceOptions<T> {
  loggedInUserProvider: WardenLoggedInUserProvider<T>;
  wardenClient: WardenClient;
  eventProcessor: WardenUserServiceEventProcessingProvider<T>;
  loginCheckTimerPingSeconds?: number;
  autoLoginHandlingThresholdSeconds?: number;
  allowAutoRefresh?: boolean;
}
