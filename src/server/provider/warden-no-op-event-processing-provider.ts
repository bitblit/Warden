/**
 * Default implementation of the event processing provider - does nothing
 */
import { WardenEntry } from '../../common/model/warden-entry';
import { WardenEventProcessingProvider } from './warden-event-processing-provider';

export class WardenNoOpEventProcessingProvider implements WardenEventProcessingProvider {
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  public async userCreated(entry: WardenEntry): Promise<void> {}
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  public async userRemoved(entry: WardenEntry): Promise<void> {}
}
