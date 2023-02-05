/**
 * Classes implementing WardenMessageSendingProvider are able to
 * send expiring, single
 */

export interface WardenCommandExchangeProvider {
  sendCommand(cmdString: string): Promise<string>;
}
