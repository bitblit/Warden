/**
 * Classes implementing WardenMessageSendingProvider are able to
 * send expiring, single
 */

export interface WardenCommandSender {
  sendCommand(cmdString: string): Promise<string>
}
