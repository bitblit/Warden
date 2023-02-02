import { WardenLoginRequest } from './warden-login-request';

export interface WardenLoginResults {
  request: WardenLoginRequest;
  jwtToken?: string;
  error?: string;
}
