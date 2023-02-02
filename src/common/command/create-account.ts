import {WardenContactEntry} from "../model/warden-contact-entry";

export interface CreateAccount {
  contact: WardenContactEntry;
  sendCode?: boolean;
  label?: string;
  tags?: string[];
}
