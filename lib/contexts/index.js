import did_v1 from './did-v1.js';
import credentials_v1 from './credentials-v1.js';
import credentials_v2 from './credentials-v2.js';
import data_integrity_v2 from './data-integrity-v2.js';
import multikey_v1 from './multikey-v1.js';

export const contexts = {
  "https://www.w3.org/ns/did/v1": did_v1,
  "https://www.w3.org/2018/credentials/v1": credentials_v1,
  "https://www.w3.org/ns/credentials/v2": credentials_v2,
  "https://w3id.org/security/data-integrity/v2": data_integrity_v2,
  "https://w3id.org/security/multikey/v1": multikey_v1,
};