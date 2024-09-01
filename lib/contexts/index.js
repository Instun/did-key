import did_v1 from './did-v1.json' with { type: "json" };
import credentials_v1 from './credentials-v1.json' with { type: "json" };
import data_integrity_v2 from './data-integrity-v2.json' with { type: "json" };
import multikey_v1 from './multikey-v1.json' with { type: "json" };

export const contexts = {
  "https://www.w3.org/ns/did/v1": did_v1,
  "https://www.w3.org/2018/credentials/v1": credentials_v1,
  "https://w3id.org/security/data-integrity/v2": data_integrity_v2,
  "https://w3id.org/security/multikey/v1": multikey_v1,
};
