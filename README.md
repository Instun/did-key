# @instun/did-key

A comprehensive library for managing Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) in fibjs, Node.js, and browsers. This library supports multiple cryptographic suites and provides functionality for key generation, credential issuance, selective disclosure, and verification.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
  - [Key Management](#key-management)
  - [Verifiable Credentials](#verifiable-credentials)
  - [Selective Disclosure](#selective-disclosure)
  - [Verifiable Presentations](#verifiable-presentations)
- [Advanced Usage](#advanced-usage)
  - [Cross-Key Type Support](#cross-key-type-support)
  - [Custom Contexts](#custom-contexts)
  - [Raw Data Operations](#raw-data-operations)
  - [Synchronous API](#synchronous-api)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Multi-platform Support**: Works in fibjs, Node.js, and browsers
- **Multiple Cryptographic Suites**: 
  - ECDSA (P-256, P-384, P-521)
  - Ed25519
  - SM2 (Chinese National Standard)
  - BLS12-381 (for BBS+ signatures)
- **Verifiable Credentials**:
  - Standard VC issuance and verification
  - Selective Disclosure support
  - Verifiable Presentation creation and verification
- **Synchronous API**: Additional sync functions available in fibjs environment

## Installation

```bash
# For fibjs
fibjs --install @instun/did-key

# For Node.js
npm install @instun/did-key

# For Yarn users
yarn add @instun/did-key
```

## Quick Start

```javascript
import * as dkey from '@instun/did-key';

// 1. Generate a key pair
const key = await dkey.generate('P-256');

// 2. Create a credential
const credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": ["VerifiableCredential"],
  "issuer": key.id,
  "issuanceDate": new Date().toISOString(),
  "credentialSubject": {
    "id": "did:example:123",
    "name": "John Doe"
  }
};

// 3. Issue the credential
const verifiableCredential = await dkey.issueCredential({
  credential,
  key
});

// 4. Verify the credential
const result = await dkey.verifyCredential({
  credential: verifiableCredential
});

console.log(result.verified); // true

// You can also verify using just the DID ID
const resultWithDID = await dkey.verifyCredential({
  credential: verifiableCredential,
  verificationMethod: key.id  // Using DID ID
});

console.log(resultWithDID.verified); // true
```

## Core Concepts

### Key Management

#### Supported Key Types
- `P-256` - ECDSA with NIST P-256 curve
- `P-384` - ECDSA with NIST P-384 curve
- `P-521` - ECDSA with NIST P-521 curve
- `Ed25519` - EdDSA with Curve25519
- `SM2` - Chinese National Standard
- `Bls12381` - BLS12-381 for BBS+ signatures

#### Key Generation

```javascript
// Generate different types of keys
const p256Key = await dkey.generate('P-256');
const edKey = await dkey.generate('Ed25519');
const sm2Key = await dkey.generate('SM2');
const blsKey = await dkey.generate('Bls12381');

// Key structure
console.log(p256Key);
// {
//   id: "did:key:zDn....",           // DID identifier
//   controller: "did:key:zDn....",    // Same as id
//   publicKeyMultibase: "zDn....",    // Public key in multibase format
//   secretKeyMultibase: "z42....",    // Private key in multibase format
// }
```

### Verifiable Credentials

#### Standard Credential Issuance

```javascript
const issuerKey = await dkey.generate('P-256');

const credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": ["VerifiableCredential"],
  "issuer": issuerKey.id,
  "issuanceDate": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:123",
    "name": "John Doe"
  }
};

const verifiableCredential = await dkey.issueCredential({
  credential,
  key: issuerKey
});
```

#### Credential Verification

```javascript
const result = await dkey.verifyCredential({
  credential: verifiableCredential
});

// Detailed verification results
const detailedResult = await dkey.verifyCredential({
  credential: verifiableCredential
});
// Result includes:
// - verified: boolean
// - results: Array of verification details including verificationMethod

// You can also verify using just the DID ID
const resultWithDID = await dkey.verifyCredential({
  credential: verifiableCredential,
  verificationMethod: issuerKey.id  // Using DID ID
});
```

### Selective Disclosure

```javascript
// Issue with selective disclosure support
const verifiableCredential = await dkey.issueCredential({
  credential,
  key: issuerKey,
  mandatoryPointers: [
    '/issuanceDate',
    '/issuer'
  ]
});

// Derive with specific attributes
const derivedCredential = await dkey.deriveCredential({
  verifiableCredential,
  selectivePointers: [
    '/credentialSubject/name'
  ]
});

// With presentation header
const derivedWithHeader = await dkey.deriveCredential({
  verifiableCredential,
  presentationHeader: Buffer.from('custom-header'),
  selectivePointers: [
    '/credentialSubject/name'
  ]
});
```

Note: Selective Disclosure is supported with `P-256` and `Bls12381` key types.

### Verifiable Presentations

```javascript
// Create presentation
const holderKey = await dkey.generate('P-256');
const verifiablePresentation = await dkey.signPresentation({
  credential: verifiableCredential,
  key: holderKey
});

// Verify presentation
const result = await dkey.verifyPresentation({
  presentation: verifiablePresentation
});

// Detailed verification results
const presResult = await dkey.verifyPresentation({
  presentation: verifiablePresentation
});
// Result includes:
// - verified: boolean
// - credentialResults: Verification results for included credentials
// - presentationResult: Verification result for the presentation itself

// You can also verify using just the DID IDs
const resultWithDIDs = await dkey.verifyPresentation({
  presentation: verifiablePresentation,
  presentationVerificationMethod: holderKey.id,    // Holder's DID ID
  credentialVerificationMethod: issuerKey.id       // Issuer's DID ID
});
```

## Advanced Usage

### Cross-Key Type Support

```javascript
// Issue credential with P-256
const issuerKey = await dkey.generate('P-256');
const verifiableCredential = await dkey.issueCredential({
  credential,
  key: issuerKey
});

// Sign presentation with Ed25519
const holderKey = await dkey.generate('Ed25519');
const verifiablePresentation = await dkey.signPresentation({
  credential: verifiableCredential,
  key: holderKey
});
```

### Custom Contexts

```javascript
// Register custom context
dkey.contexts['https://instun.com/custom-context'] = {
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "custom_field": {
      "@id": "https://instun.com/vocab#custom_field",
      "@type": "@json"
    }
  }
};

// Use in credential
const credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://instun.com/custom-context"
  ],
  "type": ["VerifiableCredential"],
  "credentialSubject": {
    "custom_field": {
      "field1": "value1",
      "field2": 123
    }
  }
};
```

### Raw Data Operations

Work with raw cryptographic data:

```javascript
// Sign raw data
const signature = await dkey.sign({
  key,
  data: 'Hello, World!'
});

// Verify raw signature
// You can use either the full key object or just the DID ID
const verifiedWithKey = await dkey.verify({
  key,
  data: 'Hello, World!',
  signature
});

const verifiedWithDID = await dkey.verify({
  key: key.id,  // Using DID ID directly
  data: 'Hello, World!',
  signature
});
```

### Verification Methods

All verification operations support using either the full key object or just the DID ID:

```javascript
// 1. Verify credential using DID ID
const credentialResult = await dkey.verifyCredential({
  credential: verifiableCredential,
  verificationMethod: key.id  // Using DID ID
});

// 2. Verify presentation using DID IDs
const presentationResult = await dkey.verifyPresentation({
  presentation: verifiablePresentation,
  presentationVerificationMethod: holderKey.id,    // Holder's DID ID
  credentialVerificationMethod: issuerKey.id       // Issuer's DID ID
});

// 3. Verify raw signature using DID ID
const signatureResult = await dkey.verify({
  data: 'Hello, World!',
  signature,
  key: key.id  // Using DID ID
});
```

This feature simplifies verification operations by allowing you to use just the DID identifier instead of requiring the full key object. It's particularly useful when you have stored or received only the DID ID and don't have access to the complete key object.

### Synchronous API

Available in fibjs environment only:

```javascript
// Sync key generation
const key = dkey.generate_sync('P-256');

// Sync credential issuance
const verifiableCredential = dkey.issueCredential_sync({
  credential,
  key
});

// Sync raw data operations
const signature = dkey.sign_sync({
    data: Buffer.from('hello'),
    key
});

const isValid = dkey.verify_sync({
    data: Buffer.from('hello'),
    signature,
    key
});
```

## API Reference

### Key Management

#### generate(type)
Generate a new key pair of the specified type.

- **Parameters**
  - `type` {string} - Key type ('P-256'|'P-384'|'P-521'|'Ed25519'|'SM2'|'Bls12381')
- **Returns**
  - `Promise<object>` - Key pair object containing:
    - `id` {string} - DID identifier
    - `controller` {string} - Same as id
    - `publicKeyMultibase` {string} - Public key in multibase format
    - `secretKeyMultibase` {string} - Private key in multibase format

#### generate_sync(type) [fibjs only]
Synchronous version of `generate()`.

### Credential Operations

#### issueCredential(options)
Issue a verifiable credential.

- **Parameters**
  - `options` {object}
    - `credential` {object} - Credential to be issued
    - `key` {object} - Issuer's key pair
    - `mandatoryPointers` {string[]} - Optional. Paths that cannot be omitted in selective disclosure
- **Returns**
  - `Promise<object>` - Verifiable credential with proof

#### verifyCredential(options)
Verify a credential's authenticity and validity.

- **Parameters**
  - `options` {object}
    - `credential` {object} - Credential to verify
    - `verificationMethod` {object|string} - Optional. Verification method (full key object or DID ID)
    - `documentLoader` {Function} - Optional. Custom document loader
- **Returns**
  - `Promise<object>`
    - `verified` {boolean} - Verification result
    - `results` {Array} - Detailed verification results

### Selective Disclosure

#### deriveCredential(options)
Derive a new credential with selected fields.

- **Parameters**
  - `options` {object}
    - `verifiableCredential` {object} - Original credential
    - `selectivePointers` {string[]} - Paths to include
    - `presentationHeader` {Buffer} - Optional. Additional context
- **Returns**
  - `Promise<object>` - Derived credential

### Presentation Operations

#### signPresentation(options)
Create a verifiable presentation.

- **Parameters**
  - `options` {object}
    - `credential` {object} - Credential to include
    - `key` {object} - Holder's key pair
- **Returns**
  - `Promise<object>` - Signed presentation

#### verifyPresentation(options)
Verify a presentation.

- **Parameters**
  - `options` {object}
    - `presentation` {object} - Presentation to verify
    - `presentationVerificationMethod` {object|string} - Optional. Holder's verification method (full key object or DID ID)
    - `credentialVerificationMethod` {object|string} - Optional. Issuer's verification method (full key object or DID ID)
- **Returns**
  - `Promise<object>`
    - `verified` {boolean} - Overall verification result
    - `credentialResults` {Array} - Results for each credential
    - `presentationResult` {object} - Presentation verification details

### Raw Data Operations

#### sign(options)
Sign raw data.

- **Parameters**
  - `options` {object}
    - `data` {Buffer} - Data to sign
    - `key` {object} - Signer's key pair
- **Returns**
  - `Promise<Buffer>` - Signature

#### verify(options)
Verify raw data signature.

- **Parameters**
  - `options` {object}
    - `data` {Buffer} - Original data
    - `signature` {Buffer} - Signature to verify
    - `key` {object|string} - Verifier's key pair or DID ID
- **Returns**
  - `Promise<boolean>` - Verification result

### Context Management

#### contexts
Object for managing custom JSON-LD contexts.

- **Properties**
  - Custom context URLs mapped to their definitions

### Supported Cryptographic Suites

#### ECDSA Suites
- `ecdsa-2019`: Standard ECDSA signatures
  - Supported key types: P-256, P-384, P-521
  - Use cases: Standard credential issuance and verification

- `ecdsa-sd-2023`: ECDSA with selective disclosure
  - Supported key types: P-256
  - Features: Selective disclosure, mandatory fields

#### EdDSA Suite
- `eddsa-2022`: EdDSA signatures
  - Supported key type: Ed25519
  - Use cases: High-performance signing and verification

#### SM2 Suite
- `sm2-2023`: Chinese National Standard
  - Supported key type: SM2
  - Features: Compliance with Chinese standards

#### BBS+ Suite
- `bbs-2023`: BBS+ signatures
  - Supported key type: Bls12381
  - Features: Advanced selective disclosure, zero-knowledge proofs

### Synchronous API (fibjs only)

All async functions have synchronous versions with `_sync` suffix:
- `generate_sync()`
- `sign_sync()`
- `verify_sync()`
- `issueCredential_sync()`
- `verifyCredential_sync()`
- `deriveCredential_sync()`
- `signPresentation_sync()`
- `verifyPresentation_sync()`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT