@instun/did-key
=========

A module for generating DID keys and issuing Verifiable Credentials (VC), which can be utilized in fibjs, Node.js, and browsers.

## Install

To install from NPM:

```
fibjs --install @instun/did-key
```
## Usage
To use the functions provided in this module, import them as follows:
#### ES6 Import
```JavaScript
import * as dkey from '@instun/did-key';
```
#### CommonJS Require
```JavaScript
const dkey = require('@instun/did-key');
```

### Interface definition
The interfaces of basic functions in did-key are all async functions, and these functions are compatible in fibjs, Node.js, and browsers. In order to facilitate the usage in fibjs, when the module detects that the environment is fibjs, it will add a corresponding set of *_sync functions. 

### Generating a new public/secret key pair
To generate a new key pair, use the generate function. Here is an example of generating a key pair using the P-256 curve:
```JavaScript
import * as dkey from '@instun/did-key';

const key = await dkey.generate('P-256');
```
The algorithms that can be used to generate keys are: P-256, P-384, P-521, Ed25519, Bls12381
### Issuing a Verifiable Credential
To issue a Verifiable Credential, use the issueCredential function. Here is an example:
```JavaScript
import * as dkey from '@instun/did-key';

const issuer_key = await dkey.generate('P-256');

const verifiableCredential = await dkey.issueCredential({
    credential: demo_credential,
    key: issuer_key
});
```

### Issuing a Selective Disclosure Verifiable Credential
To issue a Selective Disclosure Verifiable Credential, you can specify mandatory pointers. Here is an example:
```JavaScript
import * as dkey from '@instun/did-key';

const issuer_key = await dkey.generate('P-256');

const verifiableCredential = await dkey.issueCredential({
    credential: demo_credential,
    key: issuer_key,
    mandatoryPointers: [
        '/issuanceDate',
        '/issuer'
    ]
});
```
You can also use a different key type, such as Bls12381:
```JavaScript
import * as dkey from '@instun/did-key';

const issuer_key = await dkey.generate('Bls12381');

const verifiableCredential = await dkey.issueCredential({
    credential: demo_credential,
    key: issuer_key,
    mandatoryPointers: [
        '/issuanceDate',
        '/issuer'
    ]
});
```
The supported algorithms for Selective Disclosure Verifiable Credential are: P-256, Bls12381.
When generating a Selective Disclosure Verifiable Credential, you can set mandatoryPointers to specify the required attributes. If the key algorithm is P-256 and mandatoryPointers are not specified, a regular Verifiable Credential will be issued.

### Deriving a Selective Disclosure Verifiable Credential
You can derive a Selective Disclosure Verifiable Credential by specifying selective pointers. Here is an example:
```JavaScript
const derivedCredential = await dkey.deriveCredential({
    verifiableCredential: verifiableCredential,
    selectivePointers: [
        '/credentialSubject/dog_name'
    ]
});
```
When deriving a Selective Disclosure Verifiable Credential, you need to set selectivePointers to specify which attributes will be included in the Selective Disclosure Verifiable Credential. 

### Verifying a Verifiable Credential
To verify a Verifiable Credential, use the following code:
```JavaScript
const result = await dkey.verifyCredential({
    credential: verifiableCredential
});
```
Please note that a regular Verifiable Credential can be verified directly. However, a Selective Disclosure Verifiable Credential issued directly cannot be verified directly. You need to call deriveCredential to derive a Verifiable Credential in order to verify it. 
verifyCredential only verifies the integrity of the Verifiable Credential itself, but does not verify its issuer. So after verifying the credential, you need to check the legitimacy of the issuer yourself. 

### Signing the Presentation
You can sign a presentation using the original or derived credential. Below are examples for both cases:
#### Signing with Original Credential
```JavaScript
import * as dkey from '@instun/did-key';

const holder_key = await dkey.generate('P-256');

const verifiablePresentation = await dkey.signPresentation({
    credential: verifiableCredential,
    key: holder_key
});
```
#### Signing with Derived Credential
```JavaScript
import * as dkey from '@instun/did-key';

const holder_key = await dkey.generate('P-256');

const verifiablePresentation = await dkey.signPresentation({
    credential: derivedCredential,
    key: holder_key
});
```
You can sign a Verifiable Presentation with a key that uses a different algorithm from the issue key of the Verifiable Credential. The verifyPresentation function will automatically load different encryption components to verify them separately according to different algorithms.
### Verifying a Verifiable Presentation
To verify a Verifiable Presentation, use the following code:
```JavaScript
const result = await dkey.verifyPresentation({
    presentation: verifiablePresentation
});
```
Like verifyCredential, verifyPresentation simply checks the integrity of the Verifiable Presentation and the Verifiable Credential it contains, without verifying the issuer's source. So after verifyPresentation, you need to verify the legitimacy of the issuer by yourself. 
## Conclusion
This documentation provides a comprehensive guide to issuing, deriving, verifying, and signing Selective Disclosure Verifiable Credentials using the @instun/did-key library. Ensure you follow the examples and adjust the parameters as needed for your specific use case.