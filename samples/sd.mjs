import * as dkey from '../lib/node.js';
import demo_credential from '../test/demo_credential.cjs';
import demo_context from '../test/demo_context.cjs';

dkey.contexts['https://instun.com/custom-context'] = demo_context;

const key = await dkey.generate('Bls12381');
console.log(key);

const verifiableCredential = await dkey.issueCredential({
    credential: demo_credential,
    key,
    mandatoryPointers: [
        '/issuanceDate',
        '/issuer'
    ]
});

console.log(verifiableCredential);

const derivedCredential = await dkey.deriveCredential({
    verifiableCredential: verifiableCredential,
    presentationHeader: Buffer.from('asdf'),
    selectivePointers: [
        '/credentialSubject/dog_name'
    ]
});

console.log(derivedCredential);

const result = await dkey.verifyCredential({
    credential: derivedCredential
});

console.dir(result, {
    depth: 10
});

const key1 = await dkey.generate('P-256');

const verifiablePresentation = await dkey.signPresentation({
    credential: derivedCredential,
    key: key1
});

console.log(verifiablePresentation);

const result1 = await dkey.verifyPresentation({
    presentation: verifiablePresentation
});

console.dir(result1, {
    depth: 10
});
