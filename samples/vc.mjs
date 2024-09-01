import * as dkey from '../lib/node.js';
import demo_credential from '../test/demo_credential.json' with { type: 'json'};
import demo_context from '../test/demo_context.json' with { type: 'json'};

dkey.contexts['https://instun.com/custom-context'] = demo_context;

const key = await dkey.generate('P-256');
console.log(key);

const verifiableCredential = await dkey.issueCredential({
    credential: demo_credential,
    key
});

console.log(verifiableCredential);

const result = await dkey.verifyCredential({
    credential: verifiableCredential
});

console.dir(result, {
    depth: 10
});

const key1 = await dkey.generate('P-256');

const verifiablePresentation = await dkey.signPresentation({
    credential: verifiableCredential,
    key: key1
});

console.log(verifiablePresentation);

const result1 = await dkey.verifyPresentation({
    presentation: verifiablePresentation
});

console.dir(result1, {
    depth: 10
});
