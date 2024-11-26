import * as dkey from '../lib/node.js';

const key = await dkey.generate('P-256');
console.log(key);

const sig = await dkey.sign({
    data: Buffer.from('hello'),
    key
});

console.log(sig);

const result = await dkey.verify({
    data: Buffer.from('hello'),
    signature: sig,
    key: key.id
});

console.log(result);