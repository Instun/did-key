const test = require('test');
test.setup();

const dkey = require('..');

const demo_credential = require('./demo_credential.json');
const demo_context = require('./demo_context.json');

dkey.contexts['https://instun.com/custom-context'] = demo_context;

function deepCopy(obj) {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }

    if (obj instanceof Date) {
        return new Date(obj);
    }

    const copy = Array.isArray(obj) ? [] : {};

    for (const key in obj)
        if (obj.hasOwnProperty(key))
            copy[key] = deepCopy(obj[key]);

    return copy;
}

const types = [
    'P-256', 'P-384', 'P-521', 'Ed25519'
];

const sd_types = [
    'P-256', 'Bls12381'
];

describe('did-key', () => {
    function _test(type) {
        describe(type, () => {
            it('generate', () => {
                const key = dkey.generate_sync(type);

                assert.property(key, 'id');
                assert.equal(key.id, key.controller);
                assert.property(key, 'secretKeyMultibase');
                assert.property(key, 'publicKeyMultibase');
            });

            it('issue credential', () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = dkey.generate_sync(type);
                const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                assert.equal(key.id, verifiableCredential.issuer);
                assert.equal(key.id, verifiableCredential.proof.verificationMethod);
                assert.equal(verifiableCredential.proof.proofPurpose, "assertionMethod");
            });

            it('verify credential', () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = dkey.generate_sync(type);
                const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                const result = dkey.verifyCredential_sync({ credential: verifiableCredential });
                assert.isTrue(result.verified);

                assert.isTrue(result.results[0].verified);
                assert.equal(key.id, result.results[0].verificationMethod.id);
            });

            it('faked credential', () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = dkey.generate_sync(type);
                const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                verifiableCredential.credentialSubject.foo = 'foo';

                const result = dkey.verifyCredential_sync({ credential: verifiableCredential });

                assert.isFalse(result.verified);
                assert.isFalse(result.results[0].verified);
            });

            it('issue presentation', () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = dkey.generate_sync(type);
                const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                const key1 = dkey.generate_sync(type);
                const verifiablePresentation = dkey.signPresentation_sync({
                    credential: verifiableCredential,
                    key: key1
                });

                assert.deepEqual(verifiablePresentation.verifiableCredential, verifiableCredential);

                assert.equal(key1.id, verifiablePresentation.proof.verificationMethod);
                assert.equal(verifiablePresentation.proof.proofPurpose, "authentication");
            });

            it('verify presentation', () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = dkey.generate_sync(type);
                const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                const key1 = dkey.generate_sync(type);
                const verifiablePresentation = dkey.signPresentation_sync({
                    credential: verifiableCredential,
                    key: key1
                });

                const result = dkey.verifyPresentation_sync({ presentation: verifiablePresentation });
                assert.isTrue(result.verified);

                assert.isTrue(result.credentialResults[0].results[0].verified);
                assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                assert.isTrue(result.presentationResult.results[0].verified);
                assert.equal(key1.id, result.presentationResult.results[0].verificationMethod.id);
            });

            it('faked presentation', () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = dkey.generate_sync(type);
                const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                const key1 = dkey.generate_sync(type);
                const verifiablePresentation = dkey.signPresentation_sync({
                    credential: verifiableCredential,
                    key: key1
                });
                verifiablePresentation.foo = 'foo';

                const result = dkey.verifyPresentation_sync({ presentation: verifiablePresentation });

                assert.isFalse(result.verified);

                assert.isTrue(result.credentialResults[0].results[0].verified);
                assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                assert.isFalse(result.presentationResult.results[0].verified);
            });

            it('faked credential in presentation', () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = dkey.generate_sync(type);
                const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                const key1 = dkey.generate_sync(type);
                const verifiablePresentation = dkey.signPresentation_sync({
                    credential: verifiableCredential,
                    key: key1
                });
                verifiablePresentation.verifiableCredential.foo = 'foo';

                const result = dkey.verifyPresentation_sync({ presentation: verifiablePresentation });

                assert.isFalse(result.verified);
                assert.isFalse(result.credentialResults[0].results[0].verified);
                assert.isFalse(result.presentationResult.results[0].verified);
            });
        });
    }

    types.forEach(_test);

    describe('issue presentation with different type of key', () => {
        function _test(type1, type2) {
            it(`presentation(${type2}) with credential(${type1})`, () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = dkey.generate_sync(type1);
                const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                const key1 = dkey.generate_sync(type2);
                const verifiablePresentation = dkey.signPresentation_sync({
                    credential: verifiableCredential,
                    key: key1
                });

                const result = dkey.verifyPresentation_sync({ presentation: verifiablePresentation });
                assert.isTrue(result.verified);

                assert.isTrue(result.credentialResults[0].results[0].verified);
                assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                assert.isTrue(result.presentationResult.results[0].verified);
                assert.equal(key1.id, result.presentationResult.results[0].verificationMethod.id);
            });
        }

        types.forEach(type1 => {
            types.forEach(type2 => {
                _test(type1, type2);
            });
        });
    });

    describe('Selective Disclosure Verifiable Credential', () => {
        function _test(type) {
            describe(type, () => {
                it('issue credential', () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = dkey.generate_sync(type);
                    const verifiableCredential = dkey.issueCredential_sync({
                        credential: _demo_credential,
                        key,
                        mandatoryPointers: [
                            '/issuanceDate',
                            '/issuer'
                        ]
                    });

                    assert.equal(key.id, verifiableCredential.issuer);
                    assert.equal(key.id, verifiableCredential.proof.verificationMethod);
                    assert.equal(verifiableCredential.proof.proofPurpose, "assertionMethod");

                    assert.deepEqual(verifiableCredential.credentialSubject, _demo_credential.credentialSubject);
                });

                it('derive credential', () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = dkey.generate_sync(type);
                    const verifiableCredential = dkey.issueCredential_sync({
                        credential: _demo_credential,
                        key,
                        mandatoryPointers: [
                            '/issuanceDate',
                            '/issuer'
                        ]
                    });

                    const derivedCredential = dkey.deriveCredential_sync({
                        verifiableCredential: verifiableCredential,
                        presentationHeader: Buffer.from('asdf'),
                        selectivePointers: [
                            '/credentialSubject/dog_name'
                        ]
                    });

                    assert.equal(derivedCredential.issuer, verifiableCredential.issuer);
                    assert.equal(derivedCredential.issuanceDate, verifiableCredential.issuanceDate);

                    assert.deepEqual(verifiableCredential.credentialSubject.doc_name, _demo_credential.credentialSubject.doc_name);
                    assert.notProperty(derivedCredential.credentialSubject, 'cat_name');
                });

                it('verify credential', () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = dkey.generate_sync(type);
                    const verifiableCredential = dkey.issueCredential_sync({
                        credential: _demo_credential,
                        key,
                        mandatoryPointers: [
                            '/issuanceDate',
                            '/issuer'
                        ]
                    });

                    const derivedCredential = dkey.deriveCredential_sync({
                        verifiableCredential: verifiableCredential,
                        presentationHeader: Buffer.from('asdf'),
                        selectivePointers: [
                            '/credentialSubject/dog_name'
                        ]
                    });

                    const result = dkey.verifyCredential_sync({ credential: derivedCredential });
                    assert.isTrue(result.verified);

                    assert.isTrue(result.results[0].verified);
                    assert.equal(key.id, result.results[0].verificationMethod.id);
                });
            });
        }

        sd_types.forEach(_test);

        describe('issue presentation with different type of key', () => {
            function _test(type1, type2) {
                it(`presentation(${type2}) with credential(${type1})`, () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = dkey.generate_sync(type1);
                    const verifiableCredential = dkey.issueCredential_sync({
                        credential: _demo_credential,
                        key,
                        mandatoryPointers: [
                            '/issuanceDate',
                            '/issuer'
                        ]
                    });

                    const derivedCredential = dkey.deriveCredential_sync({
                        verifiableCredential: verifiableCredential,
                        presentationHeader: Buffer.from('asdf'),
                        selectivePointers: [
                            '/credentialSubject/dog_name'
                        ]
                    });

                    const key1 = dkey.generate_sync(type2);
                    const verifiablePresentation = dkey.signPresentation_sync({
                        credential: derivedCredential,
                        key: key1
                    });

                    const result = dkey.verifyPresentation_sync({ presentation: verifiablePresentation });
                    assert.isTrue(result.verified);

                    assert.isTrue(result.credentialResults[0].results[0].verified);
                    assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                    assert.isTrue(result.presentationResult.results[0].verified);
                    assert.equal(key1.id, result.presentationResult.results[0].verificationMethod.id);
                });
            }

            sd_types.forEach(type1 => {
                types.forEach(type2 => {
                    _test(type1, type2);
                });
            });
        });
    });
});

test.run(console.DEBUG);
