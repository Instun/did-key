import { describe, it } from 'node:test';
import assert from 'assert';

import * as dkey from '../lib/node.js';
import demo_credential from './demo_credential.mjs';
import demo_context from './demo_context.mjs';

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
    'P-256', 'P-384', 'P-521', 'Ed25519', 'SM2'
];

const sd_types = [
    'P-256', 'Bls12381'
];

if (process.versions.fibjs)
    describe('did-key sync', () => {
        function _test(type) {
            describe(type, () => {
                it('generate', () => {
                    const key = dkey.generate_sync(type);

                    assert.ok('id' in key, 'key should have id property');
                    assert.equal(key.id, key.controller);
                    assert.ok('secretKeyMultibase' in key, 'key should have secretKeyMultibase property');
                    assert.ok('publicKeyMultibase' in key, 'key should have publicKeyMultibase property');
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
                    assert.ok(result.verified);

                    assert.ok(result.results[0].verified);
                    assert.equal(key.id, result.results[0].verificationMethod.id);
                });

                it('faked credential', () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = dkey.generate_sync(type);
                    const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                    verifiableCredential.credentialSubject.foo = 'foo';

                    const result = dkey.verifyCredential_sync({ credential: verifiableCredential });

                    assert.ok(!result.verified);
                    assert.ok(!result.results[0].verified);
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
                    assert.ok(result.verified);

                    assert.ok(result.credentialResults[0].results[0].verified);
                    assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                    assert.ok(result.presentationResult.results[0].verified);
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

                    assert.ok(!result.verified);

                    assert.ok(result.credentialResults[0].results[0].verified);
                    assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                    assert.ok(!result.presentationResult.results[0].verified);
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

                    assert.ok(!result.verified);
                    assert.ok(!result.credentialResults[0].results[0].verified);
                    assert.ok(!result.presentationResult.results[0].verified);
                });

                it('sign and verify data', () => {
                    const key = dkey.generate_sync(type);
                    const data = Buffer.from('hello');

                    const signature = dkey.sign_sync({
                        data,
                        key
                    });

                    const result = dkey.verify_sync({
                        data,
                        signature,
                        key
                    });

                    assert.ok(result);

                    // Test with wrong data
                    const wrongResult = dkey.verify_sync({
                        data: Buffer.from('wrong data'),
                        signature,
                        key
                    });

                    assert.ok(!wrongResult);
                });

                it('verify with did id', () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = dkey.generate_sync(type);
                    const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key });

                    // Verify using DID ID instead of full key
                    const result = dkey.verifyCredential_sync({
                        credential: verifiableCredential,
                        verificationMethod: key.id
                    });
                    assert.ok(result.verified);
                });

                it('raw signature verify with did id', () => {
                    const key = dkey.generate_sync(type);
                    const data = Buffer.from('hello');

                    const signature = dkey.sign_sync({
                        data,
                        key
                    });

                    // Verify using DID ID
                    const result = dkey.verify_sync({
                        data,
                        signature,
                        key: key.id
                    });
                    assert.ok(result);

                    // Should fail with wrong data
                    const wrongResult = dkey.verify_sync({
                        data: Buffer.from('wrong data'),
                        signature,
                        key: key.id
                    });
                    assert.ok(!wrongResult);
                });

                it('presentation verify with did id', () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const issuerKey = dkey.generate_sync(type);
                    const verifiableCredential = dkey.issueCredential_sync({ credential: _demo_credential, key: issuerKey });

                    const holderKey = dkey.generate_sync(type);
                    const verifiablePresentation = dkey.signPresentation_sync({
                        credential: verifiableCredential,
                        key: holderKey
                    });

                    // Verify presentation using DID IDs
                    const result = dkey.verifyPresentation_sync({
                        presentation: verifiablePresentation,
                        presentationVerificationMethod: holderKey.id,
                        credentialVerificationMethod: issuerKey.id
                    });
                    assert.ok(result.verified);
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
                    assert.ok(result.verified);

                    assert.ok(result.credentialResults[0].results[0].verified);
                    assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                    assert.ok(result.presentationResult.results[0].verified);
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
                        assert.ok(!('cat_name' in derivedCredential.credentialSubject), 'credentialSubject should not have cat_name property');
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
                        assert.ok(result.verified);

                        assert.ok(result.results[0].verified);
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
                        assert.ok(result.verified);

                        assert.ok(result.credentialResults[0].results[0].verified);
                        assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                        assert.ok(result.presentationResult.results[0].verified);
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


describe('did-key async', () => {
    function _test(type) {
        describe(type, () => {
            it('generate', async () => {
                const key = await dkey.generate(type);

                assert.ok('id' in key, 'key should have id property');
                assert.equal(key.id, key.controller);
                assert.ok('secretKeyMultibase' in key, 'key should have secretKeyMultibase property');
                assert.ok('publicKeyMultibase' in key, 'key should have publicKeyMultibase property');
            });

            it('issue credential', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                assert.equal(key.id, verifiableCredential.issuer);
                assert.equal(key.id, verifiableCredential.proof.verificationMethod);
                assert.equal(verifiableCredential.proof.proofPurpose, "assertionMethod");
            });

            it('verify credential', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                const result = await dkey.verifyCredential({ credential: verifiableCredential });
                assert.ok(result.verified);

                assert.ok(result.results[0].verified);
                assert.equal(key.id, result.results[0].verificationMethod.id);
            });

            it('faked credential', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                verifiableCredential.credentialSubject.foo = 'foo';

                const result = await dkey.verifyCredential({ credential: verifiableCredential });

                assert.ok(!result.verified);
                assert.ok(!result.results[0].verified);
            });

            it('issue presentation', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                const key1 = await dkey.generate(type);
                const verifiablePresentation = await dkey.signPresentation({
                    credential: verifiableCredential,
                    key: key1
                });

                assert.deepEqual(verifiablePresentation.verifiableCredential, verifiableCredential);

                assert.equal(key1.id, verifiablePresentation.proof.verificationMethod);
                assert.equal(verifiablePresentation.proof.proofPurpose, "authentication");
            });

            it('verify presentation', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                const key1 = await dkey.generate(type);
                const verifiablePresentation = await dkey.signPresentation({
                    credential: verifiableCredential,
                    key: key1
                });

                const result = await dkey.verifyPresentation({ presentation: verifiablePresentation });
                assert.ok(result.verified);

                assert.ok(result.credentialResults[0].results[0].verified);
                assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                assert.ok(result.presentationResult.results[0].verified);
                assert.equal(key1.id, result.presentationResult.results[0].verificationMethod.id);
            });

            it('faked presentation', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                const key1 = await dkey.generate(type);
                const verifiablePresentation = await dkey.signPresentation({
                    credential: verifiableCredential,
                    key: key1
                });
                verifiablePresentation.foo = 'foo';

                const result = await dkey.verifyPresentation({ presentation: verifiablePresentation });

                assert.ok(!result.verified);

                assert.ok(result.credentialResults[0].results[0].verified);
                assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                assert.ok(!result.presentationResult.results[0].verified);
            });

            it('faked credential in presentation', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                const key1 = await dkey.generate(type);
                const verifiablePresentation = await dkey.signPresentation({
                    credential: verifiableCredential,
                    key: key1
                });
                verifiablePresentation.verifiableCredential.foo = 'foo';

                const result = await dkey.verifyPresentation({ presentation: verifiablePresentation });

                assert.ok(!result.verified);
                assert.ok(!result.credentialResults[0].results[0].verified);
                assert.ok(!result.presentationResult.results[0].verified);
            });

            it('sign and verify data', async () => {
                const key = await dkey.generate(type);
                const data = Buffer.from('hello');

                const signature = await dkey.sign({
                    data,
                    key
                });

                const result = await dkey.verify({
                    data,
                    signature,
                    key
                });

                assert.ok(result);

                // Test with wrong data
                const wrongResult = await dkey.verify({
                    data: Buffer.from('wrong data'),
                    signature,
                    key
                });

                assert.ok(!wrongResult);
            });

            it('verify with did id', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                // Verify using DID ID instead of full key
                const result = await dkey.verifyCredential({
                    credential: verifiableCredential,
                    verificationMethod: key.id
                });
                assert.ok(result.verified);
            });

            it('raw signature verify with did id', async () => {
                const key = await dkey.generate(type);
                const data = Buffer.from('hello');

                const signature = await dkey.sign({
                    data,
                    key
                });

                // Verify using DID ID
                const result = await dkey.verify({
                    data,
                    signature,
                    key: key.id
                });
                assert.ok(result);

                // Should fail with wrong data
                const wrongResult = await dkey.verify({
                    data: Buffer.from('wrong data'),
                    signature,
                    key: key.id
                });
                assert.ok(!wrongResult);
            });

            it('presentation verify with did id', async () => {
                const _demo_credential = deepCopy(demo_credential);

                const issuerKey = await dkey.generate(type);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key: issuerKey });

                const holderKey = await dkey.generate(type);
                const verifiablePresentation = await dkey.signPresentation({
                    credential: verifiableCredential,
                    key: holderKey
                });

                // Verify presentation using DID IDs
                const result = await dkey.verifyPresentation({
                    presentation: verifiablePresentation,
                    presentationVerificationMethod: holderKey.id,
                    credentialVerificationMethod: issuerKey.id
                });
                assert.ok(result.verified);
            });
        });
    }

    types.forEach(_test);

    describe('issue presentation with different type of key', () => {
        function _test(type1, type2) {
            it(`presentation(${type2}) with credential(${type1})`, async () => {
                const _demo_credential = deepCopy(demo_credential);

                const key = await dkey.generate(type1);
                const verifiableCredential = await dkey.issueCredential({ credential: _demo_credential, key });

                const key1 = await dkey.generate(type2);
                const verifiablePresentation = await dkey.signPresentation({
                    credential: verifiableCredential,
                    key: key1
                });

                const result = await dkey.verifyPresentation({ presentation: verifiablePresentation });
                assert.ok(result.verified);

                assert.ok(result.credentialResults[0].results[0].verified);
                assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                assert.ok(result.presentationResult.results[0].verified);
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
                it('issue credential', async () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = await dkey.generate(type);
                    const verifiableCredential = await dkey.issueCredential({
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

                it('derive credential', async () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = await dkey.generate(type);
                    const verifiableCredential = await dkey.issueCredential({
                        credential: _demo_credential,
                        key,
                        mandatoryPointers: [
                            '/issuanceDate',
                            '/issuer'
                        ]
                    });

                    const derivedCredential = await dkey.deriveCredential({
                        verifiableCredential: verifiableCredential,
                        presentationHeader: Buffer.from('asdf'),
                        selectivePointers: [
                            '/credentialSubject/dog_name'
                        ]
                    });

                    assert.equal(derivedCredential.issuer, verifiableCredential.issuer);
                    assert.equal(derivedCredential.issuanceDate, verifiableCredential.issuanceDate);

                    assert.deepEqual(verifiableCredential.credentialSubject.doc_name, _demo_credential.credentialSubject.doc_name);
                    assert.ok(!('cat_name' in derivedCredential.credentialSubject), 'credentialSubject should not have cat_name property');
                });

                it('verify credential', async () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = await dkey.generate(type);
                    const verifiableCredential = await dkey.issueCredential({
                        credential: _demo_credential,
                        key,
                        mandatoryPointers: [
                            '/issuanceDate',
                            '/issuer'
                        ]
                    });

                    const derivedCredential = await dkey.deriveCredential({
                        verifiableCredential: verifiableCredential,
                        presentationHeader: Buffer.from('asdf'),
                        selectivePointers: [
                            '/credentialSubject/dog_name'
                        ]
                    });

                    const result = await dkey.verifyCredential({ credential: derivedCredential });
                    assert.ok(result.verified);

                    assert.ok(result.results[0].verified);
                    assert.equal(key.id, result.results[0].verificationMethod.id);
                });
            });
        }

        sd_types.forEach(_test);

        describe('issue presentation with different type of key', () => {
            function _test(type1, type2) {
                it(`presentation(${type2}) with credential(${type1})`, async () => {
                    const _demo_credential = deepCopy(demo_credential);

                    const key = await dkey.generate(type1);
                    const verifiableCredential = await dkey.issueCredential({
                        credential: _demo_credential,
                        key,
                        mandatoryPointers: [
                            '/issuanceDate',
                            '/issuer'
                        ]
                    });

                    const derivedCredential = await dkey.deriveCredential({
                        verifiableCredential: verifiableCredential,
                        presentationHeader: Buffer.from('asdf'),
                        selectivePointers: [
                            '/credentialSubject/dog_name'
                        ]
                    });

                    const key1 = await dkey.generate(type2);
                    const verifiablePresentation = await dkey.signPresentation({
                        credential: derivedCredential,
                        key: key1
                    });

                    const result = await dkey.verifyPresentation({ presentation: verifiablePresentation });
                    assert.ok(result.verified);

                    assert.ok(result.credentialResults[0].results[0].verified);
                    assert.equal(key.id, result.credentialResults[0].results[0].verificationMethod.id);

                    assert.ok(result.presentationResult.results[0].verified);
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
