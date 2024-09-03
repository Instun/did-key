import * as crypto from 'crypto';
import * as bbs from '@digitalbazaar/bbs-signatures';

export var CIPHERSUITES = bbs.CIPHERSUITES;
export var generateKeyPair = bbs.generateKeyPair;
export var sign = bbs.sign;
export var deriveProof = bbs.deriveProof;
export var verifyProof = bbs.verifyProof;

if (process.versions.fibjs) {
    generateKeyPair = async function (options) {
        var keyPair = await crypto.promises.generateKeyPair('Bls12381G2', {
            publicKeyEncoding: { format: 'raw' },
            privateKeyEncoding: { format: 'raw' }
        });

        return {
            publicKey: keyPair.publicKey,
            secretKey: keyPair.privateKey
        };
    }

    sign = async function (options) {
        return await crypto.promises.bbsSign(options.messages, {
            key: options.secretKey,
            format: 'raw',
            namedCurve: 'Bls12381G2',
            header: options.header,
            suite: options.ciphersuite == 'BLS12-381-SHA-256' ? 'Bls12381Sha256' : 'Bls12381Shake256'
        });
    }

    deriveProof = async function (options) {
        return await crypto.promises.proofGen(
            options.signature,
            options.messages,
            options.disclosedMessageIndexes,
            {
                key: options.publicKey,
                format: 'raw',
                namedCurve: 'Bls12381G2',
                header: options.header,
                proof_header: options.presentationHeader,
                suite: options.ciphersuite == 'BLS12-381-SHA-256' ? 'Bls12381Sha256' : 'Bls12381Shake256'
            });
    }

    verifyProof = async function (options) {
        return await crypto.promises.proofVerify(
            options.disclosedMessages,
            options.disclosedMessageIndexes,
            {
                key: options.publicKey,
                format: 'raw',
                namedCurve: 'Bls12381G2',
                header: options.header,
                proof_header: options.presentationHeader,
                suite: options.ciphersuite == 'BLS12-381-SHA-256' ? 'Bls12381Sha256' : 'Bls12381Shake256'
            }, options.proof);
    }
}
