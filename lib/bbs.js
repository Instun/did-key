/**
 * BBS+ Signature Implementation
 * Provides BBS+ signature operations with fallback to native implementation in fibjs
 * Supports:
 * - Key generation
 * - Signing
 * - Proof derivation
 * - Proof verification
 */

import * as crypto from 'crypto';
import * as bbs from '@digitalbazaar/bbs-signatures';

// Export original BBS+ implementation
export var CIPHERSUITES = bbs.CIPHERSUITES;
export var generateKeyPair = bbs.generateKeyPair;
export var sign = bbs.sign;
export var deriveProof = bbs.deriveProof;
export var verifyProof = bbs.verifyProof;

// Override with native implementations in fibjs environment
if (process.versions.fibjs) {
    /**
     * Generate BLS12-381 key pair using native crypto
     * @param {Object} options Generation options
     * @returns {Promise<Object>} Generated key pair
     *   - publicKey: Raw public key buffer
     *   - secretKey: Raw private key buffer
     */
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

    /**
     * Sign messages using BBS+ signatures
     * @param {Object} options Signing options
     * @param {Array} options.messages Messages to sign
     * @param {Buffer} options.secretKey Private key
     * @param {Buffer} options.header Optional header
     * @param {string} options.ciphersuite Ciphersuite name
     * @returns {Promise<Buffer>} Generated signature
     */
    sign = async function (options) {
        return await crypto.promises.bbsSign(options.messages, {
            key: options.secretKey,
            format: 'raw',
            namedCurve: 'Bls12381G2',
            header: options.header,
            suite: options.ciphersuite == 'BLS12-381-SHA-256' ? 'Bls12381Sha256' : 'Bls12381Shake256'
        });
    }

    /**
     * Derive selective disclosure proof
     * @param {Object} options Proof options
     * @param {Buffer} options.signature Original signature
     * @param {Array} options.messages Original messages
     * @param {Array} options.disclosedMessageIndexes Indices to reveal
     * @param {Buffer} options.publicKey Public key
     * @param {Buffer} options.header Optional signature header
     * @param {Buffer} options.presentationHeader Optional proof header
     * @param {string} options.ciphersuite Ciphersuite name
     * @returns {Promise<Buffer>} Generated proof
     */
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

    /**
     * Verify selective disclosure proof
     * @param {Object} options Verification options
     * @param {Array} options.disclosedMessages Revealed messages
     * @param {Array} options.disclosedMessageIndexes Indices of revealed messages
     * @param {Buffer} options.publicKey Public key
     * @param {Buffer} options.header Optional signature header
     * @param {Buffer} options.presentationHeader Optional proof header
     * @param {string} options.ciphersuite Ciphersuite name
     * @param {Buffer} options.proof Proof to verify
     * @returns {Promise<boolean>} Verification result
     */
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
