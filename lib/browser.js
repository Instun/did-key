/**
 * Browser-compatible DID key management and credential operations
 * Supports:
 * - Key generation and management
 * - Credential issuance and verification
 * - Selective disclosure
 * - Presentations
 */

import * as vc from './vc/index.js';

import * as suites from './suites.js'
import * as defaultContexts from "./contexts/index.js";

export const contexts = defaultContexts.contexts;

/**
 * Generate a new key pair of the specified type
 * Supported types: P-256, P-384, P-521, Ed25519, SM2, Bls12381
 * 
 * @param {string} type Key type 
 * @returns {Promise<Object>} Key pair with:
 *   - id: DID URI
 *   - controller: Same as id
 *   - publicKeyMultibase: Encoded public key
 *   - secretKeyMultibase: Encoded private key
 * @throws {Error} If key type is not supported
 */
export async function generate(type) {
    const generater = suites.generaters[type];
    if (!generater) {
        const error_message = 'Unsupported key type: ' + type + ', supported types are: ' + Object.keys(suites.generaters).join(', ');
        throw new Error(error_message);
    }

    const keyPair = await generater();

    var did = `did:key:${keyPair.publicKeyMultibase}`;
    keyPair.id = did;
    keyPair.controller = did;

    return await keyPair.export({
        includeContext: true,
        publicKey: true,
        secretKey: true
    });
}

/**
 * Sign raw data using a key pair
 * @param {Object} options Signing options
 * @param {Buffer} options.data Data to sign
 * @param {Object|string} options.key Signer's key pair or DID
 * @returns {Promise<Buffer>} Generated signature
 */
export async function sign(options) {
    const keyPair = await suites.getKeyPair(options.key);
    return await keyPair.signer().sign(options);
}

/**
 * Verify a signature against raw data
 * @param {Object} options Verification options
 * @param {Buffer} options.data Original data
 * @param {Buffer} options.signature Signature to verify
 * @param {Object|string} options.key Verifier's key pair or DID
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verify(options) {
    const keyPair = await suites.getKeyPair(options.key);
    return await keyPair.verifier().verify(options);
}

/**
 * Custom document loader for JSON-LD contexts and DIDs
 * Supports:
 * - Built-in contexts from memory
 * - DID resolution for did:key method
 * - Remote context loading via fetch
 * 
 * @param {string} url Context URL or DID to resolve
 * @returns {Promise<Object>} Resolved document
 * @throws {Error} If resolution fails
 */
export async function documentLoader(url) {
    if (contexts[url])
        return { document: contexts[url] };

    if (url && url.startsWith("did:key:")) {
        const { didAuthority, keyIdFragment, publicKeyMultibase } = suites.parseDid(url);

        const keyPair = await suites.fromMultibase({ publicKeyMultibase });
        const key = await keyPair.export({
            includeContext: true,
            publicKey: true
        });

        const contexts = ['https://www.w3.org/ns/did/v1'];

        if (typeof key['@context'] === 'string')
            contexts.push(key['@context']);
        else if (Array.isArray(key['@context']))
            contexts.push(...key['@context']);

        return {
            document: {
                '@context': contexts,
                id: didAuthority,
                controller: didAuthority,
                publicKeyMultibase,
                assertionMethod: [didAuthority],
                authentication: [didAuthority]
            }
        };
    }

    try {
        const response = await fetch(url);
        if (!response.ok)
            throw new Error(`Network response was not ok: ${response.statusText}`);

        const document = contexts[url] = await response.json();
        return { document };
    } catch (error) {
        const message = "Cannot resolve DID document for: " + url + ". Error: " + error.message;
        throw new Error(message);
    }
}

/**
 * Issue a verifiable credential
 * Supports selective disclosure if enabled and key type allows
 * 
 * @param {Object} options Credential options
 * @param {Object} options.credential Credential to issue
 * @param {Object} options.key Issuer's key pair
 * @param {boolean} options.useSelectiveDisclosure Enable selective disclosure
 * @param {Function} options.documentLoader Custom document loader
 * @returns {Promise<Object>} Verifiable credential with proof
 */
export async function issueCredential(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    if (!_options.suite && _options.key)
        _options.suite = await suites.signer_suite(_options);

    _options.credential.issuer = _options.suite.verificationMethod;

    return await vc.issue(_options);
}

/**
 * Verify a credential's authenticity and validity
 * @param {Object} options Verification options
 * @param {Object} options.credential Credential to verify
 * @param {Object|string} options.verificationMethod Optional. Verification method (full key or DID)
 * @param {Function} options.documentLoader Optional. Custom document loader
 * @returns {Promise<Object>} Verification results with status and details
 */
export async function verifyCredential(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    return await vc.verifyCredential(_options);
}

/**
 * Derive a new credential with selective disclosure
 * @param {Object} options Derivation options
 * @param {Object} options.verifiableCredential Original credential
 * @param {string[]} options.selectivePointers Paths to include
 * @param {Buffer} options.presentationHeader Optional. Additional context
 * @param {Function} options.documentLoader Optional. Custom document loader
 * @returns {Promise<Object>} Derived credential
 */
export async function deriveCredential(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    if (!_options.suite)
        _options.suite = suites.derive_suite(_options);

    return await vc.derive(_options);
}

/**
 * Generate random challenge string for presentations
 * @param {number} length Length of challenge string
 * @returns {string} Random challenge string
 */
function generateRandomString(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let randomString = '';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);

    for (let i = 0; i < length; i++) {
        randomString += charset[array[i] % charset.length];
    }

    return randomString;
}

/**
 * Sign a presentation containing credentials
 * @param {Object} options Presentation options
 * @param {Object} options.credential Optional. Credential to include
 * @param {Object} options.presentation Optional. Existing presentation
 * @param {Object} options.key Holder's key pair
 * @param {string} options.challenge Optional. Presentation challenge
 * @param {Function} options.documentLoader Optional. Custom document loader
 * @returns {Promise<Object>} Signed verifiable presentation
 */
export async function signPresentation(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    if (!_options.presentation && _options.credential)
        _options.presentation = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2"
            ],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": _options.credential
        };

    if (!_options.suite && _options.key)
        _options.suite = await suites.signer_suite(_options);

    if (!_options.challenge)
        _options.challenge = generateRandomString(32);

    return await vc.signPresentation(_options);
}

/**
 * Verify a presentation and its contained credentials
 * @param {Object} options Verification options
 * @param {Object} options.presentation Presentation to verify
 * @param {string} options.challenge Optional. Expected challenge
 * @param {Object|string} options.presentationVerificationMethod Optional. Holder's verification method
 * @param {Object|string} options.credentialVerificationMethod Optional. Issuer's verification method
 * @param {Function} options.documentLoader Optional. Custom document loader
 * @returns {Promise<Object>} Verification results including:
 *   - verified: Overall verification status
 *   - credentialResults: Results for each credential
 *   - presentationResult: Presentation verification details
 */
export async function verifyPresentation(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    const presentation = _options.presentation;

    if (!_options.challenge)
        _options.challenge = presentation.proof.challenge;

    return await vc.verify(_options);
}
