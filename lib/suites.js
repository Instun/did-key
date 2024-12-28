import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import { cryptosuite as ecdsa2019Cryptosuite } from '@digitalbazaar/ecdsa-2019-cryptosuite';
import * as ecdsaSd2023Cryptosuite from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';

import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import { cryptosuite as eddsa2022CryptoSuite } from '@digitalbazaar/eddsa-2022-cryptosuite';

import { SM2Multikey } from '@instun/sm2-multikey';
import { cryptosuite as sm2Cryptosuite } from '@instun/sm2-2023-cryptosuite';
import * as sm2Sd2023Cryptosuite from '@instun/sm2-sd-2023-cryptosuite';

import * as bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as bbs2023Cryptosuite from '@digitalbazaar/bbs-2023-cryptosuite';

import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';

/**
 * Suite management and cryptographic operations for different key types
 * Key prefixes:
 * - zDn: ECDSA P-256
 * - z82: ECDSA P-384 
 * - z2J: ECDSA P-521
 * - zEP: SM2
 * - z6M: Ed25519
 * - zUC: BLS12-381
 */

/**
 * Creates an ECDSA cryptosuite with optional selective disclosure support
 * Only P-256 supports selective disclosure through ecdsa-sd-2023
 * Other ECDSA curves use standard ecdsa-2019
 * 
 * @param {Object} options Configuration options
 * @param {boolean} options.useSelectiveDisclosure Enable selective disclosure
 * @param {Object} options.key Key pair object
 * @returns {Object} Cryptosuite instance
 */
function ecdsa_createCryptosuite(options) {
    if (options.useSelectiveDisclosure) {
        const multibaseMultikeyHeader = options.key.publicKeyMultibase.slice(0, 3);
        if (multibaseMultikeyHeader !== 'zDn')
            throw new Error('ECDSA selective disclosure is only supported with P-256 keys');
        return ecdsaSd2023Cryptosuite.createSignCryptosuite(options);
    }
    return ecdsa2019Cryptosuite;
}

/**
 * Supported cryptographic suites mapped by multibase prefix
 * Each suite contains:
 * - from: Function to create key pair from multibase
 * - cryptosuite: Function to create signing/verification suite
 * 
 * Selective disclosure support:
 * - P-256: Optional
 * - BLS12-381: Required
 * - Others: Not supported
 */
const suites = {
    'zDn': {  // P-256 ECDSA
        from: EcdsaMultikey.from,
        cryptosuite: ecdsa_createCryptosuite
    },
    'z82': {  // P-384 ECDSA
        from: EcdsaMultikey.from,
        cryptosuite: ecdsa_createCryptosuite
    },
    'z2J': {  // P-521 ECDSA
        from: EcdsaMultikey.from,
        cryptosuite: ecdsa_createCryptosuite
    },
    'zEP': {  // Chinese SM2
        from: SM2Multikey.from,
        cryptosuite: function (options) {
            // SM2 does not support selective disclosure
            if (options.useSelectiveDisclosure)
                return sm2Sd2023Cryptosuite.createSignCryptosuite(options);

            return sm2Cryptosuite;
        }
    },
    'z6M': {  // Ed25519
        from: Ed25519Multikey.from,
        cryptosuite: function (options) {
            // Ed25519 does not support selective disclosure
            if (options.useSelectiveDisclosure)
                throw new Error('Ed25519 does not support selective disclosure');

            return eddsa2022CryptoSuite;
        }
    },
    'zUC': {  // BLS12-381
        from: bls12381Multikey.from,
        cryptosuite: function (options) {
            // BLS12-381 must use selective disclosure
            if (!options.useSelectiveDisclosure)
                throw new Error('BLS12-381 must use selective disclosure');

            return bbs2023Cryptosuite.createSignCryptosuite(options);
        }
    }
};

/**
 * Key pair generators for supported key types
 * Returns key pair with multibase-encoded public and private keys
 */
export const generaters = {
    'P-256': EcdsaMultikey.generate.bind(EcdsaMultikey, { curve: 'P-256' }),
    'P-384': EcdsaMultikey.generate.bind(EcdsaMultikey, { curve: 'P-384' }),
    'P-521': EcdsaMultikey.generate.bind(EcdsaMultikey, { curve: 'P-521' }),
    'SM2': SM2Multikey.generate,
    'Ed25519': Ed25519Multikey.generate,
    'Bls12381': bls12381Multikey.generateBbsKeyPair.bind(bls12381Multikey, { algorithm: 'BBS-BLS12-381-SHA-256' })
}

/**
 * Verification suites for different proof types
 * Used for credential and presentation verification
 */
export const verifers = {
    'ecdsa-2019': new DataIntegrityProof({ cryptosuite: ecdsa2019Cryptosuite }),
    'sm2-2023': new DataIntegrityProof({ cryptosuite: sm2Cryptosuite }),
    'eddsa-2022': new DataIntegrityProof({ cryptosuite: eddsa2022CryptoSuite }),
    'bbs-2023': new DataIntegrityProof({ cryptosuite: bbs2023Cryptosuite.createVerifyCryptosuite() }),
    'ecdsa-sd-2023': new DataIntegrityProof({ cryptosuite: ecdsaSd2023Cryptosuite.createVerifyCryptosuite() }),
    'sm2-sd-2023': new DataIntegrityProof({ cryptosuite: sm2Sd2023Cryptosuite.createVerifyCryptosuite() })
}

/**
 * Extend jsonld-signatures verify to support automatic cryptosuite detection
 * Uses proof.cryptosuite to determine appropriate verification suite
 */
const jsigs_verify = jsigs.verify;
jsigs.verify = async function (document, options) {
    const _options = { ...options };

    if (!_options.suite) {
        _options.suite = verifers[document.proof.cryptosuite];
        if (!_options.suite)
            throw new Error('Unsupported cryptosuite: ' + document.proof.cryptosuite);
    }

    return await jsigs_verify(document, _options);
}

ecdsa2019Cryptosuite.requiredAlgorithm.push('P-521');

/**
 * Get suite implementation based on key's multibase prefix
 * @param {Object} key Key pair or public key object 
 * @returns {Object} Suite implementation
 * @throws {Error} If multibase prefix is not supported
 */
function get_suite(key) {
    const multibaseMultikeyHeader = key.publicKeyMultibase.slice(0, 3);
    const suite = suites[multibaseMultikeyHeader];
    if (!suite) {
        throw new Error(`Unsupported "multibaseMultikeyHeader", "${multibaseMultikeyHeader}".`);
    }

    return suite;
}

/**
 * Create key pair from multibase-encoded key
 * @param {Object} key Key object with publicKeyMultibase
 * @returns {Promise<Object>} Key pair instance
 */
export async function fromMultibase(key) {
    return await get_suite(key).from(key);
}

/**
 * Parse DID URI into components
 * @param {string} did DID URI (did:key:...)
 * @returns {Object} Parsed components (authority, fragment, multibase)
 */
export function parseDid(did) {
    const [didAuthority, keyIdFragment] = did.split('#');
    const publicKeyMultibase = didAuthority.substring('did:key:'.length);

    return { didAuthority, keyIdFragment, publicKeyMultibase };
}

/**
 * Create or validate key pair from DID or key object
 * @param {string|Object} did DID URI or key object
 * @returns {Promise<Object>} Key pair instance
 * @throws {Error} If DID is invalid or keys mismatch
 */
export async function getKeyPair(did) {
    var key;

    if (typeof did === 'object') {
        key = { ...did };
        did = key.id;
    }
    else if (typeof did !== 'string')
        throw new Error('Invalid DID');

    const { didAuthority, keyIdFragment, publicKeyMultibase } = parseDid(did);
    if (!key)
        key = {
            id: did,
            controller: didAuthority,
            publicKeyMultibase
        };
    else if (!key.publicKeyMultibase)
        key.publicKeyMultibase = publicKeyMultibase;
    else if (key.publicKeyMultibase !== publicKeyMultibase)
        throw new Error('Mismatched DID');

    return await fromMultibase(key);
}

/**
 * Create signing suite for issuing credentials/presentations
 * @param {Object} options Configuration options
 * @returns {Promise<Object>} Data integrity proof suite
 */
export async function signer_suite(options) {
    const keyPair = await getKeyPair(options.key);
    return new DataIntegrityProof({
        signer: keyPair.signer(),
        cryptosuite: get_suite(keyPair).cryptosuite(options)
    });
}

/**
 * Create suite for deriving selective disclosure credentials
 * @param {Object} options Derivation options
 * @returns {Object} Data integrity proof suite for derivation
 * @throws {Error} If cryptosuite is not supported
 */
export function derive_suite(options) {
    switch (options.verifiableCredential.proof.cryptosuite) {
        case 'bbs-2023':
            return new DataIntegrityProof({
                cryptosuite: bbs2023Cryptosuite.createDiscloseCryptosuite(options)
            });
        case 'ecdsa-sd-2023':
            return new DataIntegrityProof({
                cryptosuite: ecdsaSd2023Cryptosuite.createDiscloseCryptosuite(options)
            });
        case 'sm2-sd-2023':
            return new DataIntegrityProof({
                cryptosuite: sm2Sd2023Cryptosuite.createDiscloseCryptosuite(options)
            });
    }

    throw new Error('Unsupported cryptosuite: ' + options.verifiableCredential.proof.cryptosuite);
}