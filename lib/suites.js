import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import { cryptosuite as ecdsa2019Cryptosuite } from '@digitalbazaar/ecdsa-2019-cryptosuite';
import * as ecdsaSd2023Cryptosuite from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';

import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import { cryptosuite as eddsa2022CryptoSuite } from '@digitalbazaar/eddsa-2022-cryptosuite';

import { SM2Multikey, cryptosuite as sm2Cryptosuite } from '@instun/sm2-multikey';

import * as bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as bbs2023Cryptosuite from '@digitalbazaar/bbs-2023-cryptosuite';

import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';

function ecdsa_createCryptosuite(options) {
    if (options.mandatoryPointers)
        return ecdsaSd2023Cryptosuite.createSignCryptosuite(options);
    return ecdsa2019Cryptosuite;
}

const suites = {
    'zDn': {
        from: EcdsaMultikey.from,
        cryptosuite: ecdsa_createCryptosuite
    },
    'z82': {
        from: EcdsaMultikey.from,
        cryptosuite: ecdsa_createCryptosuite
    },
    'z2J': {
        from: EcdsaMultikey.from,
        cryptosuite: ecdsa_createCryptosuite
    },
    'zEP': {
        from: SM2Multikey.from,
        cryptosuite: function () { return sm2Cryptosuite }
    },
    'z6M': {
        from: Ed25519Multikey.from,
        cryptosuite: function () { return eddsa2022CryptoSuite }
    },
    'zUC': {
        from: bls12381Multikey.from,
        cryptosuite: bbs2023Cryptosuite.createSignCryptosuite
    }
};

export const generaters = {
    'P-256': EcdsaMultikey.generate.bind(EcdsaMultikey, { curve: 'P-256' }),
    'P-384': EcdsaMultikey.generate.bind(EcdsaMultikey, { curve: 'P-384' }),
    'P-521': EcdsaMultikey.generate.bind(EcdsaMultikey, { curve: 'P-521' }),
    'SM2': SM2Multikey.generate,
    'Ed25519': Ed25519Multikey.generate,
    'Bls12381': bls12381Multikey.generateBbsKeyPair.bind(bls12381Multikey, { algorithm: 'BBS-BLS12-381-SHA-256' })
}

export const verifers = {
    'ecdsa-2019': new DataIntegrityProof({ cryptosuite: ecdsa2019Cryptosuite }),
    'sm2-2023': new DataIntegrityProof({ cryptosuite: sm2Cryptosuite }),
    'eddsa-2022': new DataIntegrityProof({ cryptosuite: eddsa2022CryptoSuite }),
    'bbs-2023': new DataIntegrityProof({ cryptosuite: bbs2023Cryptosuite.createVerifyCryptosuite() }),
    'ecdsa-sd-2023': new DataIntegrityProof({ cryptosuite: ecdsaSd2023Cryptosuite.createVerifyCryptosuite() })
}

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

function get_suite(key) {
    const multibaseMultikeyHeader = key.publicKeyMultibase.slice(0, 3);
    const suite = suites[multibaseMultikeyHeader];
    if (!suite) {
        throw new Error(`Unsupported "multibaseMultikeyHeader", "${multibaseMultikeyHeader}".`);
    }

    return suite;
}

export async function fromMultibase(key) {
    return await get_suite(key).from(key);
}

export function parseDid(did) {
    const [didAuthority, keyIdFragment] = did.split('#');
    const publicKeyMultibase = didAuthority.substring('did:key:'.length);

    return { didAuthority, keyIdFragment, publicKeyMultibase };
}

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

export async function signer_suite(options) {
    const keyPair = await getKeyPair(options.key);
    return new DataIntegrityProof({
        signer: keyPair.signer(),
        cryptosuite: get_suite(keyPair).cryptosuite(options)
    });
}

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
    }

    throw new Error('Unsupported cryptosuite: ' + options.verifiableCredential.proof.cryptosuite);
}