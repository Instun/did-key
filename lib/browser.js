import * as vc from './vc';

import * as suites from './suites.js'
import * as defaultContexts from "./contexts/index.js";

export const contexts = defaultContexts.contexts;

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

export async function sign(options) {
    const keyPair = await suites.getKeyPair(options.key);
    return await keyPair.signer().sign(options);
}

export async function verify(options) {
    const keyPair = await suites.getKeyPair(options.key);
    return await keyPair.verifier().verify(options);
}

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

export async function issueCredential(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    if (!_options.suite && _options.key)
        _options.suite = await suites.signer_suite(_options);

    _options.credential.issuer = _options.suite.verificationMethod;

    return await vc.issue(_options);
}

export async function verifyCredential(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    return await vc.verifyCredential(_options);
}

export async function deriveCredential(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    if (!_options.suite)
        _options.suite = suites.derive_suite(_options);

    return await vc.derive(_options);
}

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

export async function verifyPresentation(options) {
    const _options = { ...options };

    if (!_options.documentLoader)
        _options.documentLoader = documentLoader;

    const presentation = _options.presentation;

    if (!_options.challenge)
        _options.challenge = presentation.proof.challenge;

    return await vc.verify(_options);
}
