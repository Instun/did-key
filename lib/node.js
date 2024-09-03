import * as util from 'util';
import * as http from "http";
import * as crypto from 'crypto';
import * as vm from 'vm';

import * as bbs from './bbs.js';

var did_key;

if (process.versions.fibjs) {
    const modules = {
        "crypto": crypto,
        "node:crypto": crypto,
        "util": util,
        "node:util": util,
        "http": http,
        "https": http,
        "node-fetch": http.promises.get,
        "@digitalbazaar/bbs-signatures": bbs,
        "@digitalbazaar/http-client": {
            "httpClient": {
                "get": http.promises.get
            }
        }
    };

    const sbox = new vm.SandBox(modules);
    did_key = sbox.require('./browser.js', import.meta.dirname);
} else {
    did_key = await import('./browser.js');
}

export var contexts = did_key.contexts;

export var generate = did_key.generate;
export var generate_sync;

export var issueCredential = did_key.issueCredential;
export var issueCredential_sync;

export var verifyCredential = did_key.verifyCredential;
export var verifyCredential_sync;

export var deriveCredential = did_key.deriveCredential;
export var deriveCredential_sync;

export var signPresentation = did_key.signPresentation;
export var signPresentation_sync;

export var verifyPresentation = did_key.verifyPresentation;
export var verifyPresentation_sync;

if (process.versions.fibjs) {
    generate_sync = util.sync(generate);
    issueCredential_sync = util.sync(issueCredential);
    verifyCredential_sync = util.sync(verifyCredential);
    deriveCredential_sync = util.sync(deriveCredential);
    signPresentation_sync = util.sync(signPresentation);
    verifyPresentation_sync = util.sync(verifyPresentation);
}
