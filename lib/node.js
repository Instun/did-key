/**
 * Node.js and fibjs compatibility layer
 * Provides environment-specific implementations and synchronous API support
 * 
 * In fibjs:
 * - Uses vm.SandBox for module isolation
 * - Provides native crypto implementations
 * - Adds synchronous versions of all async functions
 * 
 * In Node.js:
 * - Uses standard browser implementation
 * - No sync functions available
 */

import * as util from 'util';
import * as http from "http";
import * as crypto from 'crypto';
import * as vm from 'vm';

import * as bbs from './bbs.js';

var did_key;

// Setup environment-specific implementation
if (process.versions.fibjs) {
    // Module mapping for fibjs sandbox
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

    // Create isolated sandbox with mapped modules
    const sbox = new vm.SandBox(modules);
    did_key = await sbox.import('./browser.js', import.meta.dirname);
} else {
    // Use standard browser implementation in Node.js
    did_key = await import('./browser.js');
}

// Export standard API from browser implementation
export var contexts = did_key.contexts;
export var generate = did_key.generate;
export var sign = did_key.sign;
export var verify = did_key.verify;
export var issueCredential = did_key.issueCredential;
export var verifyCredential = did_key.verifyCredential;
export var deriveCredential = did_key.deriveCredential;
export var signPresentation = did_key.signPresentation;
export var verifyPresentation = did_key.verifyPresentation;

// Declare sync function variables
export var generate_sync;
export var sign_sync;
export var verify_sync;
export var issueCredential_sync;
export var verifyCredential_sync;
export var deriveCredential_sync;
export var signPresentation_sync;
export var verifyPresentation_sync;

// Create synchronous versions of all functions in fibjs
if (process.versions.fibjs) {
    generate_sync = util.sync(generate);
    sign_sync = util.sync(sign);
    verify_sync = util.sync(verify);
    issueCredential_sync = util.sync(issueCredential);
    verifyCredential_sync = util.sync(verifyCredential);
    deriveCredential_sync = util.sync(deriveCredential);
    signPresentation_sync = util.sync(signPresentation);
    verifyPresentation_sync = util.sync(verifyPresentation);
}
