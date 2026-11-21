// Runs in the page's own JavaScript world (manifest "world": "MAIN") in top-level
// HTTPS documents. It wraps navigator.credentials.create/get for public-key
// requests, asks the extension through webauthn_bridge.js, and uses the
// browser's own WebAuthn whenever the extension declines or is unavailable.
// Nothing here is trusted: the page can call or replace these functions itself.
// The background derives the origin from browser sender metadata, and every
// registration or sign-in needs the person's choice in an extension window.
(function install(root) {
    "use strict";
    const credentials = root.navigator?.credentials;
    if (!credentials || typeof root.PublicKeyCredential !== "function") return;
    const CHANNEL = "pm-passkey";
    const READY_WAIT_MS = 1000;
    const originalCreate = credentials.create.bind(credentials);
    const originalGet = credentials.get.bind(credentials);

    function bytes(source) {
        // Realm-independent: buffers may come from another frame.
        if (Object.prototype.toString.call(source) === "[object ArrayBuffer]") return new Uint8Array(source);
        if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
        throw new TypeError("Expected a BufferSource");
    }
    function encode(source) {
        let text = "";
        for (const byte of bytes(source)) text += String.fromCharCode(byte);
        return root.btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    function decode(text) {
        const binary = root.atob(
            String(text).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(text).length + 3) % 4)
        );
        const out = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
        return out.buffer;
    }
    function descriptors(list = []) {
        return Array.from(list, descriptor => ({
            type: descriptor.type,
            id: encode(descriptor.id),
            ...(descriptor.transports ? { transports: Array.from(descriptor.transports) } : {}),
        }));
    }
    function plain(value) {
        return value && typeof value === "object" ? JSON.parse(JSON.stringify(value)) : undefined;
    }

    // PublicKeyCredentialCreationOptions in WebAuthn's JSON form.
    function creationJSON(options) {
        const user = options.user;
        return {
            rp: { id: options.rp?.id ?? root.location.hostname, name: String(options.rp?.name ?? "") },
            user: {
                id: encode(user.id),
                name: String(user.name),
                displayName: String(user.displayName || user.name),
            },
            challenge: encode(options.challenge),
            pubKeyCredParams: Array.from(options.pubKeyCredParams || [], param => ({
                type: param.type,
                alg: param.alg,
            })),
            excludeCredentials: descriptors(options.excludeCredentials),
            ...(options.authenticatorSelection ? { authenticatorSelection: plain(options.authenticatorSelection) } : {}),
            ...(options.attestation ? { attestation: options.attestation } : {}),
            ...(options.hints ? { hints: Array.from(options.hints) } : {}),
            ...(options.extensions ? { extensions: plain(options.extensions) } : {}),
        };
    }
    // PublicKeyCredentialRequestOptions in WebAuthn's JSON form.
    function requestJSON(options) {
        return {
            challenge: encode(options.challenge),
            rpId: options.rpId ?? root.location.hostname,
            allowCredentials: descriptors(options.allowCredentials),
            ...(options.userVerification ? { userVerification: options.userVerification } : {}),
            ...(options.hints ? { hints: Array.from(options.hints) } : {}),
            ...(options.extensions ? { extensions: plain(options.extensions) } : {}),
        };
    }

    function define(target, values) {
        for (const [key, value] of Object.entries(values))
            Object.defineProperty(target, key, { value, enumerable: true, configurable: true });
        return target;
    }
    // Objects that behave like the browser's own credentials, including
    // instanceof checks, for the response JSON the vault produced.
    function credential(json, kind) {
        const r = json.response;
        const response =
            kind === "create"
                ? define(Object.create(root.AuthenticatorAttestationResponse.prototype), {
                      clientDataJSON: decode(r.clientDataJSON),
                      attestationObject: decode(r.attestationObject),
                      getTransports: () => Array.from(r.transports || []),
                      getAuthenticatorData: () => decode(r.authenticatorData),
                      getPublicKey: () => decode(r.publicKey),
                      getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
                  })
                : define(Object.create(root.AuthenticatorAssertionResponse.prototype), {
                      clientDataJSON: decode(r.clientDataJSON),
                      authenticatorData: decode(r.authenticatorData),
                      signature: decode(r.signature),
                      userHandle: r.userHandle ? decode(r.userHandle) : null,
                  });
        return define(Object.create(root.PublicKeyCredential.prototype), {
            id: json.id,
            rawId: decode(json.rawId),
            type: "public-key",
            authenticatorAttachment: json.authenticatorAttachment || "platform",
            response,
            getClientExtensionResults: () => plain(json.clientExtensionResults) || {},
            toJSON: () => plain(json),
        });
    }

    let ready = false;
    const waiting = [];
    const pending = new Map();
    root.addEventListener("message", event => {
        if (event.source !== root || event.origin !== root.location.origin) return;
        const data = event.data;
        if (!data || data.channel !== CHANNEL) return;
        if (data.type === "ready") {
            ready = true;
            waiting.splice(0).forEach(resume => resume());
        } else if (data.type === "result" && pending.has(data.id)) {
            const resolve = pending.get(data.id);
            pending.delete(data.id);
            resolve(data.result || { fallback: true });
        }
    });
    function whenReady() {
        if (ready) return Promise.resolve(true);
        return new Promise(resolve => {
            waiting.push(() => resolve(true));
            root.setTimeout(() => resolve(ready), READY_WAIT_MS);
        });
    }
    async function ask(kind, options, signal) {
        if (!(await whenReady())) return { fallback: true };
        const id = root.crypto.randomUUID();
        return new Promise((resolve, reject) => {
            const abort = () => {
                pending.delete(id);
                root.postMessage({ channel: CHANNEL, type: "cancel", id }, root.location.origin);
                reject(new root.DOMException("The operation was aborted.", "AbortError"));
            };
            if (signal?.aborted) return abort();
            signal?.addEventListener("abort", abort, { once: true });
            pending.set(id, result => {
                signal?.removeEventListener("abort", abort);
                resolve(result);
            });
            root.postMessage(
                { channel: CHANNEL, type: "request", id, kind, options: JSON.stringify(options) },
                root.location.origin
            );
        });
    }
    async function handle(kind, options, original) {
        const publicKey = options?.publicKey;
        // Conditional (autofill-style) requests stay with the browser.
        if (!publicKey || options.mediation === "conditional") return original(options);
        let json;
        try {
            json = kind === "create" ? creationJSON(publicKey) : requestJSON(publicKey);
        } catch (_) {
            return original(options);
        }
        const result = await ask(kind, json, options.signal);
        if (result.fallback) return original(options);
        if (result.credential) return credential(result.credential, kind);
        throw new root.DOMException(
            result.message || "The request was not allowed.",
            ["InvalidStateError", "AbortError"].includes(result.error) ? result.error : "NotAllowedError"
        );
    }

    credentials.create = function create(options) {
        return handle("create", options, originalCreate);
    };
    credentials.get = function get(options) {
        return handle("get", options, originalGet);
    };
    root.postMessage({ channel: CHANNEL, type: "hello" }, root.location.origin);
})(typeof window !== "undefined" ? window : globalThis);
