// Browser passkeys: WebAuthn requests relayed by webauthn_bridge.js become one
// explicit decision in passkey_prompt.html. The site is the browser-reported
// origin of the top-level document, never a value the page supplied, and the
// vault checks the relying party against it again. Requests this vault cannot
// serve are returned to the browser's own WebAuthn.
const PasswordManagerBackgroundPasskeys = {
    create({ chrome, security, nativeRequest, crypto, setTimeout, lifetimeMs = 180_000 }) {
        const decisions = (
            typeof PasswordManagerDecisionWindows === "undefined"
                ? require("./background_windows.js")
                : PasswordManagerDecisionWindows
        ).create({
            chrome,
            page: "passkey_prompt.html",
            width: 400,
            height: 440,
            setTimeout,
            unavailable: "Could not open passkey prompt",
        });
        const pending = new Map();
        const FALLBACK = Object.freeze({ fallback: true });

        function promptSender(sender) {
            return security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL("passkey_prompt.html"));
        }

        function finish(token, result) {
            const record = pending.get(token);
            if (!record) return;
            pending.delete(token);
            if (Number.isInteger(record.windowId)) {
                decisions.release(record.windowId);
                decisions.close(record.windowId);
            }
            record.resolve(result);
        }

        // WebAuthn's default is "preferred".
        function requestedVerification(kind, options) {
            const requested =
                kind === "create" ? options.authenticatorSelection?.userVerification : options.userVerification;
            return ["required", "discouraged"].includes(requested) ? requested : "preferred";
        }

        // Requests the vault cannot serve go straight back to the browser.
        function supported(kind, options) {
            if (Array.isArray(options.hints) && options.hints.some(hint => hint !== "client-device")) return false;
            const extensions = options.extensions && typeof options.extensions === "object" ? options.extensions : {};
            if (kind === "get") return Object.keys(extensions).length === 0;
            return (
                Array.isArray(options.pubKeyCredParams) &&
                options.pubKeyCredParams.some(param => param?.type === "public-key" && param?.alg === -7) &&
                options.authenticatorSelection?.authenticatorAttachment !== "cross-platform" &&
                Object.keys(extensions).every(name => name === "credProps") &&
                typeof options.rp?.id === "string" &&
                typeof options.user?.name === "string"
            );
        }

        async function request(message, sender) {
            const origin = security.senderOrigin(sender);
            const tabId = sender?.tab?.id;
            if (
                !origin?.startsWith("https://") ||
                sender?.frameId !== 0 ||
                !Number.isInteger(tabId) ||
                typeof sender?.documentId !== "string" ||
                !sender.documentId ||
                !["create", "get"].includes(message?.kind) ||
                typeof message.requestId !== "string" ||
                message.requestId.length > 64 ||
                typeof message.options !== "string" ||
                message.options.length > 64 * 1024
            ) {
                throw new Error("Invalid passkey request");
            }
            let options;
            try {
                options = JSON.parse(message.options);
            } catch (_) {
                throw new Error("Invalid passkey request");
            }
            if (!options || typeof options !== "object" || Array.isArray(options)) {
                throw new Error("Invalid passkey request");
            }
            if (!supported(message.kind, options)) return FALLBACK;
            // One decision per tab; a second concurrent request is refused.
            const busy = () => [...pending.values()].some(record => record.tabId === tabId);
            const refused = { error: "NotAllowedError", message: "Another passkey request is waiting." };
            if (busy()) return refused;
            let choices = [];
            let sessionId = null;
            let locked = false;
            // Whether the desktop app can confirm it is you: the vault has a
            // master password or a passkey PIN on this device.
            let canConfirm = false;
            const lookup =
                message.kind === "get"
                    ? await nativeRequest("getPasskeys", { domain: origin, passkeyRequest: message.options })
                    : await nativeRequest("status");
            if (!lookup.success) {
                locked = /locked/i.test(lookup.error || "");
                if (!locked) return FALLBACK;
            } else if (message.kind === "get") {
                choices = lookup.data;
                sessionId = lookup.sessionId;
                // Nothing saved for this site: the browser may have one.
                if (!choices.length) return FALLBACK;
            } else {
                locked = lookup.data?.locked === true;
                sessionId = lookup.sessionId || null;
                canConfirm = lookup.data?.passkey_verification === true;
            }
            if (message.kind === "get" && !locked) {
                const status = await nativeRequest("status");
                canConfirm = status.success === true && status.data?.passkey_verification === true;
            }
            // Another request may have started during the lookup.
            if (busy()) return refused;
            const token = crypto.randomUUID();
            return new Promise(resolve => {
                const record = {
                    token,
                    tabId,
                    documentId: sender.documentId,
                    requestId: message.requestId,
                    origin,
                    kind: message.kind,
                    options: message.options,
                    rp: message.kind === "create" ? options.rp.id : options.rpId,
                    verification: requestedVerification(message.kind, options),
                    user: message.kind === "create" ? options.user.name : "",
                    choices,
                    sessionId,
                    locked,
                    canConfirm,
                    resolve,
                    windowId: null,
                    expiresAt: Date.now() + lifetimeMs,
                };
                pending.set(token, record);
                decisions
                    .open(token, record, {
                        isCurrent: () => pending.get(token) === record,
                        expiresAt: record.expiresAt,
                        onExpire: () => finish(token, { error: "NotAllowedError", message: "The passkey request timed out." }),
                    })
                    .then(
                        windowId => {
                            if (pending.get(token) === record) record.windowId = windowId;
                        },
                        () => finish(token, FALLBACK)
                    );
            });
        }

        function current(message, sender) {
            if (!promptSender(sender)) throw new Error("Invalid passkey prompt");
            const record = pending.get(message?.token);
            if (!record || record.expiresAt <= Date.now()) throw new Error("Passkey request expired");
            return record;
        }

        // After the vault unlocks elsewhere, a locked request looks up its choices again.
        async function refreshLocked(record) {
            if (!record.locked) return;
            const lookup =
                record.kind === "get"
                    ? await nativeRequest("getPasskeys", { domain: record.origin, passkeyRequest: record.options })
                    : await nativeRequest("status");
            if (!lookup.success) return;
            if (record.kind === "get") {
                // As on first lookup: with no passkey for this site, the browser's own
                // passkey options take over instead of an empty prompt.
                if (!Array.isArray(lookup.data) || !lookup.data.length) {
                    finish(record.token, FALLBACK);
                    return;
                }
                record.choices = lookup.data;
                record.sessionId = lookup.sessionId;
                const status = await nativeRequest("status");
                record.canConfirm = status.success === true && status.data?.passkey_verification === true;
                record.locked = false;
            } else if (lookup.data?.locked !== true) {
                record.sessionId = lookup.sessionId || null;
                record.canConfirm = lookup.data?.passkey_verification === true;
                record.locked = false;
            }
        }

        function data(message, sender) {
            const record = current(message, sender);
            if (message?.refresh === true && record.locked)
                return refreshLocked(record).then(() => describe(record));
            return describe(record);
        }
        function describe(record) {
            return {
                success: true,
                kind: record.kind,
                origin: record.origin,
                rp: record.rp,
                user: record.user,
                locked: record.locked,
                verification: record.verification,
                canConfirm: record.canConfirm,
                choices: record.choices.map(choice => ({
                    id: choice.id,
                    userName: choice.user_name,
                    displayName: choice.display_name,
                })),
            };
        }

        // The page that asked must still be showing the same site.
        async function requireDestination(record) {
            const tab = await chrome.tabs.get(record.tabId).catch(() => null);
            if (pending.get(record.token) !== record || security.urlOrigin(tab?.url) !== record.origin) {
                finish(record.token, { error: "NotAllowedError", message: "The page changed." });
                throw new Error("The page changed; the passkey request was cancelled");
            }
        }

        async function complete(message, sender) {
            const record = current(message, sender);
            const action = message.selection?.action;
            if (action === "fallback") {
                finish(record.token, FALLBACK);
                return { success: true };
            }
            if (action !== "confirm") {
                finish(record.token, { error: "NotAllowedError" });
                return { success: true };
            }
            if (record.locked) throw new Error("Unlock the vault in the desktop app, then try again.");
            const wantsProof = record.verification !== "discouraged" && message.selection?.confirmInDesktop === true;
            if (record.verification === "required" && !record.canConfirm) {
                throw new Error(
                    "This site requires proof that it is you. Set a passkey PIN in the desktop app (Settings → Security), or use another passkey provider."
                );
            }
            if (record.verification === "required" && !wantsProof) {
                throw new Error("This site requires you to confirm it is you in the desktop app.");
            }
            if (wantsProof && !record.canConfirm) throw new Error("This vault cannot confirm it is you.");
            const choice =
                record.kind === "get" ? record.choices.find(candidate => candidate.id === message.selection.id) : null;
            if (record.kind === "get" && !choice) throw new Error("Choose one of the listed passkeys");
            await requireDestination(record);
            let verification = {};
            if (wantsProof) {
                // The service waits for the person to confirm in the desktop app.
                const confirmed = await nativeRequest("verifyPasskeyUser", {
                    domain: record.origin,
                    expectedSession: record.sessionId,
                });
                if (pending.get(record.token) !== record) return { success: false, error: "The passkey request ended." };
                // Not confirmed: the window stays open to try again or cancel.
                if (!confirmed.success) return { success: false, error: confirmed.error || "Not confirmed" };
                verification = { verificationToken: confirmed.data };
                await requireDestination(record);
            }
            let response;
            if (record.kind === "create") {
                response = await nativeRequest("createPasskey", {
                    domain: record.origin,
                    passkeyRequest: record.options,
                    expectedSession: record.sessionId,
                    ...verification,
                });
            } else {
                response = await nativeRequest("getPasskeyAssertion", {
                    domain: record.origin,
                    entryId: choice.id,
                    expectedRevision: choice.revision,
                    expectedSession: record.sessionId,
                    passkeyRequest: record.options,
                    ...verification,
                });
            }
            if (!response.success) {
                const excluded = /CredentialExcluded/.test(response.error || "");
                finish(record.token, {
                    error: excluded ? "InvalidStateError" : "NotAllowedError",
                    message: excluded ? "A passkey for this account is already saved." : undefined,
                });
                return { success: false, error: response.error || "Passkey request failed" };
            }
            finish(record.token, { credential: response.data });
            return { success: true };
        }

        function cancel(message, sender) {
            for (const record of pending.values()) {
                if (
                    record.tabId === sender?.tab?.id &&
                    record.documentId === sender?.documentId &&
                    record.requestId === message?.requestId
                ) {
                    finish(record.token, { error: "AbortError" });
                }
            }
            return { success: true };
        }

        function windowRemoved(windowId) {
            const record = decisions.release(windowId);
            if (!record) return false;
            finish(record.token, { error: "NotAllowedError" });
            return true;
        }

        function invalidate() {
            for (const token of [...pending.keys()]) finish(token, { error: "NotAllowedError" });
        }

        return { request, data, complete, cancel, windowRemoved, invalidate };
    },
};

if (typeof module !== "undefined") module.exports = PasswordManagerBackgroundPasskeys;
