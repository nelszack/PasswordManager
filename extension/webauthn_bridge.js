// Isolated-world half of browser passkeys, in top-level HTTPS documents. It
// relays WebAuthn requests from webauthn_page.js to the extension and posts the
// outcome back. The page can post these messages too; that is equivalent to
// calling navigator.credentials itself, because the background takes the origin
// from browser sender metadata and asks the person before every operation.
(() => {
    "use strict";
    const CHANNEL = "pm-passkey";
    const MAX_OPTIONS = 64 * 1024;
    const reply = (id, result) =>
        window.postMessage({ channel: CHANNEL, type: "result", id, result }, location.origin);
    const announce = () => window.postMessage({ channel: CHANNEL, type: "ready" }, location.origin);

    window.addEventListener("message", event => {
        if (event.source !== window || event.origin !== location.origin) return;
        const data = event.data;
        if (!data || data.channel !== CHANNEL) return;
        if (data.type === "hello") {
            announce();
            return;
        }
        if (typeof data.id !== "string" || !/^[0-9a-f-]{36}$/.test(data.id)) return;
        if (data.type === "cancel") {
            chrome.runtime.sendMessage(
                { action: "cancelPasskeyRequest", requestId: data.id },
                () => void chrome.runtime.lastError
            );
            return;
        }
        if (
            data.type !== "request" ||
            !["create", "get"].includes(data.kind) ||
            typeof data.options !== "string" ||
            data.options.length > MAX_OPTIONS
        ) {
            return;
        }
        try {
            chrome.runtime.sendMessage(
                { action: "passkeyRequest", requestId: data.id, kind: data.kind, options: data.options },
                response => {
                    // A rejected request (`success: false` from the router, for
                    // example when the browser omits sender details) is not a
                    // refusal: the browser's own WebAuthn handles it.
                    const failed =
                        chrome.runtime.lastError ||
                        !response ||
                        typeof response !== "object" ||
                        response.success === false;
                    reply(data.id, failed ? { fallback: true } : response);
                }
            );
        } catch (_) {
            // The extension was reloaded; the browser's own WebAuthn still works.
            reply(data.id, { fallback: true });
        }
    });
    announce();
})();
