(function (root, factory) {
    const api = factory();
    root.PasswordManagerDuoDetection = api;
    if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    function duoOrigin(value) {
        try {
            const url = new URL(value);
            return url.protocol === "https:" && !url.port
                && url.hostname.toLowerCase().endsWith(".duosecurity.com");
        } catch (_) { return false; }
    }
    function challenge(text, url) {
        const words = String(text || "").slice(0, 32_000).replace(/\s+/g, " ");
        if (/\bduo\s+push\b/i.test(words)) {
            return /send (?:me )?a push|push (?:sent|notification)|check (?:your |the )?(?:phone|device)|open duo mobile|approve (?:the |this )?(?:request|login)|waiting for|verify (?:your |the )?identity/i.test(words);
        }
        return duoOrigin(url) && /push sent|check (?:your |the )?(?:phone|device)|open duo mobile/i.test(words);
    }
    return { duoOrigin, challenge };
});
