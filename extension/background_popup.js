// Popup vault access for the active tab: list logins saved for the tab's
// origin, fill one into the page, and copy values through the desktop service's
// timed clipboard so secrets never reach the browser for a copy.
const PasswordManagerBackgroundPopup = {
    create({ chrome, security, protocol, nativeRequest, crypto, setTimeout, rememberFilled = () => {} }) {
        const FILL_LIFETIME = 15_000;
        const FIELDS = new Set(["username", "password", "totp"]);
        const pendingFills = new Map();
        let listing = null;
        // The latest vault-wide search, so a copy names one of its results.
        let found = null;
        let generation = 0;

        function popupSender(sender) {
            return security.securePickerSender(sender, chrome.runtime.id, chrome.runtime.getURL("popup.html"));
        }

        async function activeTab() {
            const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
            return tab;
        }

        // Only https pages receive the content script, so only they can be filled.
        function siteOf(tab) {
            const origin = security.urlOrigin(tab?.url);
            if (!origin) return { origin: null, reason: "unsupported" };
            if (!origin.startsWith("https://")) return { origin: null, reason: "insecure", host: origin };
            return { origin, reason: null };
        }

        async function logins(request, sender) {
            if (!popupSender(sender)) throw new Error("Invalid popup request");
            const epoch = generation;
            const tab = await activeTab();
            const site = siteOf(tab);
            if (!site.origin) {
                listing = null;
                return { success: true, site: null, reason: site.reason, host: site.host || null, items: [] };
            }
            const response = await nativeRequest("getLoginItems", { domain: site.origin });
            if (epoch !== generation) throw new Error("The vault locked; try again");
            const items = protocol
                .parseItems(response)
                .filter(item => Number.isSafeInteger(item?.id) && item.id > 0)
                .map(item => ({
                    id: item.id,
                    revision: item.revision,
                    name: String(item.name || ""),
                    username: String(item.username || ""),
                    hasTotp: item.has_totp === true,
                }));
            listing = { tabId: tab.id, origin: site.origin, items, sessionId: protocol.sessionId(response) };
            return { success: true, site: site.origin, items: items.map(({ revision, ...item }) => item) };
        }

        // The selection must come from the latest listing for the same tab and origin.
        async function selected(request) {
            if (!listing) throw new Error("Reopen the popup to see this site's logins");
            const item = listing.items.find(candidate => candidate.id === request?.id);
            if (!item) throw new Error("That login is no longer available");
            const tab = await chrome.tabs.get(listing.tabId).catch(() => null);
            if (!tab || security.urlOrigin(tab.url) !== listing.origin) {
                listing = null;
                throw new Error("The page changed; reopen the popup");
            }
            return { item, origin: listing.origin, tabId: listing.tabId, sessionId: listing.sessionId };
        }

        async function copy(request, sender) {
            if (!popupSender(sender)) throw new Error("Invalid popup request");
            if (!FIELDS.has(request?.field)) throw new Error("Invalid copy request");
            const choice = await selected(request);
            const response = await nativeRequest("copyLoginValue", {
                domain: choice.origin,
                entryId: choice.item.id,
                field: request.field,
                expectedRevision: choice.item.revision,
                expectedSession: choice.sessionId,
            });
            if (!response.success) throw new Error(response.error || "Could not copy");
            return { success: true, data: response.data };
        }

        // Vault-wide search over names, usernames, and addresses; no secrets.
        async function search(request, sender) {
            if (!popupSender(sender)) throw new Error("Invalid popup request");
            const query = typeof request?.query === "string" ? request.query.trim() : "";
            if (query.length < 2 || query.length > 256) return { success: true, items: [], total: 0 };
            const epoch = generation;
            const response = await nativeRequest("searchItems", { query });
            if (!response.success) throw new Error(response.error || "Search failed");
            if (epoch !== generation) throw new Error("The vault locked; try again");
            const page = response.data || {};
            const items = (Array.isArray(page.items) ? page.items : [])
                .filter(item => Number.isSafeInteger(item?.id) && item.id > 0)
                .slice(0, 50)
                .map(item => ({
                    id: item.id,
                    revision: item.revision,
                    name: String(item.name || ""),
                    username: String(item.username || ""),
                    kind: String(item.kind || "login"),
                    site: String(item.urls?.[0] || ""),
                    hasTotp: item.has_totp === true,
                }));
            found = { items, sessionId: protocol.sessionId(response) };
            return {
                success: true,
                total: Number.isSafeInteger(page.total) ? page.total : items.length,
                items: items.map(({ revision, ...item }) => item),
            };
        }

        // Copy a search result's main secret through the desktop service.
        async function copyItem(request, sender) {
            if (!popupSender(sender)) throw new Error("Invalid popup request");
            const item = found?.items.find(candidate => candidate.id === request?.id);
            if (!item) throw new Error("Search again to copy this item");
            const field = request?.field || "password";
            if (!FIELDS.has(field)) throw new Error("Invalid copy request");
            const response = await nativeRequest("copyItem", {
                entryId: item.id,
                field,
                expectedRevision: item.revision,
                expectedSession: found.sessionId,
            });
            if (!response.success) throw new Error(response.error || "Could not copy");
            return { success: true, data: response.data };
        }

        async function copyGenerated(request, sender) {
            if (!popupSender(sender)) throw new Error("Invalid popup request");
            const value = request?.value;
            if (typeof value !== "string" || !value || value.length > 4096) throw new Error("Invalid copy request");
            const response = await nativeRequest("copyGenerated", { password: value });
            if (!response.success) throw new Error(response.error || "Could not copy");
            return { success: true, data: response.data };
        }

        // Save a new login for the listed site with a password generated in the popup.
        async function save(request, sender) {
            if (!popupSender(sender)) throw new Error("Invalid popup request");
            const name = typeof request?.name === "string" ? request.name.trim() : "";
            const username = typeof request?.username === "string" ? request.username.trim() : "";
            const password = request?.password;
            if (!name || name.length > 200 || username.length > 400) throw new Error("Enter a name for the login");
            if (typeof password !== "string" || !password || password.length > 4096)
                throw new Error("Generate a password first");
            if (!listing) throw new Error("Reopen the popup to add a login for this site");
            const tab = await chrome.tabs.get(listing.tabId).catch(() => null);
            if (!tab || security.urlOrigin(tab.url) !== listing.origin) {
                listing = null;
                throw new Error("The page changed; reopen the popup");
            }
            const response = await nativeRequest("saveCredentials", {
                domain: listing.origin,
                name,
                username,
                password,
                expectedSession: listing.sessionId,
            });
            if (!response.success) throw new Error(response.error || "Could not save");
            return { success: true, data: response.data };
        }

        async function fill(request, sender) {
            if (!popupSender(sender)) throw new Error("Invalid popup request");
            const choice = await selected(request);
            const token = crypto.randomUUID();
            const pending = { ...choice, expiresAt: Date.now() + FILL_LIFETIME, generation };
            pendingFills.set(token, pending);
            setTimeout(() => {
                if (pendingFills.get(token) === pending) pendingFills.delete(token);
            }, FILL_LIFETIME);
            let answer;
            try {
                answer = await chrome.tabs.sendMessage(choice.tabId, { action: "pmPopupFill", token }, { frameId: 0 });
                // Sign-in forms are often in an iframe. Same-origin frames with a
                // login form answer; the claim still checks each frame's origin.
                if (answer?.noForm) {
                    answer =
                        (await chrome.tabs
                            .sendMessage(choice.tabId, {
                                action: "pmPopupFill",
                                token,
                                embedded: true,
                                origin: choice.origin,
                            })
                            .catch(() => null)) || answer;
                }
            } catch (_) {
                answer = null;
            }
            if (!answer?.success) {
                pendingFills.delete(token);
                throw new Error(
                    answer?.error ||
                        "This page is not ready for filling. Reload it, or use the key button in the login field."
                );
            }
            return { success: true };
        }

        // The page frame that holds the login form claims the fill it was asked
        // to perform. Only one frame may claim it.
        async function claim(request, sender) {
            const pending = pendingFills.get(request?.token);
            if (
                !pending ||
                pending.expiresAt <= Date.now() ||
                pending.generation !== generation ||
                sender?.tab?.id !== pending.tabId ||
                !Number.isInteger(sender?.frameId) ||
                security.senderOrigin(sender) !== pending.origin
            ) {
                throw new Error("Fill request expired");
            }
            if (pending.claimed) return { success: false, duplicate: true, error: "Already filled" };
            pending.claimed = true;
            const response = await nativeRequest("getLoginItem", {
                domain: pending.origin,
                entryId: pending.item.id,
                expectedRevision: pending.item.revision,
                expectedSession: pending.sessionId,
            });
            if (!response.success) throw new Error(response.error || "Login unavailable");
            if (pending.generation !== generation) throw new Error("Fill request expired");
            const payload = response.data;
            await rememberFilled(
                { tabId: pending.tabId, frameId: sender.frameId, domain: pending.origin },
                payload.username ? String(payload.username).trim() : "",
                payload.password
            );
            return { success: true, payload };
        }

        function invalidate() {
            generation++;
            pendingFills.clear();
            listing = null;
            found = null;
        }

        return { logins, search, copyItem, copy, copyGenerated, save, fill, claim, invalidate };
    },
};

module.exports = PasswordManagerBackgroundPopup;
