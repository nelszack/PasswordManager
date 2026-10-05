const PasswordManagerGenerator = (() => {
    const defaults = Object.freeze({ mode: "password", length: 20, uppercase: true, lowercase: true, digits: true,
        symbols: true, symbolSet: "!@#$%^&*-_=+", excludeAmbiguous: true, words: 6, separator: "-" });
    const left = "amber ancient autumn bold bright calm cedar cinder clear cloud cobalt coral crisp dawn deep ember fable fair fern frost gentle gold grand green harbor hidden indigo iron ivory jade keen lively lunar maple merry misty noble north ocean olive opal quiet rapid red river royal sage silver solar solid spring stone swift tender tidal true velvet vivid warm wild winter wise young zenith".split(" ");
    const right = "acorn badger beacon birch brook canyon castle comet crane creek dolphin eagle falcon field finch forest fox garden glade grove heron hill island lake lantern lark leaf meadow moon oak otter owl panda peak pine planet quartz raven reef ridge robin sail shore sparrow star summit sun tiger trail tree valley violet wave willow wind wolf wren yard zephyr harvest isle orchard prairie rain".split(" ");
    function groups(settings) {
        const ambiguous = new Set("Il1O0o|`'\"");
        return [[settings.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"], [settings.lowercase, "abcdefghijklmnopqrstuvwxyz"],
            [settings.digits, "0123456789"], [settings.symbols, settings.symbolSet]]
            .filter(([enabled]) => enabled).map(([, value]) => [...new Set(value)].filter(c => !settings.excludeAmbiguous || !ambiguous.has(c)).join(""))
            .filter(Boolean);
    }
    function validate(input = {}) {
        const settings = { ...defaults, ...input };
        if (!["password", "passphrase"].includes(settings.mode) || !Number.isInteger(settings.length) || settings.length < 1 || settings.length > 255
            || !Number.isInteger(settings.words) || settings.words < 1 || settings.words > 32
            || typeof settings.separator !== "string" || settings.separator.length > 16 || /[\x00-\x1f\x7f]/.test(settings.separator)
            || typeof settings.symbolSet !== "string" || settings.symbolSet.length > 128 || /[^\x21-\x7e]/.test(settings.symbolSet)
            || ["uppercase", "lowercase", "digits", "symbols", "excludeAmbiguous"].some(key => typeof settings[key] !== "boolean")) {
            throw new Error("Invalid generator settings");
        }
        if (settings.mode === "password" && groups(settings).length === 0) throw new Error("Enable at least one non-empty character set");
        return settings;
    }
    function randomIndex(limit) {
        const ceiling = Math.floor(0x100000000 / limit) * limit;
        const value = new Uint32Array(1);
        do { crypto.getRandomValues(value); } while (value[0] >= ceiling);
        return value[0] % limit;
    }
    function generate(input = {}) {
        const settings = validate(input);
        if (settings.mode === "passphrase") {
            return Array.from({ length: settings.words }, () => left[randomIndex(left.length)] + right[randomIndex(right.length)]).join(settings.separator);
        }
        const classes = groups(settings), all = classes.join("");
        const characters = settings.length >= classes.length ? classes.map(group => group[randomIndex(group.length)]) : [];
        while (characters.length < settings.length) characters.push(all[randomIndex(all.length)]);
        for (let i = characters.length - 1; i > 0; i--) { const j = randomIndex(i + 1); [characters[i], characters[j]] = [characters[j], characters[i]]; }
        return characters.join("");
    }
    function siteOrigin(value) {
        const url = new URL(value);
        if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
            throw new Error("Enter an HTTPS origin, such as https://example.com, without a path");
        }
        return url.origin;
    }
    function settingsForSite(storage, url) {
        let origin; try { origin = new URL(url).origin; } catch (_) { origin = ""; }
        const override = Object.hasOwn(storage.pmGeneratorsByOrigin || {}, origin) ? storage.pmGeneratorsByOrigin[origin] : undefined;
        try { return validate(override || storage.pmGenerator || {}); }
        catch (_) { try { return validate(storage.pmGenerator || {}); } catch (_) { return defaults; } }
    }
    return { defaults, validate, generate, siteOrigin, settingsForSite };
})();
if (typeof module !== "undefined") module.exports = PasswordManagerGenerator;
