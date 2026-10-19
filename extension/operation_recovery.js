(function (root, factory) {
    const api = factory();
    if (typeof module === "object" && module.exports) module.exports = api;
    else root.PasswordManagerOperationRecovery = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
    "use strict";
    function create({ reconcile, acknowledgeUnknown, onUncertain = () => {} }) {
        let pending = false, unresolved = null, lastState = null;
        function remember(operationId, action) {
            if (unresolved?.operationId === operationId) { unresolved.action = action || unresolved.action; return; }
            lastState = null; unresolved = { operationId, action }; onUncertain(unresolved);
        }
        async function run(operation) {
            if (pending) return;
            if (unresolved) throw new Error("Review the previous operation before making another change.");
            pending = true;
            try { return await operation(); }
            catch (error) { if (error.uncertain) remember(error.operationId, error.operationAction); throw error; }
            finally { pending = false; }
        }
        async function review() {
            if (!unresolved?.operationId) throw new Error("The operation identity is unavailable. Inspect the vault before continuing.");
            const outcome = await reconcile(unresolved.operationId);
            lastState = outcome.state;
            if (["committed", "committed_durability_unknown", "failed"].includes(outcome.state)) unresolved = null;
            return outcome;
        }
        async function acknowledge() {
            if (lastState !== "unknown" || !unresolved?.operationId) throw new Error("Review the unknown operation before acknowledging it");
            await acknowledgeUnknown(unresolved.operationId);
            unresolved = null; lastState = null;
        }
        return { run, review, remember, acknowledge, get unresolved() { return unresolved; }, get pending() { return pending; } };
    }
    return { create };
});
