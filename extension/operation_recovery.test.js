const test = require("node:test");
const assert = require("node:assert/strict");
const { create } = require("./operation_recovery.js");

test("unknown and pending outcomes never authorize a new mutation; a committed receipt does", async () => {
    let state = "unknown", writes = 0;
    const recovery = create({ reconcile: async operationId => ({ state, operationId, revision: 2 }) });
    await assert.rejects(recovery.run(async () => { writes++; throw Object.assign(new Error("Reply lost"), { uncertain: true, operationId: "save-1" }); }), /Reply lost/);
    for (state of ["unknown", "pending"]) {
        assert.equal((await recovery.review()).state, state);
        await assert.rejects(recovery.run(async () => writes++), /previous operation/);
    }
    state = "committed";
    await recovery.review(); await recovery.run(async () => writes++);
    assert.equal(writes, 2);
});

test("definite failures allow correction and durability warnings are terminal without replay", async () => {
    const recovery = create({ reconcile: async () => ({ state: "committed_durability_unknown" }) });
    await assert.rejects(recovery.run(async () => { throw new Error("Revision conflict"); }), /Revision conflict/);
    assert.equal(recovery.unresolved, null);
    recovery.remember("save-2");
    assert.equal((await recovery.review()).state, "committed_durability_unknown");
    assert.equal(recovery.unresolved, null);
});

test("unknown acknowledgement is explicit, cannot acknowledge pending, and never reruns the mutation", async () => {
    const acknowledgements = []; let state = "pending", writes = 0;
    const recovery = create({ reconcile: async () => ({ state }), acknowledgeUnknown: async id => acknowledgements.push(id) });
    await assert.rejects(recovery.run(async () => { writes++; throw Object.assign(new Error("Lost"), { uncertain: true, operationId: "save-3", operationAction: "managerUpdate" }); }));
    await recovery.review(); await assert.rejects(recovery.acknowledge(), /unknown operation/);
    state = "unknown"; await recovery.review();
    assert.equal(recovery.unresolved.action, "managerUpdate");
    await recovery.acknowledge();
    assert.deepEqual(acknowledgements, ["save-3"]); assert.equal(writes, 1);
    await recovery.run(async () => writes++); assert.equal(writes, 2);
});
