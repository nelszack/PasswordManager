const test = require("node:test");
const assert = require("node:assert/strict");
const { create } = require("./content_controls.js");

test("credential filling preserves literal None usernames and omits only absent values", () => {
    const { accountUsername } = create({ bridge: {}, credentials: {}, autofill: {} });
    for (const username of ["None", "  username  ", "", null, undefined]) {
        assert.equal(accountUsername({ username }), username || "");
    }
});

test("position measurements defer writes and unchanged positions avoid style mutation", () => {
    const { positionedButton } = require("./content_controls.js");
    const previous = global.getComputedStyle;
    global.getComputedStyle = () => ({ display: "block", visibility: "visible", opacity: "1" });
    try {
        let writes = 0;
        const input = { isConnected: true, nodeType: 1, getBoundingClientRect: () => ({ width:100,height:20,right:120,top:10 }) };
        const style = new Proxy({}, { set(object,key,value) { writes++; object[key]=value; return true; } });
        const position = positionedButton(input,{style},30);
        const apply = position.measure();
        assert.equal(writes,0);
        apply(); assert.equal(style.left,"90px"); assert.equal(style.top,"6px"); assert.equal(style.display,"flex");
        const before = writes; position(); assert.equal(writes,before);
        input.isConnected=false; position(); assert.equal(style.display,"none");
    } finally { global.getComputedStyle=previous; }
});

test("layout frames measure every control before applying any position", () => {
    const previous = {};
    for (const key of ["window", "document", "MutationObserver", "ResizeObserver", "requestAnimationFrame"]) previous[key] = global[key];
    const events={}, frames=[], work=[];
    global.window={addEventListener(name,callback) { events[name]=callback; }};
    global.document={body:{}};
    global.MutationObserver=class { observe() {} disconnect() {} };
    global.ResizeObserver=class { observe() {} unobserve() {} disconnect() {} };
    global.requestAnimationFrame=callback=>frames.push(callback);
    const controls=create({bridge:{},credentials:{},autofill:{}});
    try {
        for (const id of [1,2]) {
            const position=()=>assert.fail("unbatched position");
            position.measure=()=> {work.push(`read ${id}`);return()=>work.push(`write ${id}`);};
            controls.registerPositionedControl({isConnected:true},{remove(){}},position);
        }
        assert.equal(frames.length, 1, "discovery schedules one shared layout frame");
        assert.deepEqual(work, [], "registering controls performs no geometry work");
        events.resize(); events.scroll();
        assert.equal(frames.length,1);
        frames.shift()();
        assert.deepEqual(work,["read 1","read 2","write 1","write 2"]);
    } finally {
        controls.dispose();
        for (const [key,value] of Object.entries(previous)) {
            if (value===undefined) delete global[key]; else global[key]=value;
        }
    }
});

test("controls step left of site icons that cover the field's right edge", () => {
    const { positionedButton } = require("./content_controls.js");
    const previous = { getComputedStyle: global.getComputedStyle, document: global.document };
    global.getComputedStyle = () => ({ display: "block", visibility: "visible", opacity: "1" });
    try {
        const input = { isConnected: true, nodeType: 1, getBoundingClientRect: () => ({ left: 20, width: 100, height: 20, right: 120, top: 10 }) };
        const ours = { classList: { contains: name => name === "my-extension-ui" } };
        let hits = [];
        global.document = { elementsFromPoint: () => hits };
        const style = {};
        const position = positionedButton(input, { style }, 30);
        hits = [ours, input]; position(); assert.equal(style.left, "90px");
        hits = [ours, { classList: { contains: () => false }, contains: () => false }]; position();
        assert.equal(style.left, "58px", "site icon on top");
        hits = [{ contains: node => node === input }]; position(); assert.equal(style.left, "90px", "ancestor wrapper");
        hits = []; position(); assert.equal(style.left, "90px");
    } finally { Object.assign(global, previous); if (!previous.document) delete global.document; }
});
