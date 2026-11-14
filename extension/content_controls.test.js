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
        apply(); assert.equal(style.left,"90px"); assert.equal(style.top,"6px");
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
