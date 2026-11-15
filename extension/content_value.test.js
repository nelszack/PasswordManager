const test = require("node:test");
const assert = require("node:assert/strict");
const { setControlValue } = require("./content_value.js");

test("native value setters bypass framework overrides and emit the same composed input/change events", () => {
    const previous = {};
    for (const name of ["HTMLInputElement", "HTMLTextAreaElement", "HTMLSelectElement"]) {
        previous[name] = global[name];
        global[name] = class {
            set value(value) { this.nativeValue = value; }
            dispatchEvent(event) { this.events.push(event); }
        };
    }
    try {
        for (const Constructor of [HTMLInputElement, HTMLTextAreaElement, HTMLSelectElement]) {
            const control = new Constructor(); control.events = [];
            Object.defineProperty(control, "value", { set() { assert.fail("framework setter"); } });
            setControlValue(control, "  exact value\n");
            assert.equal(control.nativeValue, "  exact value\n");
            assert.deepEqual(control.events.map(event => [event.type, event.bubbles, event.composed]),
                [["input", true, true], ["change", true, false]]);
        }
    } finally {
        for (const [name, value] of Object.entries(previous)) {
            if (value === undefined) delete global[name]; else global[name] = value;
        }
    }
});
