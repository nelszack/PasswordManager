"use strict";
// An editor owns one reveal lease. Async replies are bound to its serial; the
// timer erases only the values it revealed, preserving subsequent user edits.
module.exports.create = function create({ setTimeout, clearTimeout, onHide }) {
    let serial = 0, timer, records = [];
    function cancel() { clearTimeout(timer); serial++; records = []; }
    function request() { return ++serial; }
    function track(control) { records.push({ control, value: control.value }); }
    function transfer(previous, next, previousDisplayed) {
        for (const record of records) {
            if (record.control === previous && record.value === previousDisplayed) {
                record.control = next; record.value = next.value;
            }
        }
    }
    function schedule(isCurrent, requestSerial) {
        clearTimeout(timer);
        timer = setTimeout(() => {
            if (requestSerial !== serial || !isCurrent()) return;
            for (const { control, value } of records) {
                if (control.value === value) { control.value = ""; if (control.tagName === "INPUT") control.type = "password"; }
                onHide(control);
            }
            records = [];
        }, 30_000);
    }
    return { cancel, request, track, transfer, schedule,
        retainCurrent() { records = records.filter(({ control, value }) => control.isConnected && control.value === value); },
        get serial() { return serial; } };
};
