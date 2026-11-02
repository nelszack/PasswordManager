"use strict";
// An editor owns one reveal lease. Async replies are bound to its serial; the
// timer erases only the values it revealed, preserving subsequent user edits.
module.exports.create = function create({ setTimeout, clearTimeout, onHide, onHidden = () => {} }) {
    let serial = 0, timer, records = [];
    function cancel() { clearTimeout(timer); serial++; records = []; onHidden(); }
    function request() { return ++serial; }
    function track(control, erase = true) { records.push({ control, value: control.value, erase }); }
    function transfer(previous, next, previousDisplayed) {
        for (const record of records) {
            if (record.control === previous && record.value === previousDisplayed) {
                record.control = next; record.value = next.value;
            }
        }
    }
    function hide() {
        clearTimeout(timer); serial++;
        for (const { control, value, erase } of records) {
            if (erase && control.value === value) control.value = "";
            if (control.tagName === "TEXTAREA") control.hidden = true;
            if (control.tagName === "INPUT") control.type = "password";
            onHide(control);
        }
        records = []; onHidden();
    }
    function schedule(isCurrent, requestSerial) {
        clearTimeout(timer);
        timer = setTimeout(() => {
            if (requestSerial === serial && isCurrent()) hide();
        }, 30_000);
    }
    return { cancel, hide, request, track, transfer, schedule,
        retainCurrent() { records = records.filter(({ control, value }) => control.isConnected && control.value === value); },
        get serial() { return serial; } };
};
