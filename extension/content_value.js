"use strict";
// Callers validate eligibility and resolve select options before setting a value.
function setControlValue(control, value) {
    const prototype =
        control instanceof HTMLInputElement
            ? HTMLInputElement.prototype
            : control instanceof HTMLTextAreaElement
              ? HTMLTextAreaElement.prototype
              : HTMLSelectElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
    if (setter) setter.call(control, value);
    else control.value = value;
    control.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    control.dispatchEvent(new Event("change", { bubbles: true }));
}
module.exports = { setControlValue };
