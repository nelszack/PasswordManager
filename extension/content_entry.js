"use strict";
const { create } = require("./content.js");
let controller;
function mount() {
    controller?.dispose(); controller = create();
    controller.start().catch(error => console.log("Password Manager error:", error));
}
window.addEventListener("pagehide", () => queueMicrotask(() => { controller?.dispose(); controller = null; }));
window.addEventListener("pageshow", event => { if (event.persisted) mount(); });
mount();
