"use strict";
const { create, runtimeAvailable } = require("./content.js");
let controller = null;
function mount() {
    controller?.dispose();
    controller = null;
    // A script left behind by an extension update or reload stays inert.
    if (!runtimeAvailable()) return;
    controller = create();
    controller.start().catch(error => console.log("Password Manager error:", error));
}
// One listener captures credentials and then disposes. Browsers run microtasks
// between listeners of a dispatched event, so a separate deferred disposal
// registered first would tear down the controller before it could capture.
// Untrusted events come from page scripts and neither capture nor dispose.
window.addEventListener("pagehide", event => {
    if (!event.isTrusted) return;
    const current = controller;
    controller = null;
    if (!current) return;
    try {
        current.handlePageHide(event);
    } finally {
        current.dispose();
    }
});
window.addEventListener("pageshow", event => {
    if (event.persisted) mount();
});
mount();
