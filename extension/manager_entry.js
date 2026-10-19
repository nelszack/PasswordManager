"use strict";
const controller = require("./manager.js").create();
window.addEventListener("pagehide", controller.dispose, { once: true });
