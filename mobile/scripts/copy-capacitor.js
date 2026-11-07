// Copies Capacitor's browser script into www/vendor so the plain-JavaScript
// app (no bundler) can use window.Capacitor.registerPlugin(...).
const fs = require("fs");
const path = require("path");
const source = require.resolve("@capacitor/core/dist/capacitor.js");
const target = path.join(__dirname, "..", "www", "vendor", "capacitor.js");
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.copyFileSync(source, target);
console.log("Copied Capacitor core to www/vendor/capacitor.js");
