// This script is a dirty hack for Node.JS ESM imports.
// TypeScript compiles imports without a `.js` extension, which results in ERR_MODULE_NOT_FOUND when running in Node.JS.
// This fixes it by adding the `.js` file extension to the import in the generated files (thankfully there is currently only one such instance).
const fs = require('fs');

const file = 'dist/generated/payjoin_ffi.js';
let content = fs.readFileSync(file, 'utf8');
content = content.replace('from "./bitcoin"', 'from "./bitcoin.js"');
fs.writeFileSync(file, content);
