// Export the generated bindings to the app.
export * from "./generated/payjoin.js";

// Now import the bindings so we can:
// - initialize them
// - export them as namespaced objects as the default export.
import * as payjoin from "./generated/payjoin.js";

import initAsync from "./generated/wasm-bindgen/index.js";
import wasmPath from "./generated/wasm-bindgen/index_bg.wasm";

export async function uniffiInitAsync() {
    await initAsync({ module_or_path: wasmPath });

    // Initialize the generated bindings: mostly checksums, but also callbacks.
    // - the boolean flag ensures this loads exactly once, even if the JS code
    //   is reloaded (e.g. during development with metro).
    payjoin.default.initialize();
}

// Export the crates as individually namespaced objects.
export default {
    payjoin,
};
