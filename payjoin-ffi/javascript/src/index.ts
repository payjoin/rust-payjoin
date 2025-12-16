// Export the generated bindings to the app.
export * as payjoin from "./generated/payjoin.js";

// Now import the bindings so we can:
// - initialize them
// - export them as namespaced objects as the default export.
import * as payjoin from "./generated/payjoin.js";

let initialized = false;

export async function uniffiInitAsync() {
    if (initialized) return;

    // Await WASM loading
    await import("./generated/wasm-bindgen/index.js");

    // Initialize the generated bindings: mostly checksums, but also callbacks.
    // - the boolean flag ensures this loads exactly once, even if the JS code
    //   is reloaded (e.g. during development with metro).
    payjoin.default.initialize();

    initialized = true;
}

// Export the crates as individually namespaced objects.
export default {
    payjoin,
};
