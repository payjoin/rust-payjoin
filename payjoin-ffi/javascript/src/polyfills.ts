import buffer from "node:buffer";
import ws from "ws";


// Reqired for Node.JS version < 20,
// buffer.File is not available in all v18 and v19 versions as it was backported
if (typeof globalThis.File === "undefined") {
    if (buffer.File) {
        (globalThis.File as any) = buffer.File;
    } else {
        console.warn("File is missing and not found in buffer module");
    }
}

// WebSocket polyfill is needed for Node.JS version < 21
// This will work for v18+
if (typeof globalThis.WebSocket === "undefined") {
    try {
        (globalThis.WebSocket as any) = ws;
    } catch (e) {
        console.error("Failed to load WebSocket polyfill", e);
    }
}
