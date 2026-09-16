import { readFileSync } from "node:fs";

const fixtures = new URL(
    "../../../payjoin-test-utils/fixtures/",
    import.meta.url,
);

export const ORIGINAL_PSBT = readFileSync(
    new URL("original-psbt.base64", fixtures),
    "ascii",
);
// Copy into a Uint8Array so the ArrayBuffer contains exactly the fixture bytes,
// without the offset or extra capacity of Node's pooled Buffer.
export const OHTTP_KEYS = Uint8Array.from(
    Buffer.from(
        readFileSync(new URL("ohttp-keys.hex", fixtures), "ascii").trim(),
        "hex",
    ),
).buffer;
