import { ORIGINAL_PSBT, OHTTP_KEYS } from "./fixtures.ts";
import { describe, test, before } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
    payjoin as nodejsPayjoin,
    uniffiInitAsync as nodejsUniffiInitAsync,
} from "payjoin";
import * as webPayjoinModule from "../src/web/generated/payjoin.js";
import initWebAsync from "../src/web/generated/wasm-bindgen/index.js";
import {
    InMemoryReceiverPersister,
    InMemoryReceiverPersisterAsync,
    InMemorySenderPersister,
    InMemorySenderPersisterAsync,
} from "./utils.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function webUniffiInitAsync() {
    const wasmPath = join(
        __dirname,
        "../src/web/generated/wasm-bindgen/index_bg.wasm",
    );
    const wasmBytes = readFileSync(wasmPath);
    await initWebAsync({ module_or_path: wasmBytes });
    webPayjoinModule.default.initialize();
}

function runUnitTests(name: string, payjoin: typeof nodejsPayjoin) {
    describe(`[${name}] URI tests`, () => {
        test("URL encoded payjoin parameter", () => {
            const uri =
                "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
            const result = payjoin.Url.parse(uri);
            assert.ok(result, "pj url should be url encoded");
        });

        test("valid URL", () => {
            const uri =
                "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
            const result = payjoin.Url.parse(uri);
            assert.ok(result, "pj is not a valid url");
        });

        test("missing amount should be ok", () => {
            const uri =
                "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
            const result = payjoin.Url.parse(uri);
            assert.ok(result, "missing amount should be ok");
        });

        test("valid URIs with different addresses and endpoints", () => {
            const https = "https://example.com";
            const onion =
                "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion";

            const base58 = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
            const bech32Upper =
                "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
            const bech32Lower =
                "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

            const addresses = [base58, bech32Upper, bech32Lower];
            const pjs = [https, onion];

            for (const address of addresses) {
                for (const pj of pjs) {
                    const uri = `${address}?amount=1&pj=${pj}`;
                    assert.doesNotThrow(
                        () => payjoin.Url.parse(uri),
                        `Failed to create a valid Uri for ${uri}`,
                    );
                }
            }
        });
    });

    describe(`[${name}] Persistence tests`, () => {
        test("receiver persistence", () => {
            const persister = new InMemoryReceiverPersister();
            const address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
            const ohttpKeys = payjoin.OhttpKeys.decode(OHTTP_KEYS);

            const builder = new payjoin.ReceiverBuilder(
                address,
                "https://example.com",
                ohttpKeys,
            );
            builder.build().save(persister);

            const result = payjoin.replayReceiverEventLog(persister);
            const state = result.state();

            assert.strictEqual(
                state.tag,
                "Initialized",
                "State should be Initialized",
            );
        });

        test("sender persistence", () => {
            const persister = new InMemoryReceiverPersister();
            const address = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
            const ohttpKeys = payjoin.OhttpKeys.decode(OHTTP_KEYS);

            const receiver = new payjoin.ReceiverBuilder(
                address,
                "https://example.com",
                ohttpKeys,
            )
                .build()
                .save(persister);
            const uri = receiver.pjUri();

            const senderPersister = new InMemorySenderPersister();
            const withReplyKey = new payjoin.SenderBuilder(ORIGINAL_PSBT, uri)
                .buildRecommended(BigInt(1000))
                .save(senderPersister);

            assert.ok(withReplyKey, "Sender should be created successfully");
        });
    });

    describe(`[${name}] Receiver cancel tests`, () => {
        test("receiver cancel from initialized", () => {
            const persister = new InMemoryReceiverPersister();
            const address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
            const ohttpKeys = payjoin.OhttpKeys.decode(OHTTP_KEYS);

            const initialized = new payjoin.ReceiverBuilder(
                address,
                "https://example.com",
                ohttpKeys,
            )
                .build()
                .save(persister);
            const cancelTransition = initialized.cancel();
            const fallbackTx = cancelTransition.save(persister);
            assert.strictEqual(fallbackTx, undefined);

            const result = payjoin.replayReceiverEventLog(persister);
            const state = result.state();
            assert.strictEqual(
                state.tag,
                "Closed",
                "State should be Closed after cancel",
            );
        });

        test("receiver cancel async from initialized", async () => {
            const persister = new InMemoryReceiverPersisterAsync();
            const address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
            const ohttpKeys = payjoin.OhttpKeys.decode(OHTTP_KEYS);

            const initialized = await new payjoin.ReceiverBuilder(
                address,
                "https://example.com",
                ohttpKeys,
            )
                .build()
                .saveAsync(persister);
            const cancelTransition = initialized.cancel();
            const fallbackTx = await cancelTransition.saveAsync(persister);
            assert.strictEqual(fallbackTx, undefined);

            const result = await payjoin.replayReceiverEventLogAsync(persister);
            const state = result.state();
            assert.strictEqual(
                state.tag,
                "Closed",
                "State should be Closed after cancel",
            );
        });
    });

    describe(`[${name}] Sender cancel tests`, () => {
        test("sender cancel from with reply key", () => {
            const persister = new InMemoryReceiverPersister();
            const address = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
            const ohttpKeys = payjoin.OhttpKeys.decode(OHTTP_KEYS);

            const receiver = new payjoin.ReceiverBuilder(
                address,
                "https://example.com",
                ohttpKeys,
            )
                .build()
                .save(persister);
            const uri = receiver.pjUri();

            const senderPersister = new InMemorySenderPersister();
            const withReplyKey = new payjoin.SenderBuilder(ORIGINAL_PSBT, uri)
                .buildRecommended(BigInt(1000))
                .save(senderPersister);

            const cancelTransition = withReplyKey.cancel();
            const pendingFallback = cancelTransition.save(senderPersister);
            assert.ok(pendingFallback, "pending fallback should be returned");
            assert.ok(
                pendingFallback.fallbackTx().byteLength > 0,
                "fallback tx bytes should be non-empty",
            );

            const cancelledResult =
                payjoin.replaySenderEventLog(senderPersister);
            assert.strictEqual(
                cancelledResult.state().tag,
                "SenderPendingFallback",
                "State should be SenderPendingFallback after cancel",
            );

            pendingFallback.close().save(senderPersister);
            const closedResult = payjoin.replaySenderEventLog(senderPersister);
            assert.strictEqual(
                closedResult.state().tag,
                "Closed",
                "State should be Closed after close",
            );
        });

        test("sender cancel async from with reply key", async () => {
            const persister = new InMemoryReceiverPersisterAsync();
            const address = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
            const ohttpKeys = payjoin.OhttpKeys.decode(OHTTP_KEYS);

            const receiver = await new payjoin.ReceiverBuilder(
                address,
                "https://example.com",
                ohttpKeys,
            )
                .build()
                .saveAsync(persister);
            const uri = receiver.pjUri();

            const senderPersister = new InMemorySenderPersisterAsync();
            const withReplyKey = await new payjoin.SenderBuilder(
                ORIGINAL_PSBT,
                uri,
            )
                .buildRecommended(BigInt(1000))
                .saveAsync(senderPersister);

            const cancelTransition = withReplyKey.cancel();
            const pendingFallback =
                await cancelTransition.saveAsync(senderPersister);
            assert.ok(pendingFallback, "pending fallback should be returned");
            assert.ok(
                pendingFallback.fallbackTx().byteLength > 0,
                "fallback tx bytes should be non-empty",
            );

            const cancelledResult =
                await payjoin.replaySenderEventLogAsync(senderPersister);
            assert.strictEqual(
                cancelledResult.state().tag,
                "SenderPendingFallback",
                "State should be SenderPendingFallback after cancel",
            );

            await pendingFallback.close().saveAsync(senderPersister);
            const closedResult =
                await payjoin.replaySenderEventLogAsync(senderPersister);
            assert.strictEqual(
                closedResult.state().tag,
                "Closed",
                "State should be Closed after close",
            );
        });
    });

    describe(`[${name}] Async Persistence tests`, () => {
        test("receiver async persistence", async () => {
            const persister = new InMemoryReceiverPersisterAsync();
            const address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
            const ohttpKeys = payjoin.OhttpKeys.decode(OHTTP_KEYS);

            const builder = new payjoin.ReceiverBuilder(
                address,
                "https://example.com",
                ohttpKeys,
            );
            await builder.build().saveAsync(persister);

            const result = await payjoin.replayReceiverEventLogAsync(persister);
            const state = result.state();

            assert.strictEqual(
                state.tag,
                "Initialized",
                "State should be Initialized",
            );
        });

        test("sender async persistence", async () => {
            const persister = new InMemoryReceiverPersisterAsync();
            const address = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
            const ohttpKeys = payjoin.OhttpKeys.decode(OHTTP_KEYS);

            const receiver = await new payjoin.ReceiverBuilder(
                address,
                "https://example.com",
                ohttpKeys,
            )
                .build()
                .saveAsync(persister);
            const uri = receiver.pjUri();

            const senderPersister = new InMemorySenderPersisterAsync();
            const withReplyKey = await new payjoin.SenderBuilder(
                ORIGINAL_PSBT,
                uri,
            )
                .buildRecommended(BigInt(1000))
                .saveAsync(senderPersister);

            assert.ok(withReplyKey, "Sender should be created successfully");
        });
    });

    describe(`[${name}] Validation`, () => {
        test("receiver builder rejects bad address", () => {
            assert.throws(() => {
                new payjoin.ReceiverBuilder(
                    "not-an-address",
                    "https://example.com",
                    payjoin.OhttpKeys.decode(OHTTP_KEYS),
                );
            });
        });

        test("input pair rejects invalid outpoint", () => {
            assert.throws(() => {
                const txin = payjoin.TxIn.create({
                    previousOutput: payjoin.OutPoint.create({
                        txid: "deadbeef",
                        vout: 0,
                    }),
                    scriptSig: new Uint8Array([]).buffer,
                    sequence: 0,
                    witness: [],
                });
                const psbtIn = payjoin.PsbtInput.create({
                    witnessUtxo: undefined,
                    redeemScript: undefined,
                    witnessScript: undefined,
                });
                new payjoin.InputPair(txin, psbtIn, undefined);
            });
        });

        test("sender builder rejects bad psbt", () => {
            assert.throws(() => {
                new payjoin.SenderBuilder(
                    "not-a-psbt",
                    payjoin.Uri.parse(
                        "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
                    ).checkPjSupported(),
                );
            });
        });
    });
}

before(async () => {
    await nodejsUniffiInitAsync();
    await webUniffiInitAsync();
});

runUnitTests("nodejs", nodejsPayjoin);
runUnitTests("web", webPayjoinModule as unknown as typeof nodejsPayjoin);
