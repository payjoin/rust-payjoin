import * as testUtils from "../test-utils/index.js";
import assert from "assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
    payjoin as nodejsPayjoin,
    uniffiInitAsync as nodejsUniffiInitAsync,
} from "payjoin";
import * as webPayjoinModule from "../dist/web/generated/payjoin.js";
import initWebAsync from "../dist/web/generated/wasm-bindgen/index.js";
import { InMemoryReceiverPersister, InMemorySenderPersister } from "./utils.ts";

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

interface Utxo {
    txid: string;
    vout: number;
    amount: number;
    scriptPubKey: string;
}

type PayjoinModule = typeof nodejsPayjoin;
const webPayjoin = webPayjoinModule as unknown as PayjoinModule;

type PJ<K extends keyof PayjoinModule> = PayjoinModule[K] extends {
    prototype: infer P;
}
    ? P
    : never;

type PJNested<
    K extends keyof PayjoinModule,
    N extends keyof PayjoinModule[K],
> = InstanceType<PayjoinModule[K][N] & (new (...args: any) => any)>;

class MempoolAcceptanceCallback {
    private connection: testUtils.RpcClient;

    constructor(connection: testUtils.RpcClient) {
        this.connection = connection;
    }

    callback(tx: ArrayBuffer): boolean {
        try {
            const hexTx = Buffer.from(tx).toString("hex");
            const resultJson = this.connection.call("testmempoolaccept", [
                JSON.stringify([hexTx]),
            ]);
            const decoded = JSON.parse(resultJson);
            return decoded[0].allowed === true;
        } catch {
            return false;
        }
    }
}

class IsScriptOwnedCallback {
    private connection: testUtils.RpcClient;

    constructor(connection: testUtils.RpcClient) {
        this.connection = connection;
    }

    callback(script: ArrayBuffer): boolean {
        try {
            const scriptHex = Buffer.from(script).toString("hex");
            const decodedScript = JSON.parse(
                this.connection.call("decodescript", [
                    JSON.stringify(scriptHex),
                ]),
            );

            const candidates: string[] = [];
            if (typeof decodedScript.address === "string") {
                candidates.push(decodedScript.address);
            }
            if (Array.isArray(decodedScript.addresses)) {
                candidates.push(
                    ...decodedScript.addresses.filter(
                        (addr: unknown): addr is string =>
                            typeof addr === "string",
                    ),
                );
            }
            if (
                decodedScript.segwit &&
                typeof decodedScript.segwit === "object"
            ) {
                const { address, addresses } = decodedScript.segwit as {
                    address?: unknown;
                    addresses?: unknown;
                };
                if (typeof address === "string") {
                    candidates.push(address);
                }
                if (Array.isArray(addresses)) {
                    candidates.push(
                        ...addresses.filter(
                            (addr: unknown): addr is string =>
                                typeof addr === "string",
                        ),
                    );
                }
            }

            for (const addr of candidates) {
                const info = JSON.parse(
                    this.connection.call("getaddressinfo", [
                        JSON.stringify(addr),
                    ]),
                );
                if (info.ismine === true) {
                    return true;
                }
            }
            return false;
        } catch {
            return false;
        }
    }
}

class CheckInputsNotSeenCallback {
    private connection: testUtils.RpcClient;

    constructor(connection: testUtils.RpcClient) {
        this.connection = connection;
    }

    callback(_outpoint: nodejsPayjoin.OutPoint): boolean {
        if (this.connection) {
        }
        return false;
    }
}

class ProcessPsbtCallback {
    private connection: testUtils.RpcClient;

    constructor(connection: testUtils.RpcClient) {
        this.connection = connection;
    }

    callback(psbt: string): string {
        const res = JSON.parse(
            this.connection.call("walletprocesspsbt", [psbt]),
        );
        return res.psbt;
    }
}

function buildSweepPsbt(
    sender: testUtils.RpcClient,
    pjUri: PJ<"PjUri">,
): string {
    const outputs: Record<string, number> = {};
    outputs[pjUri.address()] = 50;
    const psbt = JSON.parse(
        sender.call("walletcreatefundedpsbt", [
            JSON.stringify([]),
            JSON.stringify(outputs),
            JSON.stringify(0),
            JSON.stringify({
                lockUnspents: true,
                fee_rate: 10,
                subtractFeeFromOutputs: [0],
            }),
        ]),
    ).psbt;
    return JSON.parse(
        sender.call("walletprocesspsbt", [
            psbt,
            JSON.stringify(true),
            JSON.stringify("ALL"),
            JSON.stringify(false),
        ]),
    ).psbt;
}

function getInputs(
    payjoin: PayjoinModule,
    rpcConnection: testUtils.RpcClient,
): PJ<"InputPair">[] {
    const utxos: Utxo[] = JSON.parse(rpcConnection.call("listunspent", []));
    const inputs: PJ<"InputPair">[] = [];
    for (const utxo of utxos) {
        const txin = payjoin.TxIn.create({
            previousOutput: payjoin.OutPoint.create({
                txid: utxo.txid,
                vout: utxo.vout,
            }),
            scriptSig: new Uint8Array([]).buffer,
            sequence: 0,
            witness: [],
        });
        const txOut = payjoin.TxOut.create({
            valueSat: BigInt(Math.round(utxo.amount * 100_000_000)),
            // @ts-ignore
            scriptPubkey: Buffer.from(utxo.scriptPubKey, "hex"),
        });
        const psbtIn = payjoin.PsbtInput.create({
            witnessUtxo: txOut,
            redeemScript: undefined,
            witnessScript: undefined,
        });
        inputs.push(new payjoin.InputPair(txin, psbtIn, undefined));
    }
    return inputs;
}

class ReceiverProcessor {
    constructor(
        private readonly payjoin: PayjoinModule,
        private readonly receiver: testUtils.RpcClient,
        private readonly recvPersister: InMemoryReceiverPersister,
    ) {}

    private async processProvisionalProposal(
        proposal: PJ<"ProvisionalProposal">,
    ): Promise<PJ<"PayjoinProposal">> {
        return proposal
            .finalizeProposal(new ProcessPsbtCallback(this.receiver))
            .save(this.recvPersister) as PJ<"PayjoinProposal">;
    }

    private async processWantsFeeRange(
        proposal: PJ<"WantsFeeRange">,
    ): Promise<PJ<"PayjoinProposal">> {
        const provisionalProposal = proposal
            .applyFeeRange(1n, 10n)
            .save(this.recvPersister) as PJ<"ProvisionalProposal">;
        return this.processProvisionalProposal(provisionalProposal);
    }

    private async processWantsInputs(
        proposal: PJ<"WantsInputs">,
    ): Promise<PJ<"PayjoinProposal">> {
        const provisionalProposal = proposal
            .contributeInputs(getInputs(this.payjoin, this.receiver))
            .commitInputs()
            .save(this.recvPersister) as PJ<"WantsFeeRange">;
        return this.processWantsFeeRange(provisionalProposal);
    }

    private async processWantsOutputs(
        proposal: PJ<"WantsOutputs">,
    ): Promise<PJ<"PayjoinProposal">> {
        const wantsInputs = proposal
            .commitOutputs()
            .save(this.recvPersister) as PJ<"WantsInputs">;
        return this.processWantsInputs(wantsInputs);
    }

    private async processOutputsUnknown(
        proposal: PJ<"OutputsUnknown">,
    ): Promise<PJ<"PayjoinProposal">> {
        const wantsOutputs = proposal
            .identifyReceiverOutputs(new IsScriptOwnedCallback(this.receiver))
            .save(this.recvPersister) as PJ<"WantsOutputs">;
        return this.processWantsOutputs(wantsOutputs);
    }

    private async processMaybeInputsSeen(
        proposal: PJ<"MaybeInputsSeen">,
    ): Promise<PJ<"PayjoinProposal">> {
        const outputsUnknown = proposal
            .checkNoInputsSeenBefore(
                new CheckInputsNotSeenCallback(this.receiver),
            )
            .save(this.recvPersister) as PJ<"OutputsUnknown">;
        return this.processOutputsUnknown(outputsUnknown);
    }

    private async processMaybeInputsOwned(
        proposal: nodejsPayjoin.MaybeInputsOwned,
    ): Promise<PJ<"PayjoinProposal">> {
        const maybeInputsSeen = proposal
            .checkInputsNotOwned(new IsScriptOwnedCallback(this.receiver))
            .save(this.recvPersister) as PJ<"MaybeInputsSeen">;
        return this.processMaybeInputsSeen(maybeInputsSeen);
    }

    private async processUncheckedProposal(
        proposal: PJ<"UncheckedOriginalPayload">,
    ): Promise<PJ<"PayjoinProposal">> {
        const maybeInputsOwned = proposal
            .checkBroadcastSuitability(
                undefined,
                new MempoolAcceptanceCallback(this.receiver),
            )
            .save(this.recvPersister) as PJ<"MaybeInputsOwned">;
        return this.processMaybeInputsOwned(maybeInputsOwned);
    }

    createReceiverContext(
        address: string,
        directory: string,
        ohttpKeys: ReturnType<PayjoinModule["OhttpKeys"]["decode"]>,
    ): PJ<"Initialized"> {
        return new this.payjoin.ReceiverBuilder(address, directory, ohttpKeys)
            .build()
            .save(this.recvPersister) as PJ<"Initialized">;
    }

    private async retrieveReceiverProposal(
        session: PJ<"Initialized">,
        ohttpRelay: string,
    ): Promise<PJ<"PayjoinProposal"> | null> {
        const request = session.createPollRequest(ohttpRelay);
        const response = await fetch(request.request.url, {
            method: "POST",
            headers: { "Content-Type": request.request.contentType },
            body: request.request.body,
        });
        const responseBuffer = await response.arrayBuffer();
        const res = session
            .processResponse(responseBuffer, request.clientResponse)
            .save(this.recvPersister);

        if (res instanceof this.payjoin.InitializedTransitionOutcome.Stasis) {
            return null;
        } else if (
            res instanceof this.payjoin.InitializedTransitionOutcome.Progress
        ) {
            return this.processUncheckedProposal(
                res.inner.inner as PJ<"UncheckedOriginalPayload">,
            );
        }

        throw new Error(`Unknown initialized transition outcome`);
    }

    async processReceiverProposal(
        receiver:
            | PJ<"Initialized">
            | PJ<"UncheckedOriginalPayload">
            | PJ<"MaybeInputsOwned">
            | PJ<"MaybeInputsSeen">
            | PJ<"OutputsUnknown">
            | PJ<"WantsOutputs">
            | PJ<"WantsInputs">
            | PJ<"WantsFeeRange">
            | PJ<"ProvisionalProposal">
            | PJ<"PayjoinProposal">,
        ohttpRelay: string,
    ): Promise<PJ<"PayjoinProposal"> | null> {
        if (receiver instanceof this.payjoin.Initialized) {
            return this.retrieveReceiverProposal(receiver, ohttpRelay);
        }
        if (receiver instanceof this.payjoin.UncheckedOriginalPayload) {
            return this.processUncheckedProposal(receiver);
        }
        if (receiver instanceof this.payjoin.MaybeInputsOwned) {
            return this.processMaybeInputsOwned(receiver);
        }
        if (receiver instanceof this.payjoin.MaybeInputsSeen) {
            return this.processMaybeInputsSeen(receiver);
        }
        if (receiver instanceof this.payjoin.OutputsUnknown) {
            return this.processOutputsUnknown(receiver);
        }
        if (receiver instanceof this.payjoin.WantsOutputs) {
            return this.processWantsOutputs(receiver);
        }
        if (receiver instanceof this.payjoin.WantsInputs) {
            return this.processWantsInputs(receiver);
        }
        if (receiver instanceof this.payjoin.WantsFeeRange) {
            return this.processWantsFeeRange(receiver);
        }
        if (receiver instanceof this.payjoin.ProvisionalProposal) {
            return this.processProvisionalProposal(receiver);
        }
        if (receiver instanceof this.payjoin.PayjoinProposal) {
            return receiver;
        }

        throw new Error(`Unknown receiver state`);
    }
}

function testFfiValidation(payjoin: PayjoinModule): void {
    const tooLargeAmount = 21000000n * 100000000n + 1n;

    // Invalid outpoint (txid too long) should fail before amount checks.
    const invalidOutpointTxIn = payjoin.TxIn.create({
        previousOutput: payjoin.OutPoint.create({
            txid: "00".repeat(64), // 64 bytes -> invalid
            vout: 0,
        }),
        scriptSig: new Uint8Array([]).buffer,
        sequence: 0,
        witness: [],
    });
    const txout = payjoin.TxOut.create({
        valueSat: tooLargeAmount,
        scriptPubkey: new Uint8Array([0x6a]).buffer,
    });
    const psbtIn = payjoin.PsbtInput.create({
        witnessUtxo: txout,
        redeemScript: undefined,
        witnessScript: undefined,
    });
    assert.throws(() => {
        new payjoin.InputPair(invalidOutpointTxIn, psbtIn, undefined);
    }, /InvalidOutPoint/);

    // Valid outpoint hits amount overflow validation.
    const amountOverflowTxIn = payjoin.TxIn.create({
        previousOutput: payjoin.OutPoint.create({
            txid: "00".repeat(32), // valid 32-byte txid
            vout: 0,
        }),
        scriptSig: new Uint8Array([]).buffer,
        sequence: 0,
        witness: [],
    });
    try {
        new payjoin.InputPair(amountOverflowTxIn, psbtIn, undefined);
        assert.fail("Expected AmountOutOfRange error");
    } catch (e) {
        const [inner] = payjoin.InputPairError.FfiValidation.getInner(e);
        assert.strictEqual(inner.tag, "AmountOutOfRange");
    }

    // Oversized script_pubkey should fail.
    const hugeScript = new Uint8Array(10_001).fill(0x51).buffer;
    const oversizedTxOut = payjoin.TxOut.create({
        valueSat: 1n,
        scriptPubkey: hugeScript,
    });
    const oversizedPsbtIn = payjoin.PsbtInput.create({
        witnessUtxo: oversizedTxOut,
        redeemScript: undefined,
        witnessScript: undefined,
    });
    try {
        new payjoin.InputPair(amountOverflowTxIn, oversizedPsbtIn, undefined);
        assert.fail("Expected ScriptTooLarge error");
    } catch (e) {
        const [inner] = payjoin.InputPairError.FfiValidation.getInner(e);
        assert.strictEqual(inner.tag, "ScriptTooLarge");
    }

    // Weight must be positive and <= block weight.
    const smallTxOut = payjoin.TxOut.create({
        valueSat: 1n,
        scriptPubkey: new Uint8Array([0x6a]).buffer,
    });
    const smallPsbtIn = payjoin.PsbtInput.create({
        witnessUtxo: smallTxOut,
        redeemScript: undefined,
        witnessScript: undefined,
    });
    try {
        new payjoin.InputPair(
            amountOverflowTxIn,
            smallPsbtIn,
            payjoin.Weight.create({ weightUnits: 0n }),
        );
        assert.fail("Expected WeightOutOfRange error");
    } catch (e) {
        const [inner] = payjoin.InputPairError.FfiValidation.getInner(e);
        assert.strictEqual(inner.tag, "WeightOutOfRange");
    }

    const pjUri = payjoin.Uri.parse(
        "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com",
    ).checkPjSupported();
    const psbt = testUtils.originalPsbt();
    assert.throws(() => {
        new payjoin.SenderBuilder(psbt, pjUri).buildRecommended(
            18446744073709551615n,
        );
    }, /RuntimeError/);

    assert.throws(() => {
        pjUri.setAmountSats(tooLargeAmount);
    }, /AmountOutOfRange/);
}

async function testIntegrationV2ToV2(payjoin: PayjoinModule): Promise<void> {
    const env = testUtils.initBitcoindSenderReceiver();
    const receiver = env.getReceiver();
    const sender = env.getSender();

    const receiverAddressJson = receiver.call("getnewaddress", []);
    const receiverAddress = JSON.parse(receiverAddressJson);

    const services = new testUtils.TestServices();
    const directory = services.directoryUrl();
    const ohttpRelay = services.ohttpRelayUrl();
    services.waitForServicesReady();
    const ohttpKeysBytes = services.fetchOhttpKeys();
    const ohttpKeys = payjoin.OhttpKeys.decode(
        ohttpKeysBytes.buffer as ArrayBuffer,
    );

    const recvPersister = new InMemoryReceiverPersister();
    const recvProcessor = new ReceiverProcessor(
        payjoin,
        receiver,
        recvPersister,
    );
    const senderPersister = new InMemorySenderPersister();

    const session = recvProcessor.createReceiverContext(
        receiverAddress,
        directory,
        ohttpKeys,
    );

    const processResponse = await recvProcessor.processReceiverProposal(
        session,
        ohttpRelay,
    );
    assert.strictEqual(
        processResponse,
        null,
        "Initial proposal should be null",
    );

    const pjUri = session.pjUri();
    const psbt = buildSweepPsbt(sender, pjUri as PJ<"PjUri">);
    const reqCtx = new payjoin.SenderBuilder(psbt, pjUri)
        .buildRecommended(1000n)
        .save(senderPersister);

    const request = reqCtx.createV2PostRequest(ohttpRelay);
    const response = await fetch(request.request.url, {
        method: "POST",
        headers: { "Content-Type": request.request.contentType },
        body: request.request.body,
    });
    const responseBuffer = await response.arrayBuffer();
    const sendCtx = reqCtx
        .processResponse(responseBuffer, request.ohttpCtx)
        .save(senderPersister);

    const payjoinProposal = await recvProcessor.processReceiverProposal(
        session,
        ohttpRelay,
    );
    assert.notStrictEqual(
        payjoinProposal,
        null,
        "Payjoin proposal should not be null",
    );
    assert(
        payjoinProposal instanceof payjoin.PayjoinProposal,
        "Should be a payjoin proposal",
    );

    const proposal = payjoinProposal;
    const requestResponse = proposal.createPostRequest(ohttpRelay);
    const fallbackResponse = await fetch(requestResponse.request.url, {
        method: "POST",
        headers: { "Content-Type": requestResponse.request.contentType },
        body: requestResponse.request.body,
    });
    const fallbackResponseBuffer = await fallbackResponse.arrayBuffer();
    proposal.processResponse(
        fallbackResponseBuffer,
        requestResponse.clientResponse,
    );

    let pollOutcome:
        | PJNested<"PollingForProposalTransitionOutcome", "Progress">
        | PJNested<"PollingForProposalTransitionOutcome", "Stasis">;
    let attempts = 0;
    while (true) {
        const ohttpContextRequest = sendCtx.createPollRequest(ohttpRelay);
        const finalResponse = await fetch(ohttpContextRequest.request.url, {
            method: "POST",
            headers: {
                "Content-Type": ohttpContextRequest.request.contentType,
            },
            body: ohttpContextRequest.request.body,
        });
        const finalResponseBuffer = await finalResponse.arrayBuffer();
        pollOutcome = sendCtx
            .processResponse(finalResponseBuffer, ohttpContextRequest.ohttpCtx)
            .save(senderPersister);

        if (
            pollOutcome instanceof
            payjoin.PollingForProposalTransitionOutcome.Progress
        ) {
            break;
        }
        attempts += 1;
        if (attempts >= 3) {
            return;
        }
    }

    const payjoinPsbt = JSON.parse(
        sender.call("walletprocesspsbt", [pollOutcome.inner.psbtBase64]),
    ).psbt;
    const finalPsbtJson = JSON.parse(
        sender.call("finalizepsbt", [payjoinPsbt, JSON.stringify(false)]),
    );
    const finalPsbt = finalPsbtJson.psbt as string;
    const extraction = JSON.parse(
        sender.call("finalizepsbt", [payjoinPsbt, JSON.stringify(true)]),
    );
    const finalHex = extraction.hex as string;
    sender.call("sendrawtransaction", [JSON.stringify(finalHex)]);

    const decodedPsbt = JSON.parse(
        sender.call("decodepsbt", [JSON.stringify(finalPsbt)]),
    );
    const networkFees = Number(decodedPsbt.fee);
    const decodedTx = JSON.parse(
        sender.call("decoderawtransaction", [JSON.stringify(finalHex)]),
    );
    assert.strictEqual(decodedTx.vin.length, 2, "Should have 2 inputs");
    assert.strictEqual(decodedTx.vout.length, 1, "Should have 1 output");

    const receiverBalance = JSON.parse(receiver.call("getbalances", [])).mine
        .untrusted_pending;
    assert.strictEqual(
        receiverBalance,
        100 - networkFees,
        "Receiver balance should be 100 - network fees",
    );

    const senderBalance = JSON.parse(sender.call("getbalance", []));
    assert.strictEqual(senderBalance, 0.0, "Sender balance should be 0");
}

async function runTests(): Promise<void> {
    await nodejsUniffiInitAsync();
    testFfiValidation(nodejsPayjoin);
    await testIntegrationV2ToV2(nodejsPayjoin);

    await webUniffiInitAsync();
    testFfiValidation(webPayjoin);
    await testIntegrationV2ToV2(webPayjoin);
}

runTests().catch((error: unknown) => {
    console.error("\n✗ Integration test failed:", error);
    process.exit(1);
});
