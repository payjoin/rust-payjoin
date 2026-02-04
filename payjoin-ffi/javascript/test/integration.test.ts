import { payjoin, uniffiInitAsync } from "../dist/index.js";
import * as testUtils from "../test-utils/index.js";
import assert from "assert";

interface Utxo {
    txid: string;
    vout: number;
    amount: number;
    scriptPubKey: string;
}

class InMemoryReceiverPersister
    implements payjoin.JsonReceiverSessionPersister
{
    private id: string;
    private events: string[] = [];
    private closed: boolean = false;
    public connection?: testUtils.RpcClient;

    constructor(id: string) {
        this.id = id;
    }

    save(event: string): void {
        this.events.push(event);
    }

    load(): string[] {
        return this.events;
    }

    close(): void {
        this.closed = true;
    }
}

class InMemorySenderPersister implements payjoin.JsonSenderSessionPersister {
    private id: string;
    private events: string[] = [];
    private closed: boolean = false;

    constructor(id: string) {
        this.id = id;
    }

    save(event: string): void {
        this.events.push(event);
    }

    load(): string[] {
        return this.events;
    }

    close(): void {
        this.closed = true;
    }
}

class MempoolAcceptanceCallback implements payjoin.CanBroadcast {
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

class IsScriptOwnedCallback implements payjoin.IsScriptOwned {
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

class CheckInputsNotSeenCallback implements payjoin.IsOutputKnown {
    private connection: testUtils.RpcClient;

    constructor(connection: testUtils.RpcClient) {
        this.connection = connection;
    }

    callback(_outpoint: ArrayBuffer): boolean {
        return false;
    }
}

class ProcessPsbtCallback implements payjoin.ProcessPsbt {
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

function createReceiverContext(
    address: string,
    directory: string,
    ohttpKeys: payjoin.OhttpKeys,
    persister: InMemoryReceiverPersister,
): payjoin.Initialized {
    const receiver = new payjoin.ReceiverBuilder(address, directory, ohttpKeys)
        .build()
        .save(persister);
    return receiver;
}

function buildSweepPsbt(
    sender: testUtils.RpcClient,
    pjUri: payjoin.PjUri,
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

function getInputs(rpcConnection: testUtils.RpcClient): payjoin.InputPair[] {
    const utxos: Utxo[] = JSON.parse(rpcConnection.call("listunspent", []));
    const inputs: payjoin.InputPair[] = [];
    for (const utxo of utxos) {
        const txin = payjoin.PlainTxIn.create({
            previousOutput: payjoin.PlainOutPoint.create({
                txid: utxo.txid,
                vout: utxo.vout,
            }),
            scriptSig: new Uint8Array([]),
            sequence: 0,
            witness: [],
        });
        const txOut = payjoin.PlainTxOut.create({
            valueSat: BigInt(Math.round(utxo.amount * 100_000_000)),
            scriptPubkey: Buffer.from(utxo.scriptPubKey, "hex"),
        });
        const psbtIn = payjoin.PlainPsbtInput.create({
            witnessUtxo: txOut,
            redeemScript: undefined,
            witnessScript: undefined,
        });
        inputs.push(new payjoin.InputPair(txin, psbtIn, undefined));
    }
    return inputs;
}

async function processProvisionalProposal(
    proposal: payjoin.ProvisionalProposal,
    receiver: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
): Promise<payjoin.PayjoinProposal> {
    const payjoinProposal = proposal
        .finalizeProposal(new ProcessPsbtCallback(receiver))
        .save(recvPersister);
    return payjoinProposal;
}

async function processWantsFeeRange(
    proposal: payjoin.WantsFeeRange,
    receiver: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
): Promise<payjoin.PayjoinProposal> {
    const wantsFeeRange = proposal.applyFeeRange(1n, 10n).save(recvPersister);
    return await processProvisionalProposal(
        wantsFeeRange,
        receiver,
        recvPersister,
    );
}

async function processWantsInputs(
    proposal: payjoin.WantsInputs,
    receiver: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
): Promise<payjoin.PayjoinProposal> {
    const provisionalProposal = proposal
        .contributeInputs(getInputs(receiver))
        .commitInputs()
        .save(recvPersister);
    return await processWantsFeeRange(
        provisionalProposal,
        receiver,
        recvPersister,
    );
}

async function processWantsOutputs(
    proposal: payjoin.WantsOutputs,
    receiver: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
): Promise<payjoin.PayjoinProposal> {
    const wantsInputs = proposal.commitOutputs().save(recvPersister);
    return await processWantsInputs(wantsInputs, receiver, recvPersister);
}

async function processOutputsUnknown(
    proposal: payjoin.OutputsUnknown,
    receiver: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
): Promise<payjoin.PayjoinProposal> {
    const wantsOutputs = proposal
        .identifyReceiverOutputs(new IsScriptOwnedCallback(receiver))
        .save(recvPersister);
    return await processWantsOutputs(wantsOutputs, receiver, recvPersister);
}

async function processMaybeInputsSeen(
    proposal: payjoin.MaybeInputsSeen,
    receiver: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
): Promise<payjoin.PayjoinProposal> {
    const outputsUnknown = proposal
        .checkNoInputsSeenBefore(new CheckInputsNotSeenCallback(receiver))
        .save(recvPersister);
    return await processOutputsUnknown(outputsUnknown, receiver, recvPersister);
}

async function processMaybeInputsOwned(
    proposal: payjoin.MaybeInputsOwned,
    receiver: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
): Promise<payjoin.PayjoinProposal> {
    const maybeInputsOwned = proposal
        .checkInputsNotOwned(new IsScriptOwnedCallback(receiver))
        .save(recvPersister);
    return await processMaybeInputsSeen(
        maybeInputsOwned,
        receiver,
        recvPersister,
    );
}

async function processUncheckedProposal(
    proposal: payjoin.UncheckedOriginalPayload,
    receiver: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
): Promise<payjoin.PayjoinProposal> {
    const uncheckedProposal = proposal
        .checkBroadcastSuitability(
            undefined,
            new MempoolAcceptanceCallback(receiver),
        )
        .save(recvPersister);
    return await processMaybeInputsOwned(
        uncheckedProposal,
        receiver,
        recvPersister,
    );
}

async function retrieveReceiverProposal(
    receiver: payjoin.Initialized,
    recvPersister: InMemoryReceiverPersister,
    ohttpRelay: string,
): Promise<payjoin.PayjoinProposal | null> {
    const request = receiver.createPollRequest(ohttpRelay);
    const response = await fetch(request.request.url, {
        method: "POST",
        headers: { "Content-Type": request.request.contentType },
        body: request.request.body,
    });
    const responseBuffer = await response.arrayBuffer();
    const res = receiver
        .processResponse(responseBuffer, request.clientResponse)
        .save(recvPersister);

    if (res instanceof payjoin.InitializedTransitionOutcome.Stasis) {
        return null;
    } else if (res instanceof payjoin.InitializedTransitionOutcome.Progress) {
        const proposal = res.inner.inner;
        return await processUncheckedProposal(
            proposal,
            recvPersister.connection!,
            recvPersister,
        );
    }

    throw new Error(`Unknown initialized transition outcome`);
}

async function processReceiverProposal(
    receiver:
        | payjoin.Initialized
        | payjoin.UncheckedOriginalPayload
        | payjoin.MaybeInputsOwned
        | payjoin.MaybeInputsSeen
        | payjoin.OutputsUnknown
        | payjoin.WantsOutputs
        | payjoin.WantsInputs
        | payjoin.WantsFeeRange
        | payjoin.ProvisionalProposal
        | payjoin.PayjoinProposal,
    receiverRpc: testUtils.RpcClient,
    recvPersister: InMemoryReceiverPersister,
    ohttpRelay: string,
): Promise<payjoin.PayjoinProposal | null> {
    if (receiver instanceof payjoin.Initialized) {
        const res = await retrieveReceiverProposal(
            receiver,
            recvPersister,
            ohttpRelay,
        );
        if (res === null) {
            return null;
        }
        return res;
    }

    if (receiver instanceof payjoin.UncheckedOriginalPayload) {
        return await processUncheckedProposal(
            receiver,
            receiverRpc,
            recvPersister,
        );
    }
    if (receiver instanceof payjoin.MaybeInputsOwned) {
        return await processMaybeInputsOwned(
            receiver,
            receiverRpc,
            recvPersister,
        );
    }
    if (receiver instanceof payjoin.MaybeInputsSeen) {
        return await processMaybeInputsSeen(
            receiver,
            receiverRpc,
            recvPersister,
        );
    }
    if (receiver instanceof payjoin.OutputsUnknown) {
        return await processOutputsUnknown(
            receiver,
            receiverRpc,
            recvPersister,
        );
    }
    if (receiver instanceof payjoin.WantsOutputs) {
        return await processWantsOutputs(receiver, receiverRpc, recvPersister);
    }
    if (receiver instanceof payjoin.WantsInputs) {
        return await processWantsInputs(receiver, receiverRpc, recvPersister);
    }
    if (receiver instanceof payjoin.WantsFeeRange) {
        return await processWantsFeeRange(receiver, receiverRpc, recvPersister);
    }
    if (receiver instanceof payjoin.ProvisionalProposal) {
        return await processProvisionalProposal(
            receiver,
            receiverRpc,
            recvPersister,
        );
    }
    if (receiver instanceof payjoin.PayjoinProposal) {
        return receiver;
    }

    throw new Error(`Unknown receiver state`);
}

function testInvalidPrimitives(): void {
    const tooLargeAmount = 21000000n * 100000000n + 1n;

    // Invalid outpoint (txid too long) should fail before amount checks.
    const invalidOutpointTxIn = payjoin.PlainTxIn.create({
        previousOutput: payjoin.PlainOutPoint.create({
            txid: "00".repeat(64), // 64 bytes -> invalid
            vout: 0,
        }),
        scriptSig: new Uint8Array([]).buffer,
        sequence: 0,
        witness: [],
    });
    const txout = payjoin.PlainTxOut.create({
        valueSat: tooLargeAmount,
        scriptPubkey: new Uint8Array([0x6a]).buffer,
    });
    const psbtIn = payjoin.PlainPsbtInput.create({
        witnessUtxo: txout,
        redeemScript: undefined,
        witnessScript: undefined,
    });
    assert.throws(() => {
        new payjoin.InputPair(invalidOutpointTxIn, psbtIn, undefined);
    }, /InvalidOutPoint/);

    // Valid outpoint hits amount overflow validation.
    const amountOverflowTxIn = payjoin.PlainTxIn.create({
        previousOutput: payjoin.PlainOutPoint.create({
            txid: "00".repeat(32), // valid 32-byte txid
            vout: 0,
        }),
        scriptSig: new Uint8Array([]).buffer,
        sequence: 0,
        witness: [],
    });
    assert.throws(() => {
        new payjoin.InputPair(amountOverflowTxIn, psbtIn, undefined);
    }, /(Amount out of range|AmountOutOfRange)/);

    // Oversized script_pubkey should fail.
    const hugeScript = new Uint8Array(10_001).fill(0x51).buffer;
    const oversizedTxOut = payjoin.PlainTxOut.create({
        valueSat: 1n,
        scriptPubkey: hugeScript,
    });
    const oversizedPsbtIn = payjoin.PlainPsbtInput.create({
        witnessUtxo: oversizedTxOut,
        redeemScript: undefined,
        witnessScript: undefined,
    });
    assert.throws(() => {
        new payjoin.InputPair(amountOverflowTxIn, oversizedPsbtIn, undefined);
    }, /(ScriptTooLarge|script too large|InvalidPrimitive)/);

    // Weight must be positive and <= block weight.
    const smallTxOut = payjoin.PlainTxOut.create({
        valueSat: 1n,
        scriptPubkey: new Uint8Array([0x6a]).buffer,
    });
    const smallPsbtIn = payjoin.PlainPsbtInput.create({
        witnessUtxo: smallTxOut,
        redeemScript: undefined,
        witnessScript: undefined,
    });
    assert.throws(() => {
        new payjoin.InputPair(
            amountOverflowTxIn,
            smallPsbtIn,
            payjoin.PlainWeight.create({ weightUnits: 0n }),
        );
    }, /(WeightOutOfRange|Weight out of range|InvalidPsbtInput|InvalidPrimitive)/);

    const pjUri = payjoin.Uri.parse(
        "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com",
    ).checkPjSupported();
    const psbt =
        "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
    assert.throws(() => {
        new payjoin.SenderBuilder(psbt, pjUri).buildRecommended(
            18446744073709551615n,
        );
    }, /(Fee rate out of range|RuntimeError)/);

    assert.throws(() => {
        pjUri.setAmountSats(tooLargeAmount);
    }, /(Amount out of range|AmountOutOfRange)/);
}

async function testIntegrationV2ToV2(): Promise<void> {
    const env = testUtils.initBitcoindSenderReceiver();
    const bitcoind = env.getBitcoind();
    const receiver = env.getReceiver();
    const sender = env.getSender();

    const receiverAddressJson = receiver.call("getnewaddress", []);
    const receiverAddress = JSON.parse(receiverAddressJson);

    const services = new testUtils.TestServices();
    const directory = services.directoryUrl();
    const ohttpRelay = services.ohttpRelayUrl();
    services.waitForServicesReady();
    const ohttpKeysBytes = services.fetchOhttpKeys();
    const ohttpKeys = payjoin.OhttpKeys.decode(ohttpKeysBytes.buffer);

    const recvPersister = new InMemoryReceiverPersister("1");
    const senderPersister = new InMemorySenderPersister("1");
    recvPersister.connection = receiver;

    const session = createReceiverContext(
        receiverAddress,
        directory,
        ohttpKeys,
        recvPersister,
    );

    let processResponse = await processReceiverProposal(
        session,
        receiver,
        recvPersister,
        ohttpRelay,
    );
    assert.strictEqual(
        processResponse,
        null,
        "Initial proposal should be null",
    );

    const pjUri = session.pjUri();
    const psbt = buildSweepPsbt(sender, pjUri);
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

    let payjoinProposal = await processReceiverProposal(
        session,
        receiver,
        recvPersister,
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

    const ohttpContextRequest = sendCtx.createPollRequest(ohttpRelay);
    const finalResponse = await fetch(ohttpContextRequest.request.url, {
        method: "POST",
        headers: { "Content-Type": ohttpContextRequest.request.contentType },
        body: ohttpContextRequest.request.body,
    });
    const finalResponseBuffer = await finalResponse.arrayBuffer();
    const pollOutcome = sendCtx
        .processResponse(finalResponseBuffer, ohttpContextRequest.ohttpCtx)
        .save(senderPersister);

    assert(
        pollOutcome instanceof
            payjoin.PollingForProposalTransitionOutcome.Progress,
        "Should be progress outcome",
    );

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
    await uniffiInitAsync();
    testInvalidPrimitives();
    await testIntegrationV2ToV2();
}

runTests().catch((error: unknown) => {
    console.error("\n✗ Integration test failed:", error);
    process.exit(1);
});
