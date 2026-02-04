import { describe, test, before } from "node:test";
import assert from "node:assert";
import { payjoin, uniffiInitAsync } from "../dist/index.js";

before(async () => {
    await uniffiInitAsync();
});

class InMemoryReceiverPersister {
    id: number;
    events: any[];
    closed: boolean;

    constructor(id: number) {
        this.id = id;
        this.events = [];
        this.closed = false;
    }

    save(event: any) {
        this.events.push(event);
    }

    load() {
        return this.events;
    }

    close() {
        this.closed = true;
    }
}

class InMemorySenderPersister {
    id: number;
    events: any[];
    closed: boolean;

    constructor(id: number) {
        this.id = id;
        this.events = [];
        this.closed = false;
    }

    save(event: any) {
        this.events.push(event);
    }

    load() {
        return this.events;
    }

    close() {
        this.closed = true;
    }
}

class InMemoryReceiverPersisterAsync {
    id: number;
    events: any[];
    closed: boolean;

    constructor(id: number) {
        this.id = id;
        this.events = [];
        this.closed = false;
    }

    async save(event: any): Promise<void> {
        this.events.push(event);
    }

    async load(): Promise<any[]> {
        return this.events;
    }

    async close(): Promise<void> {
        this.closed = true;
    }
}

class InMemorySenderPersisterAsync {
    id: number;
    events: any[];
    closed: boolean;

    constructor(id: number) {
        this.id = id;
        this.events = [];
        this.closed = false;
    }

    async save(event: any): Promise<void> {
        this.events.push(event);
    }

    async load(): Promise<any[]> {
        return this.events;
    }

    async close(): Promise<void> {
        this.closed = true;
    }
}

describe("URI tests", () => {
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

describe("Persistence tests", () => {
    test("receiver persistence", () => {
        const persister = new InMemoryReceiverPersister(1);
        const address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
        const ohttpKeys = payjoin.OhttpKeys.decode(
            new Uint8Array([
                0x01, 0x00, 0x16, 0x04, 0xba, 0x48, 0xc4, 0x9c, 0x3d, 0x4a,
                0x92, 0xa3, 0xad, 0x00, 0xec, 0xc6, 0x3a, 0x02, 0x4d, 0xa1,
                0x0c, 0xed, 0x02, 0x18, 0x0c, 0x73, 0xec, 0x12, 0xd8, 0xa7,
                0xad, 0x2c, 0xc9, 0x1b, 0xb4, 0x83, 0x82, 0x4f, 0xe2, 0xbe,
                0xe8, 0xd2, 0x8b, 0xfe, 0x2e, 0xb2, 0xfc, 0x64, 0x53, 0xbc,
                0x4d, 0x31, 0xcd, 0x85, 0x1e, 0x8a, 0x65, 0x40, 0xe8, 0x6c,
                0x53, 0x82, 0xaf, 0x58, 0x8d, 0x37, 0x09, 0x57, 0x00, 0x04,
                0x00, 0x01, 0x00, 0x03,
            ]).buffer,
        );

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
        const persister = new InMemoryReceiverPersister(1);
        const address = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
        const ohttpKeys = payjoin.OhttpKeys.decode(
            new Uint8Array([
                0x01, 0x00, 0x16, 0x04, 0xba, 0x48, 0xc4, 0x9c, 0x3d, 0x4a,
                0x92, 0xa3, 0xad, 0x00, 0xec, 0xc6, 0x3a, 0x02, 0x4d, 0xa1,
                0x0c, 0xed, 0x02, 0x18, 0x0c, 0x73, 0xec, 0x12, 0xd8, 0xa7,
                0xad, 0x2c, 0xc9, 0x1b, 0xb4, 0x83, 0x82, 0x4f, 0xe2, 0xbe,
                0xe8, 0xd2, 0x8b, 0xfe, 0x2e, 0xb2, 0xfc, 0x64, 0x53, 0xbc,
                0x4d, 0x31, 0xcd, 0x85, 0x1e, 0x8a, 0x65, 0x40, 0xe8, 0x6c,
                0x53, 0x82, 0xaf, 0x58, 0x8d, 0x37, 0x09, 0x57, 0x00, 0x04,
                0x00, 0x01, 0x00, 0x03,
            ]).buffer,
        );

        const receiver = new payjoin.ReceiverBuilder(
            address,
            "https://example.com",
            ohttpKeys,
        )
            .build()
            .save(persister);
        const uri = receiver.pjUri();

        const senderPersister = new InMemorySenderPersister(1);
        const psbt =
            "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
        const withReplyKey = new payjoin.SenderBuilder(psbt, uri)
            .buildRecommended(BigInt(1000))
            .save(senderPersister);

        assert.ok(withReplyKey, "Sender should be created successfully");
    });
});

describe("Async Persistence tests", () => {
    test("receiver async persistence", async () => {
        const persister = new InMemoryReceiverPersisterAsync(1);
        const address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
        const ohttpKeys = payjoin.OhttpKeys.decode(
            new Uint8Array([
                0x01, 0x00, 0x16, 0x04, 0xba, 0x48, 0xc4, 0x9c, 0x3d, 0x4a,
                0x92, 0xa3, 0xad, 0x00, 0xec, 0xc6, 0x3a, 0x02, 0x4d, 0xa1,
                0x0c, 0xed, 0x02, 0x18, 0x0c, 0x73, 0xec, 0x12, 0xd8, 0xa7,
                0xad, 0x2c, 0xc9, 0x1b, 0xb4, 0x83, 0x82, 0x4f, 0xe2, 0xbe,
                0xe8, 0xd2, 0x8b, 0xfe, 0x2e, 0xb2, 0xfc, 0x64, 0x53, 0xbc,
                0x4d, 0x31, 0xcd, 0x85, 0x1e, 0x8a, 0x65, 0x40, 0xe8, 0x6c,
                0x53, 0x82, 0xaf, 0x58, 0x8d, 0x37, 0x09, 0x57, 0x00, 0x04,
                0x00, 0x01, 0x00, 0x03,
            ]).buffer,
        );

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
        const persister = new InMemoryReceiverPersisterAsync(1);
        const address = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
        const ohttpKeys = payjoin.OhttpKeys.decode(
            new Uint8Array([
                0x01, 0x00, 0x16, 0x04, 0xba, 0x48, 0xc4, 0x9c, 0x3d, 0x4a,
                0x92, 0xa3, 0xad, 0x00, 0xec, 0xc6, 0x3a, 0x02, 0x4d, 0xa1,
                0x0c, 0xed, 0x02, 0x18, 0x0c, 0x73, 0xec, 0x12, 0xd8, 0xa7,
                0xad, 0x2c, 0xc9, 0x1b, 0xb4, 0x83, 0x82, 0x4f, 0xe2, 0xbe,
                0xe8, 0xd2, 0x8b, 0xfe, 0x2e, 0xb2, 0xfc, 0x64, 0x53, 0xbc,
                0x4d, 0x31, 0xcd, 0x85, 0x1e, 0x8a, 0x65, 0x40, 0xe8, 0x6c,
                0x53, 0x82, 0xaf, 0x58, 0x8d, 0x37, 0x09, 0x57, 0x00, 0x04,
                0x00, 0x01, 0x00, 0x03,
            ]).buffer,
        );

        const receiver = await new payjoin.ReceiverBuilder(
            address,
            "https://example.com",
            ohttpKeys,
        )
            .build()
            .saveAsync(persister);
        const uri = receiver.pjUri();

        const senderPersister = new InMemorySenderPersisterAsync(1);
        const psbt =
            "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
        const withReplyKey = await new payjoin.SenderBuilder(psbt, uri)
            .buildRecommended(BigInt(1000))
            .saveAsync(senderPersister);

        assert.ok(withReplyKey, "Sender should be created successfully");
    });
});

describe("Validation", () => {
    test("receiver builder rejects bad address", () => {
        assert.throws(() => {
            new payjoin.ReceiverBuilder(
                "not-an-address",
                "https://example.com",
                payjoin.OhttpKeys.decode(
                    new Uint8Array([
                        0x01, 0x00, 0x16, 0x04, 0xba, 0x48, 0xc4, 0x9c, 0x3d,
                        0x4a, 0x92, 0xa3, 0xad, 0x00, 0xec, 0xc6, 0x3a, 0x02,
                        0x4d, 0xa1, 0x0c, 0xed, 0x02, 0x18, 0x0c, 0x73, 0xec,
                        0x12, 0xd8, 0xa7, 0xad, 0x2c, 0xc9, 0x1b, 0xb4, 0x83,
                        0x82, 0x4f, 0xe2, 0xbe, 0xe8, 0xd2, 0x8b, 0xfe, 0x2e,
                        0xb2, 0xfc, 0x64, 0x53, 0xbc, 0x4d, 0x31, 0xcd, 0x85,
                        0x1e, 0x8a, 0x65, 0x40, 0xe8, 0x6c, 0x53, 0x82, 0xaf,
                        0x58, 0x8d, 0x37, 0x09, 0x57, 0x00, 0x04, 0x00, 0x01,
                        0x00, 0x03,
                    ]).buffer,
                ),
            );
        });
    });

    test("input pair rejects invalid outpoint", () => {
        assert.throws(() => {
            const txin = payjoin.PlainTxIn.create({
                previousOutput: payjoin.PlainOutPoint.create({
                    txid: "deadbeef",
                    vout: 0,
                }),
                scriptSig: new Uint8Array([]),
                sequence: 0,
                witness: [],
            });
            const psbtIn = payjoin.PlainPsbtInput.create({
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
                "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
            );
        });
    });
});
