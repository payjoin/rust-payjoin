import unittest
import payjoin


class TestURIs(unittest.TestCase):
    def test_todo_url_encoded(self):
        uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao"
        self.assertTrue(payjoin.Url.parse(uri), "pj url should be url encoded")

    def test_valid_url(self):
        uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao"
        self.assertTrue(payjoin.Url.parse(uri), "pj is not a valid url")

    def test_missing_amount(self):
        uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj"
        self.assertTrue(payjoin.Url.parse(uri), "missing amount should be ok")

    def test_valid_uris(self):
        https = str(payjoin.example_url())
        onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion"

        base58 = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"
        bech32_upper = "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4"
        bech32_lower = "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4"

        for address in [base58, bech32_upper, bech32_lower]:
            for pj in [https, onion]:
                uri = f"{address}?amount=1&pj={pj}"
                try:
                    payjoin.Url.parse(uri)
                except Exception as e:
                    self.fail(f"Failed to create a valid Uri for {uri}. Error: {e}")


class InMemoryReceiverPersister(payjoin.JsonReceiverSessionPersister):
    def __init__(self, id):
        self.id = id
        self.events = []
        self.closed = False

    def save(self, event: str):
        self.events.append(event)

    def load(self):
        return self.events

    def close(self):
        self.closed = True


class InMemorySenderPersister(payjoin.JsonSenderSessionPersister):
    def __init__(self, id):
        self.id = id
        self.events = []
        self.closed = False

    def save(self, event: str):
        self.events.append(event)

    def load(self):
        return self.events

    def close(self):
        self.closed = True


class InMemoryReceiverPersisterAsync(payjoin.JsonReceiverSessionPersisterAsync):
    def __init__(self, id):
        self.id = id
        self.events = []
        self.closed = False

    async def save(self, event: str):
        self.events.append(event)

    async def load(self):
        return self.events

    async def close(self):
        self.closed = True


class InMemorySenderPersisterAsync(payjoin.JsonSenderSessionPersisterAsync):
    def __init__(self, id):
        self.id = id
        self.events = []
        self.closed = False

    async def save(self, event: str):
        self.events.append(event)

    async def load(self):
        return self.events

    async def close(self):
        self.closed = True


class TestReceiverPersistence(unittest.TestCase):
    def test_receiver_persistence(self):
        persister = InMemoryReceiverPersister(1)
        payjoin.ReceiverBuilder(
            "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
            "https://example.com",
            payjoin.OhttpKeys.decode(
                bytes.fromhex(
                    "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003"
                )
            ),
        ).build().save(persister)
        result = payjoin.replay_receiver_event_log(persister)
        self.assertTrue(result.state().is_INITIALIZED())


class TestSenderPersistence(unittest.TestCase):
    def test_sender_persistence(self):
        # Create a receiver to just get the pj uri
        persister = InMemoryReceiverPersister(1)
        receiver = (
            payjoin.ReceiverBuilder(
                "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
                "https://example.com",
                payjoin.OhttpKeys.decode(
                    bytes.fromhex(
                        "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003"
                    )
                ),
            )
            .build()
            .save(persister)
        )
        uri = receiver.pj_uri()

        persister = InMemorySenderPersister(1)
        psbt = payjoin.original_psbt()
        with_reply_key = (
            payjoin.SenderBuilder(psbt, uri).build_recommended(1000).save(persister)
        )


class TestReceiverAsyncPersistence(unittest.TestCase):
    def test_receiver_async_persistence(self):
        import asyncio

        async def run_test():
            persister = InMemoryReceiverPersisterAsync(1)
            await (
                payjoin.ReceiverBuilder(
                    "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
                    "https://example.com",
                    payjoin.OhttpKeys.decode(
                        bytes.fromhex(
                            "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003"
                        )
                    ),
                )
                .build()
                .save_async(persister)
            )
            result = await payjoin.replay_receiver_event_log_async(persister)
            self.assertTrue(result.state().is_INITIALIZED())

        asyncio.run(run_test())


class TestSenderAsyncPersistence(unittest.TestCase):
    def test_sender_async_persistence(self):
        import asyncio

        async def run_test():
            # Create a receiver to just get the pj uri
            persister = InMemoryReceiverPersisterAsync(1)
            receiver = await (
                payjoin.ReceiverBuilder(
                    "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
                    "https://example.com",
                    payjoin.OhttpKeys.decode(
                        bytes.fromhex(
                            "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003"
                        )
                    ),
                )
                .build()
                .save_async(persister)
            )
            uri = receiver.pj_uri()

            persister = InMemorySenderPersisterAsync(1)
            psbt = payjoin.original_psbt()
            with_reply_key = await (
                payjoin.SenderBuilder(psbt, uri)
                .build_recommended(1000)
                .save_async(persister)
            )

        asyncio.run(run_test())


class TestValidation(unittest.TestCase):
    def test_receiver_builder_rejects_bad_address(self):
        with self.assertRaises(payjoin.ReceiverBuilderError):
            payjoin.ReceiverBuilder(
                "not-an-address",
                "https://example.com",
                payjoin.OhttpKeys.decode(
                    bytes.fromhex(
                        "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003"
                    )
                ),
            )

    def test_input_pair_rejects_invalid_outpoint(self):
        with self.assertRaises(payjoin.InputPairError):
            txin = payjoin.PlainTxIn(
                previous_output=payjoin.PlainOutPoint(txid="deadbeef", vout=0),
                script_sig=bytes(),
                sequence=0,
                witness=[],
            )
            psbtin = payjoin.PlainPsbtInput(
                witness_utxo=None, redeem_script=None, witness_script=None
            )
            payjoin.InputPair(txin, psbtin, None)

    def test_sender_builder_rejects_bad_psbt(self):
        uri = payjoin.Uri.parse(
            "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?pj=https://example.com/pj"
        ).check_pj_supported()
        with self.assertRaises(payjoin.SenderInputError):
            payjoin.SenderBuilder("not-a-psbt", uri)


if __name__ == "__main__":
    unittest.main()
