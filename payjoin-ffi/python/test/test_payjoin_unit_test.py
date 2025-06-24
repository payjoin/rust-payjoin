import unittest
import payjoin as payjoin
import payjoin.bitcoin

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

class InMemoryReceiverPersister(payjoin.payjoin_ffi.JsonReceiverSessionPersister):
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

class TestReceiverPersistence(unittest.TestCase):
    def test_receiver_persistence(self):
        persister = InMemoryReceiverPersister(1)
        address = payjoin.bitcoin.Address("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", payjoin.bitcoin.Network.SIGNET)
        payjoin.payjoin_ffi.UninitializedReceiver().create_session(
            address, 
            "https://example.com", 
            payjoin.OhttpKeys.from_string("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC"), 
            None
        ).save(persister)
        result = payjoin.payjoin_ffi.replay_receiver_event_log(persister)
        self.assertTrue(result.state().is_WITH_CONTEXT())

class InMemorySenderPersister(payjoin.payjoin_ffi.JsonSenderSessionPersister):
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

class TestSenderPersistence(unittest.TestCase):
    def test_sender_persistence(self):
        # Create a receiver to just get the pj uri
        persister = InMemoryReceiverPersister(1)
        address = payjoin.bitcoin.Address("2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", payjoin.bitcoin.Network.TESTNET)
        receiver = payjoin.payjoin_ffi.UninitializedReceiver().create_session(
            address, 
            "https://example.com", 
            payjoin.OhttpKeys.from_string("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC"), 
            None
        ).save(persister)
        uri = receiver.pj_uri()

        persister = InMemorySenderPersister(1)
        psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA="
        with_reply_key = payjoin.SenderBuilder(psbt, uri).build_recommended(1000).save(persister)
            
if __name__ == "__main__":
    unittest.main()
