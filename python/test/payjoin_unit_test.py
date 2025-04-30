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


class ScriptOwnershipCallback(payjoin.IsScriptOwned):
    def __init__(self, value):
        self.value = value

    def callback(self, script):
        return self.value


class OutputOwnershipCallback(payjoin.IsOutputKnown):
    def __init__(self, value):
        self.value = value

    def callback(self, outpoint: payjoin.bitcoin.OutPoint):
        return False


class TestReceiveModule(unittest.TestCase):
    def get_proposal_from_test_vector(self) -> payjoin.UncheckedProposal:
        try:
            # QueryParams Test Vector from BIP
            query_params = payjoin.query_params()
            # OriginalPSBT Test Vector from BIP
            body = payjoin.parsed_original_psbt()

            # Mimicking the Headers::from_vec() from Rust, assuming it converts the byte array to some header-like object
            headers = payjoin.Headers.from_vec(body)

            # Call to UncheckedProposal::from_request() from Rust
            # In Python, you would replace this with the appropriate function call or object instantiation
            unchecked_proposal = payjoin.UncheckedProposal.from_request(
                body,
                query_params,
                headers,
            )
            return unchecked_proposal

        except Exception as e:
            return f"PayjoinError: {e}"

    def test_get_proposal_from_request(self):
        try:
            proposal = self.get_proposal_from_test_vector()
            print(proposal)
        except Exception as e:
            self.fail(e, "OriginalPSBT should be a valid request")

    @unittest.skip("FFI bindings for this function are not working")
    def test_unchecked_proposal_unlocks_after_checks(self):
        try:
            # QueryParams Test Vector from BIP
            query_params = payjoin.query_params()
            # OriginalPSBT Test Vector from BIP
            original_psbt = payjoin.original_psbt()
            body = list(bytes(original_psbt, "utf-8"))
            # Mimicking the Headers::from_vec() from Rust, assuming it converts the byte array to some header-like object
            headers = payjoin.Headers.from_vec(body)

            # Call to UncheckedProposal::from_request() from Rust
            # In Python, you would replace this with the appropriate function call or object instantiation
            unchecked_proposal = payjoin.UncheckedProposal.from_request(
                body,
                query_params,
                headers,
            )
            proposal = (
                unchecked_proposal.assume_interactive_receiver()
                .check_inputs_not_owned(ScriptOwnershipCallback(False))
                .check_no_mixed_input_scripts()
                .check_no_inputs_seen_before(OutputOwnershipCallback(False))
                .identify_receiver_outputs(ScriptOwnershipCallback(True))
            )
            # payjoin_proposal = proposal.apply_fee(1)
            # print(payjoin_proposal.serialize())
        except Exception as e:
            self.fail(f"test_unchecked_proposal_unlocks_after_checks exception: {e}")

class InMemoryReceiverPersister(payjoin.payjoin_ffi.ReceiverPersister):
    def __init__(self):
        self.receivers = {}

    def save(self, receiver: payjoin.Receiver) -> payjoin.ReceiverToken:
        self.receivers[str(receiver.key())] = receiver.to_json()

        return receiver.key()

    def load(self, token: payjoin.ReceiverToken) -> payjoin.Receiver:
        token = str(token)
        if token not in self.receivers.keys():
            raise ValueError(f"Token not found: {token}")
        return payjoin.Receiver.from_json(self.receivers[token])

 
class TestRecieverPersistence(unittest.TestCase):
    def test_receiver_persistence(self):
        persister = InMemoryReceiverPersister()
        address = payjoin.bitcoin.Address("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", payjoin.bitcoin.Network.SIGNET)
        new_receiver = payjoin.NewReceiver(
            address, 
            "https://example.com", 
            payjoin.OhttpKeys.from_string("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC"), 
            None
        )
        token = new_receiver.persist(persister)
        payjoin.Receiver.load(token, persister)

class InMemorySenderPersister(payjoin.payjoin_ffi.SenderPersister):
    def __init__(self):
        self.senders = {}

    def save(self, sender: payjoin.Sender) -> payjoin.SenderToken:
        self.senders[str(sender.key())] = sender.to_json()
        return sender.key()
    
    def load(self, token: payjoin.SenderToken) -> payjoin.Sender:
        token = str(token)
        if token not in self.senders.keys():
            raise ValueError(f"Token not found: {token}")
        return payjoin.Sender.from_json(self.senders[token])
    
class TestSenderPersistence(unittest.TestCase):
    def test_sender_persistence(self):
        # Create a receiver to just get the pj uri
        persister = InMemoryReceiverPersister()
        address = payjoin.bitcoin.Address("2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", payjoin.bitcoin.Network.TESTNET)
        new_receiver = payjoin.NewReceiver(
            address, 
            "https://example.com", 
            payjoin.OhttpKeys.from_string("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC"), 
            None
        )
        token = new_receiver.persist(persister)
        reciever = payjoin.Receiver.load(token, persister)
        uri = reciever.pj_uri()

        persister = InMemorySenderPersister()
        psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA="
        new_sender = payjoin.SenderBuilder(psbt, uri).build_recommended(1000)
        token = new_sender.persist(persister)
        payjoin.Sender.load(token, persister)
            
if __name__ == "__main__":
    unittest.main()
