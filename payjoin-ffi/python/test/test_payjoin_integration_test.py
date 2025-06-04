import base64
from binascii import unhexlify
import os
import sys
import httpx
import json

from payjoin import *
from typing import Optional
import payjoin.bitcoin as bitcoinffi

# The below sys path setting is required to use the 'payjoin' module in the 'src' directory
# This script is in the 'tests' directory and the 'payjoin' module is in the 'src' directory
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

import hashlib
import unittest
from pprint import *
from bitcoin import SelectParams
from bitcoin.core.script import (
    CScript,
    OP_0,
    SignatureHash,
)
from bitcoin.wallet import *
from bitcoin.rpc import Proxy, hexlify_str, JSONRPCError

SelectParams("regtest")

class InMemoryReceiverPersister(ReceiverPersister):
    def __init__(self):
        super().__init__()
        self.receivers = {}

    def save(self, receiver: WithContext) -> ReceiverToken:
        self.receivers[str(receiver.key())] = receiver.to_json()

        return receiver.key()

    def load(self, token: ReceiverToken) -> WithContext:
        token = str(token)
        if token not in self.receivers.keys():
            raise ValueError(f"Token not found: {token}")
        return WithContext.from_json(self.receivers[token])

class InMemorySenderPersister(SenderPersister):
    def __init__(self):
        super().__init__()
        self.senders = {}

    def save(self, sender: WithReplyKey) -> SenderToken:
        self.senders[str(sender.key())] = sender.to_json()
        return sender.key()

    def load(self, token: SenderToken) -> WithReplyKey:
        token = str(token)
        if token not in self.senders.keys():
            raise ValueError(f"Token not found: {token}")
        return WithReplyKey.from_json(self.senders[token])

class TestPayjoin(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = init_bitcoind_sender_receiver()
        cls.bitcoind = cls.env.get_bitcoind()
        cls.receiver = cls.env.get_receiver()
        cls.sender = cls.env.get_sender()
 
    async def test_integration_v2_to_v2(self):
        try:
            receiver_address = bitcoinffi.Address(json.loads(self.receiver.call("getnewaddress", [])), bitcoinffi.Network.REGTEST)
            init_tracing()
            services = TestServices.initialize()

            services.wait_for_services_ready()
            directory = services.directory_url()
            ohttp_keys = services.fetch_ohttp_keys()

            # **********************
            # Inside the Receiver:
            new_receiver = NewReceiver(receiver_address, directory.as_string(), ohttp_keys, None)
            persister = InMemoryReceiverPersister()
            token = new_receiver.persist(persister)
            session: WithContext = WithContext.load(token, persister)
            print(f"session: {session.to_json()}")
            # Poll receive request
            ohttp_relay = services.ohttp_relay_url()
            request: RequestResponse = session.extract_req(ohttp_relay.as_string())
            agent = httpx.AsyncClient()
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            response_body = session.process_res(response.content, request.client_response)
            # No proposal yet since sender has not responded
            self.assertIsNone(response_body)

            # **********************
            # Inside the Sender:
            # Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            pj_uri = session.pj_uri()
            psbt = build_sweep_psbt(self.sender, pj_uri)
            new_sender = SenderBuilder(psbt, pj_uri).build_recommended(1000)
            persister = InMemorySenderPersister()
            token = new_sender.persist(persister)
            req_ctx: WithReplyKey = WithReplyKey.load(token, persister)
            request: RequestV2PostContext = req_ctx.extract_v2(ohttp_relay.as_string())
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            send_ctx: V2GetContext = request.context.process_response(response.content)
            # POST Original PSBT

            # **********************
            # Inside the Receiver:

            # GET fallback psbt
            request: RequestResponse = session.extract_req(ohttp_relay.as_string())
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            # POST payjoin
            proposal = session.process_res(response.content, request.client_response)
            payjoin_proposal = handle_directory_payjoin_proposal(self.receiver, proposal)
            request: RequestResponse = payjoin_proposal.extract_req(ohttp_relay.as_string())
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            payjoin_proposal.process_res(response.content, request.client_response)

            # **********************
            # Inside the Sender:
            # Sender checks, signs, finalizes, extracts, and broadcasts
            # Replay post fallback to get the response
            request: RequestOhttpContext = send_ctx.extract_req(ohttp_relay.as_string())
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            checked_payjoin_proposal_psbt: Optional[str] = send_ctx.process_response(response.content, request.ohttp_ctx)
            self.assertIsNotNone(checked_payjoin_proposal_psbt)
            payjoin_psbt = json.loads(self.sender.call("walletprocesspsbt", [checked_payjoin_proposal_psbt]))["psbt"]
            final_psbt = json.loads(self.sender.call("finalizepsbt", [payjoin_psbt, json.dumps(False)]))["psbt"]
            payjoin_tx = bitcoinffi.Psbt.deserialize_base64(final_psbt).extract_tx()
            self.sender.call("sendrawtransaction", [json.dumps(payjoin_tx.serialize().hex())])

            # Check resulting transaction and balances
            network_fees = bitcoinffi.Psbt.deserialize_base64(final_psbt).fee().to_btc()
            # Sender sent the entire value of their utxo to receiver (minus fees)
            self.assertEqual(len(payjoin_tx.input()), 2);
            self.assertEqual(len(payjoin_tx.output()), 1);
            self.assertEqual(float(json.loads(self.receiver.call("getbalances", []))["mine"]["untrusted_pending"]), 100 - network_fees)
            self.assertEqual(float(self.sender.call("getbalance", [])), 0)
            return
        except Exception as e:
            print("Caught:", e)
            raise

def handle_directory_payjoin_proposal(receiver: Proxy, proposal: UncheckedProposal) -> PayjoinProposal:
    maybe_inputs_owned = proposal.check_broadcast_suitability(None, MempoolAcceptanceCallback(receiver))
    maybe_inputs_seen = maybe_inputs_owned.check_inputs_not_owned(IsScriptOwnedCallback(receiver))
    outputs_unknown = maybe_inputs_seen.check_no_inputs_seen_before(CheckInputsNotSeenCallback(receiver))
    wants_outputs = outputs_unknown.identify_receiver_outputs(IsScriptOwnedCallback(receiver))
    wants_inputs = wants_outputs.commit_outputs()
    provisional_proposal = wants_inputs.contribute_inputs(get_inputs(receiver)).commit_inputs()
    return provisional_proposal.finalize_proposal(ProcessPsbtCallback(receiver), 1, 10)

def build_sweep_psbt(sender: Proxy, pj_uri: PjUri) -> bitcoinffi.Psbt:
    outputs = {}
    outputs[pj_uri.address()] = 50
    psbt = json.loads(sender.call(
        "walletcreatefundedpsbt",
        [json.dumps([]),
        json.dumps(outputs),
        json.dumps(0),
        json.dumps({"lockUnspents": True, "fee_rate": 10, "subtract_fee_from_outputs": [0]})
        ]))["psbt"]
    return json.loads(sender.call("walletprocesspsbt", [psbt, json.dumps(True), json.dumps("ALL"), json.dumps(False)]))["psbt"]

def get_inputs(rpc_connection: Proxy) -> list[InputPair]:
    utxos = json.loads(rpc_connection.call("listunspent", []))
    inputs = []
    for utxo in utxos[:1]:
        txin = bitcoinffi.TxIn(
            previous_output=bitcoinffi.OutPoint(txid=utxo["txid"], vout=utxo["vout"]),
            script_sig=bitcoinffi.Script(bytes()),
            sequence=0,
            witness=[]
        )
        raw_tx = json.loads(rpc_connection.call("gettransaction", [json.dumps(utxo["txid"]), json.dumps(True), json.dumps(True)]))
        prev_out = raw_tx["decoded"]["vout"][utxo["vout"]]
        prev_spk = bitcoinffi.Script(bytes.fromhex(prev_out["scriptPubKey"]["hex"]))
        prev_amount = bitcoinffi.Amount.from_btc(prev_out["value"])
        tx_out = bitcoinffi.TxOut(value=prev_amount, script_pubkey=prev_spk)
        psbt_in = PsbtInput(witness_utxo=tx_out, redeem_script=None, witness_script=None)
        inputs.append(InputPair(txin=txin, psbtin=psbt_in))

    return inputs

class MempoolAcceptanceCallback(CanBroadcast):
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, tx):
          try:
                res = json.loads(self.connection.call("testmempoolaccept", [json.dumps([bytes(tx).hex()])]))[0][
                    "allowed"
                ]
                return res
          except Exception as e:
            print(f"An error occurred: {e}")
            return None      

class IsScriptOwnedCallback(IsScriptOwned):
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, script):
        try:
            address = bitcoinffi.Address.from_script(bitcoinffi.Script(script), bitcoinffi.Network.REGTEST)
            return json.loads(self.connection.call("getaddressinfo", [str(address)]))["ismine"]
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

class CheckInputsNotSeenCallback(IsOutputKnown):
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, _outpoint):
        return False

class ProcessPsbtCallback(ProcessPsbt):
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, psbt: str):
        res = json.loads(self.connection.call("walletprocesspsbt", [psbt])) 
        return res['psbt']

if __name__ == "__main__":
    unittest.main()
