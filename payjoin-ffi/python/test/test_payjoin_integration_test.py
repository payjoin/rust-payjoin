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

import unittest
from pprint import *
from bitcoin import SelectParams
from bitcoin.wallet import *
from bitcoin.rpc import Proxy

SelectParams("regtest")

class InMemoryReceiverSessionEventLog(JsonReceiverSessionPersister):
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

class InMemorySenderPersister(JsonSenderSessionPersister):
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


class TestPayjoin(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = init_bitcoind_sender_receiver()
        cls.bitcoind = cls.env.get_bitcoind()
        cls.receiver = cls.env.get_receiver()
        cls.sender = cls.env.get_sender()

    async def process_receiver_proposal(self, receiver: ReceiverTypeState, recv_persister: InMemoryReceiverSessionEventLog, ohttp_relay: Url) -> Optional[ReceiverTypeState]:
        if receiver.is_WITH_CONTEXT():
            res = await self.retrieve_receiver_proposal(receiver.inner, recv_persister, ohttp_relay)
            if res is None:
                return None
            return res
        
        if receiver.is_UNCHECKED_PROPOSAL():
            return await self.process_unchecked_proposal(receiver.inner, recv_persister)
        if receiver.is_MAYBE_INPUTS_OWNED():
            return await self.process_maybe_inputs_owned(receiver.inner, recv_persister)
        if receiver.is_MAYBE_INPUTS_SEEN():
            return await self.process_maybe_inputs_seen(receiver.inner, recv_persister)
        if receiver.is_OUTPUTS_UNKNOWN():
            return await self.process_outputs_unknown(receiver.inner, recv_persister)
        if receiver.is_WANTS_OUTPUTS():
            return await self.process_wants_outputs(receiver.inner, recv_persister)
        if receiver.is_WANTS_INPUTS():
            return await self.process_wants_inputs(receiver.inner, recv_persister)
        if receiver.is_PROVISIONAL_PROPOSAL():
            return await self.process_provisional_proposal(receiver.inner, recv_persister)
        if receiver.is_PAYJOIN_PROPOSAL():
            return receiver
        
        raise Exception(f"Unknown receiver state: {receiver}")
            
            
    def create_receiver_context(self, receiver_address: bitcoinffi.Address, directory: Url, ohttp_keys: OhttpKeys, recv_persister: InMemoryReceiverSessionEventLog) -> WithContext:
        receiver = UninitializedReceiver().create_session(address=receiver_address, directory=directory.as_string(), ohttp_keys=ohttp_keys, expire_after=None).save(recv_persister)
        return receiver
    
    async def retrieve_receiver_proposal(self, receiver: WithContext, recv_persister: InMemoryReceiverSessionEventLog, ohttp_relay: Url):
        agent = httpx.AsyncClient()
        request: RequestResponse = receiver.extract_req(ohttp_relay.as_string())
        response = await agent.post(
            url=request.request.url.as_string(),
            headers={"Content-Type": request.request.content_type},
            content=request.request.body
        )
        res = receiver.process_res(response.content, request.client_response).save(recv_persister)
        if res.is_none():
            return None
        proposal = res.success()
        return await self.process_unchecked_proposal(proposal, recv_persister)
    
    async def process_unchecked_proposal(self, proposal: UncheckedProposal, recv_persister: InMemoryReceiverSessionEventLog) :
        receiver = proposal.check_broadcast_suitability(None, MempoolAcceptanceCallback(self.receiver)).save(recv_persister)
        return await self.process_maybe_inputs_owned(receiver, recv_persister)
    
    async def process_maybe_inputs_owned(self, proposal: MaybeInputsOwned, recv_persister: InMemoryReceiverSessionEventLog):
        maybe_inputs_owned = proposal.check_inputs_not_owned(IsScriptOwnedCallback(self.receiver)).save(recv_persister)
        return await self.process_maybe_inputs_seen(maybe_inputs_owned, recv_persister)
    
    async def process_maybe_inputs_seen(self, proposal: MaybeInputsSeen, recv_persister: InMemoryReceiverSessionEventLog):
        outputs_unknown = proposal.check_no_inputs_seen_before(CheckInputsNotSeenCallback(self.receiver)).save(recv_persister)
        return await self.process_outputs_unknown(outputs_unknown, recv_persister)
    
    async def process_outputs_unknown(self, proposal: OutputsUnknown, recv_persister: InMemoryReceiverSessionEventLog):
        wants_outputs = proposal.identify_receiver_outputs(IsScriptOwnedCallback(self.receiver)).save(recv_persister)
        return await self.process_wants_outputs(wants_outputs, recv_persister)
    
    async def process_wants_outputs(self, proposal: WantsOutputs, recv_persister: InMemoryReceiverSessionEventLog):
        wants_inputs = proposal.commit_outputs().save(recv_persister)
        return await self.process_wants_inputs(wants_inputs, recv_persister)
    
    async def process_wants_inputs(self, proposal: WantsInputs, recv_persister: InMemoryReceiverSessionEventLog):
        provisional_proposal = proposal.contribute_inputs(get_inputs(self.receiver)).commit_inputs().save(recv_persister)
        return await self.process_provisional_proposal(provisional_proposal, recv_persister)
    
    async def process_provisional_proposal(self, proposal: ProvisionalProposal, recv_persister: InMemoryReceiverSessionEventLog):
        payjoin_proposal = proposal.finalize_proposal(ProcessPsbtCallback(self.receiver), 1, 10).save(recv_persister)
        return ReceiverTypeState.PAYJOIN_PROPOSAL(payjoin_proposal)
 
    async def test_integration_v2_to_v2(self):
        try:
            receiver_address = bitcoinffi.Address(json.loads(self.receiver.call("getnewaddress", [])), bitcoinffi.Network.REGTEST)
            init_tracing()
            services = TestServices.initialize()

            services.wait_for_services_ready()
            directory = services.directory_url()
            ohttp_keys = services.fetch_ohttp_keys()
            ohttp_relay = services.ohttp_relay_url()
            agent = httpx.AsyncClient()

            # **********************
            # Inside the Receiver:
            recv_persister = InMemoryReceiverSessionEventLog(1)
            sender_persister = InMemorySenderPersister(1)
            session = self.create_receiver_context(receiver_address, directory, ohttp_keys, recv_persister)
            process_response = await self.process_receiver_proposal(ReceiverTypeState.WITH_CONTEXT(session), recv_persister, ohttp_relay)
            print(f"session: {session.to_json()}")
            self.assertIsNone(process_response)

            # **********************
            # Inside the Sender:
            # Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            pj_uri = session.pj_uri()
            psbt = build_sweep_psbt(self.sender, pj_uri)
            req_ctx: WithReplyKey = SenderBuilder(psbt, pj_uri).build_recommended(1000).save(sender_persister)
            request: RequestV2PostContext = req_ctx.extract_v2(ohttp_relay.as_string())
            response = await agent.post(
                url=request.request.url.as_string(),
                headers={"Content-Type": request.request.content_type},
                content=request.request.body
            )
            send_ctx: V2GetContext = req_ctx.process_response(response.content, request.context).save(sender_persister)
            # POST Original PSBT

            # **********************
            # Inside the Receiver:

            # GET fallback psbt
            payjoin_proposal = await self.process_receiver_proposal(ReceiverTypeState.WITH_CONTEXT(session), recv_persister, ohttp_relay)
            self.assertIsNotNone(payjoin_proposal)
            self.assertEqual(payjoin_proposal.is_PAYJOIN_PROPOSAL(), True)

            payjoin_proposal = payjoin_proposal.inner
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
            checked_payjoin_proposal_psbt = send_ctx.process_response(response.content, request.ohttp_ctx).save(sender_persister).success()
            print(f"checked_payjoin_proposal_psbt: {checked_payjoin_proposal_psbt}")
            self.assertIsNotNone(checked_payjoin_proposal_psbt)
            payjoin_psbt = json.loads(self.sender.call("walletprocesspsbt", [checked_payjoin_proposal_psbt.serialize_base64()]))["psbt"]
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
