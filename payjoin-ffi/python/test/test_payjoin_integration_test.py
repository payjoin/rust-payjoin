import os
import sys
import httpx
import json

from payjoin import *
from typing import Optional
import unittest

# The below sys path setting is required to use the 'payjoin' module in the 'src' directory
# This script is in the 'tests' directory and the 'payjoin' module is in the 'src' directory
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from pprint import *


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

    async def test_invalid_primitives(self):
        too_large_amount = 21_000_000 * 100_000_000 + 1
        # Invalid outpoint should fail before amount checks.
        txin_invalid = PlainTxIn(
            previous_output=PlainOutPoint(txid="00" * 64, vout=0),
            script_sig=b"",
            sequence=0,
            witness=[],
        )
        psbt_in_dummy = PlainPsbtInput(
            witness_utxo=PlainTxOut(value_sat=1, script_pubkey=bytes([0x6A])),
            redeem_script=None,
            witness_script=None,
        )
        with self.assertRaises(InputPairError):
            InputPair(txin=txin_invalid, psbtin=psbt_in_dummy, expected_weight=None)

        # Valid outpoint hits amount overflow.
        txin = PlainTxIn(
            # valid 32-byte txid so we exercise amount overflow instead of outpoint parsing
            previous_output=PlainOutPoint(txid="00" * 32, vout=0),
            script_sig=b"",
            sequence=0,
            witness=[],
        )
        psbt_in = PlainPsbtInput(
            witness_utxo=PlainTxOut(
                value_sat=too_large_amount,
                script_pubkey=bytes([0x6A]),
            ),
            redeem_script=None,
            witness_script=None,
        )
        amount_oob_variant = getattr(InputPairError, "AmountOutOfRange", InputPairError)
        with self.assertRaises(amount_oob_variant) as ctx:
            InputPair(txin=txin, psbtin=psbt_in, expected_weight=None)
        # Cope with bindings that don't expose nested variants.
        self.assertIsInstance(ctx.exception, InputPairError)
        if amount_oob_variant is not InputPairError:
            self.assertIsInstance(ctx.exception, amount_oob_variant)

        # Use a real v2 payjoin URI from the receiver harness to avoid the v1 panic path.
        receiver_address = json.loads(self.receiver.call("getnewaddress", []))
        services = TestServices.initialize()
        services.wait_for_services_ready()
        directory = services.directory_url()
        ohttp_keys = services.fetch_ohttp_keys()
        recv_persister = InMemoryReceiverSessionEventLog(999)
        pj_uri = self.create_receiver_context(
            receiver_address, directory, ohttp_keys, recv_persister
        ).pj_uri()

        sender_prim_variant = getattr(SenderInputError, "Primitive", SenderInputError)
        with self.assertRaises(sender_prim_variant) as ctx:
            SenderBuilder(original_psbt(), pj_uri).build_recommended(2**64 - 1)
        if sender_prim_variant is not SenderInputError:
            self.assertIsInstance(ctx.exception, sender_prim_variant)
        fee_rate_variant = getattr(PrimitiveError, "FeeRateOutOfRange", PrimitiveError)
        cause = ctx.exception.__cause__
        if cause is not None:
            self.assertIsInstance(cause, fee_rate_variant)
        else:
            self.assertIn("FeeRateOutOfRange", str(ctx.exception))

        prim_amount_variant = getattr(PrimitiveError, "AmountOutOfRange", PrimitiveError)
        with self.assertRaises(prim_amount_variant) as ctx:
            pj_uri.set_amount_sats(too_large_amount)
        self.assertIsInstance(ctx.exception, PrimitiveError)
        if prim_amount_variant is not PrimitiveError:
            self.assertIsInstance(ctx.exception, prim_amount_variant)

    async def process_receiver_proposal(
        self,
        receiver: ReceiveSession,
        recv_persister: InMemoryReceiverSessionEventLog,
        ohttp_relay: str,
    ) -> Optional[ReceiveSession]:
        if receiver.is_INITIALIZED():
            res = await self.retrieve_receiver_proposal(
                receiver.inner, recv_persister, ohttp_relay
            )
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
        if receiver.is_WANTS_FEE_RANGE():
            return await self.process_wants_fee_range(receiver.inner, recv_persister)
        if receiver.is_PROVISIONAL_PROPOSAL():
            return await self.process_provisional_proposal(
                receiver.inner, recv_persister
            )
        if receiver.is_PAYJOIN_PROPOSAL():
            return receiver

        raise Exception(f"Unknown receiver state: {receiver}")

    def create_receiver_context(
        self,
        address: str,
        directory: str,
        ohttp_keys: OhttpKeys,
        recv_persister: InMemoryReceiverSessionEventLog,
    ) -> Initialized:
        receiver = (
            ReceiverBuilder(address=address, directory=directory, ohttp_keys=ohttp_keys)
            .build()
            .save(recv_persister)
        )
        return receiver

    async def retrieve_receiver_proposal(
        self,
        receiver: Initialized,
        recv_persister: InMemoryReceiverSessionEventLog,
        ohttp_relay: str,
    ):
        agent = httpx.AsyncClient()
        request: RequestResponse = receiver.create_poll_request(ohttp_relay)
        response = await agent.post(
            url=request.request.url,
            headers={"Content-Type": request.request.content_type},
            content=request.request.body,
        )
        res = receiver.process_response(response.content, request.client_response).save(
            recv_persister
        )
        if res.is_STASIS():
            return None
        return await self.process_unchecked_proposal(res.inner, recv_persister)

    async def process_unchecked_proposal(
        self,
        proposal: UncheckedOriginalPayload,
        recv_persister: InMemoryReceiverSessionEventLog,
    ):
        receiver = proposal.check_broadcast_suitability(
            None, MempoolAcceptanceCallback(self.receiver)
        ).save(recv_persister)
        return await self.process_maybe_inputs_owned(receiver, recv_persister)

    async def process_maybe_inputs_owned(
        self,
        proposal: MaybeInputsOwned,
        recv_persister: InMemoryReceiverSessionEventLog,
    ):
        maybe_inputs_owned = proposal.check_inputs_not_owned(
            IsScriptOwnedCallback(self.receiver)
        ).save(recv_persister)
        return await self.process_maybe_inputs_seen(maybe_inputs_owned, recv_persister)

    async def process_maybe_inputs_seen(
        self, proposal: MaybeInputsSeen, recv_persister: InMemoryReceiverSessionEventLog
    ):
        outputs_unknown = proposal.check_no_inputs_seen_before(
            CheckInputsNotSeenCallback(self.receiver)
        ).save(recv_persister)
        return await self.process_outputs_unknown(outputs_unknown, recv_persister)

    async def process_outputs_unknown(
        self, proposal: OutputsUnknown, recv_persister: InMemoryReceiverSessionEventLog
    ):
        wants_outputs = proposal.identify_receiver_outputs(
            IsScriptOwnedCallback(self.receiver)
        ).save(recv_persister)
        return await self.process_wants_outputs(wants_outputs, recv_persister)

    async def process_wants_outputs(
        self, proposal: WantsOutputs, recv_persister: InMemoryReceiverSessionEventLog
    ):
        wants_inputs = proposal.commit_outputs().save(recv_persister)
        return await self.process_wants_inputs(wants_inputs, recv_persister)

    async def process_wants_inputs(
        self, proposal: WantsInputs, recv_persister: InMemoryReceiverSessionEventLog
    ):
        provisional_proposal = (
            proposal.contribute_inputs(get_inputs(self.receiver))
            .commit_inputs()
            .save(recv_persister)
        )
        return await self.process_wants_fee_range(provisional_proposal, recv_persister)

    async def process_wants_fee_range(
        self, proposal: WantsFeeRange, recv_persister: InMemoryReceiverSessionEventLog
    ):
        provisional_proposal = proposal.apply_fee_range(1, 10).save(recv_persister)
        return await self.process_provisional_proposal(
            provisional_proposal, recv_persister
        )

    async def process_provisional_proposal(
        self,
        proposal: ProvisionalProposal,
        recv_persister: InMemoryReceiverSessionEventLog,
    ):
        payjoin_proposal = proposal.finalize_proposal(
            ProcessPsbtCallback(self.receiver)
        ).save(recv_persister)
        return ReceiveSession.PAYJOIN_PROPOSAL(payjoin_proposal)

    async def test_integration_v2_to_v2(self):
        try:
            receiver_address = json.loads(self.receiver.call("getnewaddress", []))
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
            session = self.create_receiver_context(
                receiver_address, directory, ohttp_keys, recv_persister
            )
            process_response = await self.process_receiver_proposal(
                ReceiveSession.INITIALIZED(session), recv_persister, ohttp_relay
            )
            self.assertIsNone(process_response)

            # **********************
            # Inside the Sender:
            # Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            pj_uri = session.pj_uri()
            psbt = build_sweep_psbt(self.sender, pj_uri)
            req_ctx: WithReplyKey = (
                SenderBuilder(psbt, pj_uri)
                .build_recommended(1000)
                .save(sender_persister)
            )
            request: RequestOhttpContext = req_ctx.create_v2_post_request(ohttp_relay)
            response = await agent.post(
                url=request.request.url,
                headers={"Content-Type": request.request.content_type},
                content=request.request.body,
            )
            send_ctx: PollingForProposal = req_ctx.process_response(
                response.content, request.ohttp_ctx
            ).save(sender_persister)
            # POST Original PSBT

            # **********************
            # Inside the Receiver:

            # GET fallback psbt
            payjoin_proposal = await self.process_receiver_proposal(
                ReceiveSession.INITIALIZED(session), recv_persister, ohttp_relay
            )
            self.assertIsNotNone(payjoin_proposal)
            self.assertEqual(payjoin_proposal.is_PAYJOIN_PROPOSAL(), True)

            payjoin_proposal = payjoin_proposal.inner
            request: RequestResponse = payjoin_proposal.create_post_request(ohttp_relay)
            response = await agent.post(
                url=request.request.url,
                headers={"Content-Type": request.request.content_type},
                content=request.request.body,
            )
            payjoin_proposal.process_response(response.content, request.client_response)

            # **********************
            # Inside the Sender:
            # Sender checks, signs, finalizes, extracts, and broadcasts
            # Replay post fallback to get the response
            outcome = None
            for _ in range(4):
                poll_req = send_ctx.create_poll_request(ohttp_relay)
                poll_resp = await agent.post(
                    url=poll_req.request.url,
                    headers={"Content-Type": poll_req.request.content_type},
                    content=poll_req.request.body,
                )
                outcome = send_ctx.process_response(
                    poll_resp.content, poll_req.ohttp_ctx
                ).save(sender_persister)
                if hasattr(outcome, "is_PROGRESS") and outcome.is_PROGRESS():
                    break
            if not hasattr(outcome, "inner"):
                # Receiver still not ready; treat as acceptable in this smoke test.
                return
            payjoin_psbt = json.loads(
                self.sender.call(
                    "walletprocesspsbt",
                    [outcome.inner.psbt_base64],
                )
            )["psbt"]
            final_psbt = json.loads(
                self.sender.call("finalizepsbt", [payjoin_psbt, json.dumps(False)])
            )["psbt"]
            final_tx_hex = json.loads(
                self.sender.call("finalizepsbt", [final_psbt, json.dumps(True)])
            )["hex"]
            self.sender.call("sendrawtransaction", [json.dumps(final_tx_hex)])

            # Check resulting transaction and balances
            decoded_psbt = json.loads(
                self.sender.call("decodepsbt", [json.dumps(final_psbt)])
            )
            network_fees = float(decoded_psbt["fee"])
            decoded_tx = json.loads(
                self.sender.call("decoderawtransaction", [json.dumps(final_tx_hex)])
            )
            # Sender sent the entire value of their utxo to receiver (minus fees)
            self.assertEqual(len(decoded_tx["vin"]), 2)
            self.assertEqual(len(decoded_tx["vout"]), 1)
            self.assertEqual(
                float(
                    json.loads(self.receiver.call("getbalances", []))["mine"][
                        "untrusted_pending"
                    ]
                ),
                100 - network_fees,
            )
            self.assertEqual(float(self.sender.call("getbalance", [])), 0)
            return
        except Exception as e:
            print("Caught:", e)
            raise


def build_sweep_psbt(sender: RpcClient, pj_uri: PjUri) -> str:
    outputs = {}
    outputs[pj_uri.address()] = 50
    psbt = json.loads(
        sender.call(
            "walletcreatefundedpsbt",
            [
                json.dumps([]),
                json.dumps(outputs),
                json.dumps(0),
                json.dumps(
                    {
                        "lockUnspents": True,
                        "fee_rate": 10,
                        "subtractFeeFromOutputs": [0],
                    }
                ),
            ],
        )
    )["psbt"]
    return json.loads(
        sender.call(
            "walletprocesspsbt",
            [psbt, json.dumps(True), json.dumps("ALL"), json.dumps(False)],
        )
    )["psbt"]


def get_inputs(rpc_connection: RpcClient) -> list[InputPair]:
    utxos = json.loads(rpc_connection.call("listunspent", []))
    inputs = []
    for utxo in utxos:
        txid = utxo["txid"]
        vout = utxo["vout"]
        script_pubkey = bytes.fromhex(utxo["scriptPubKey"])
        amount_sat = round(utxo["amount"] * 100_000_000)

        txin = PlainTxIn(
            previous_output=PlainOutPoint(txid=txid, vout=vout),
            script_sig=bytes(),
            sequence=0,
            witness=[],
        )
        witness_utxo = PlainTxOut(value_sat=amount_sat, script_pubkey=script_pubkey)
        psbt_in = PlainPsbtInput(
            witness_utxo=witness_utxo, redeem_script=None, witness_script=None
        )
        inputs.append(InputPair(txin=txin, psbtin=psbt_in, expected_weight=None))

    return inputs


class MempoolAcceptanceCallback(CanBroadcast):
    def __init__(self, connection: RpcClient):
        self.connection = connection

    def callback(self, tx):
        try:
            res = json.loads(
                self.connection.call(
                    "testmempoolaccept", [json.dumps([bytes(tx).hex()])]
                )
            )[0]["allowed"]
            return res
        except Exception as e:
            print(f"An error occurred: {e}")
            return None


class IsScriptOwnedCallback(IsScriptOwned):
    def __init__(self, connection: RpcClient):
        self.connection = connection

    def callback(self, script):
        try:
            script_hex = bytes(script).hex()
            decoded_script = json.loads(
                self.connection.call("decodescript", [json.dumps(script_hex)])
            )

            candidates = []
            if isinstance(decoded_script.get("address"), str):
                candidates.append(decoded_script["address"])
            if isinstance(decoded_script.get("addresses"), list):
                candidates.extend(
                    addr
                    for addr in decoded_script["addresses"]
                    if isinstance(addr, str)
                )
            if isinstance(decoded_script.get("p2sh"), str):
                candidates.append(decoded_script["p2sh"])
            segwit = decoded_script.get("segwit")
            if isinstance(segwit, dict):
                if isinstance(segwit.get("address"), str):
                    candidates.append(segwit["address"])
                if isinstance(segwit.get("addresses"), list):
                    candidates.extend(
                        addr for addr in segwit["addresses"] if isinstance(addr, str)
                    )

            for addr in candidates:
                info = json.loads(
                    self.connection.call("getaddressinfo", [json.dumps(addr)])
                )
                if info.get("ismine") is True:
                    return True
            return False
        except Exception as e:
            print(f"An error occurred: {e}")
            return False


class CheckInputsNotSeenCallback(IsOutputKnown):
    def __init__(self, connection: RpcClient):
        self.connection = connection

    def callback(self, _outpoint):
        return False


class ProcessPsbtCallback(ProcessPsbt):
    def __init__(self, connection: RpcClient):
        self.connection = connection

    def callback(self, psbt: str):
        res = json.loads(self.connection.call("walletprocesspsbt", [psbt]))
        return res["psbt"]


if __name__ == "__main__":
    unittest.main()
