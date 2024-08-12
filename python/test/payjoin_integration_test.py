import base64
from binascii import unhexlify
import os
import sys

from payjoin import *

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


# Function to create and load a wallet if it doesn't already exist
def create_and_load_wallet(rpc_connection, wallet_name):
    try:
        # Try to load the wallet using the _call method
        rpc_connection._call("loadwallet", wallet_name)
        print(f"Wallet '{wallet_name}' loaded successfully.")
    except JSONRPCError as e:
        # Check if the error code indicates the wallet does not exist
        if e.error["code"] == -18:  # Wallet not found error code
            # Create the wallet since it does not exist using the _call method
            rpc_connection._call("createwallet", wallet_name)
            print(f"Wallet '{wallet_name}' created and loaded successfully.")
        elif e.error["code"] == -35:  # Wallet already loaded
            print(f"Wallet '{wallet_name}' created and loaded successfully.")


# Set up RPC connections
rpc_user = "admin1"
rpc_password = "123"
rpc_host = "localhost"
rpc_port = "18443"


class TestPayjoin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize wallets once before all tests
        sender_wallet_name = "sender"
        sender_rpc_url = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}/wallet/{sender_wallet_name}"
        cls.sender = Proxy(service_url=sender_rpc_url)
        create_and_load_wallet(cls.sender, sender_wallet_name)

        receiver_wallet_name = "receiver"
        receiver_rpc_url = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}/wallet/{receiver_wallet_name}"
        cls.receiver = Proxy(service_url=receiver_rpc_url)
        create_and_load_wallet(cls.receiver, receiver_wallet_name)

    def test_integration(self):
        # Generate a new address for the sender
        sender_address = self.sender.getnewaddress()
        print(f"\nsender_address: {sender_address}")

        # Generate a new address for the receiver
        receiver_address = self.receiver.getnewaddress()
        print(f"\nreceiver_address: {receiver_address}")

        self.sender.generatetoaddress(10, str(sender_address))
        self.receiver.generatetoaddress(10, str(receiver_address))

        # Fetch and print the balance of the sender address
        sender_balance = self.sender.getbalance()
        print(f"Sender address balance: {sender_balance}")

        # Fetch and print the balance of the receiver address
        receiver_balance = self.receiver.getbalance()
        print(f"Receiver address balance: {receiver_balance}")

        pj_uri_address = self.receiver.getnewaddress()
        pj_uri_string = "{}?amount={}&pj=https://example.com".format(
            f"bitcoin:{str(pj_uri_address)}", 1
        )
        prj_uri = Uri.from_str(pj_uri_string).check_pj_supported()
        print(f"\nprj_uri: {prj_uri.as_string()}")
        outputs = {}
        outputs[prj_uri.address()] = prj_uri.amount()
        pre_processed_psbt = self.sender._call(
            "walletcreatefundedpsbt",
            [],
            outputs,
            0,
            {"lockUnspents": True, "feeRate": 0.000020},
        )["psbt"]
        processed_psbt_base64 = self.sender._call("walletprocesspsbt", pre_processed_psbt)[
            "psbt"
        ]
        req_ctx = RequestBuilder.from_psbt_and_uri(processed_psbt_base64, prj_uri ).build_with_additional_fee(10000, None, 0, False).extract_v1()
        req = req_ctx.request
        ctx = req_ctx.context_v1
        headers = Headers.from_vec(req.body)
        # **********************
        # Inside the Receiver:
        # this data would transit from one party to another over the network in production
        response = self.handle_pj_request(
            req=req,
            headers=headers,
            connection=self.receiver,
        )
        # this response would be returned as http response to the sender

        # **********************
        # Inside the Sender:
        # Sender checks, signs, finalizes, extracts, and broadcasts
        checked_payjoin_proposal_psbt = ctx.process_response(bytes(response, encoding='utf8'))
        payjoin_processed_psbt = self.sender._call(
            "walletprocesspsbt",
            checked_payjoin_proposal_psbt,
        )["psbt"]

        payjoin_tx_hex = self.sender._call(
            "finalizepsbt",
            payjoin_processed_psbt,
        )["hex"]

        txid = self.sender._call("sendrawtransaction", payjoin_tx_hex)
        print(f"\nBroadcast sucessful. Txid: {txid}")

    def handle_pj_request(self, req: Request, headers: Headers, connection: Proxy):
        proposal = UncheckedProposal.from_request(req.body, req.url.query(), headers)
        _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast()
        maybe_inputs_owned = proposal.check_broadcast_suitability(None,
            can_broadcast=MempoolAcceptanceCallback(connection=connection)
        )

        mixed_inputs_scripts = maybe_inputs_owned.check_inputs_not_owned(
            ScriptOwnershipCallback(connection)
        )
        inputs_seen = mixed_inputs_scripts.check_no_mixed_input_scripts()
        payjoin = inputs_seen.check_no_inputs_seen_before(
            OutputOwnershipCallback()
        ).identify_receiver_outputs(ScriptOwnershipCallback(connection))
        available_inputs = connection._call("listunspent")
        candidate_inputs = {
            int(int(i["amount"] * 100000000)): OutPoint(txid=(str(i["txid"])), vout=i["vout"])
            for i in available_inputs
        }

        selected_outpoint = payjoin.try_preserving_privacy(
            candidate_inputs=candidate_inputs
        )

        selected_utxo = next(
            (
                i
                for i in available_inputs
                if i["txid"] == selected_outpoint.txid
                   and i["vout"] == selected_outpoint.vout
            ),
            None,
        )

        txo_to_contribute = TxOut(
            value=int(selected_utxo["amount"] * 100000000),
            script_pubkey=[int(byte) for byte in unhexlify(selected_utxo["scriptPubKey"])]
        )
        outpoint_to_contribute = OutPoint(
            txid=selected_utxo["txid"], vout=int(selected_utxo["vout"])
        )
        payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute)
        payjoin_proposal = payjoin.finalize_proposal(
            ProcessPartiallySignedTransactionCallBack(connection=connection),
            1,
        )
        psbt = payjoin_proposal.psbt()
        print(f"\n Receiver's Payjoin proposal PSBT: {psbt}")
        return psbt


class ProcessPartiallySignedTransactionCallBack:
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, psbt: str):
        try:
            return  self.connection._call(
                "walletprocesspsbt", psbt, True, "NONE", False
            )["psbt"]
        except Exception as e:
            print(f"An error occurred: {e}")
            return None   


class MempoolAcceptanceCallback(CanBroadcast):
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, tx):
          try:
                return self.connection._call("testmempoolaccept", [bytes(tx).hex()])[0][
                    "allowed"
                ]
          except Exception as e:
            print(f"An error occurred: {e}")
            return None      


class OutputOwnershipCallback(IsOutputKnown):
    def callback(self, outpoint: OutPoint):
        return False


class ScriptOwnershipCallback(IsScriptOwned):
    def __init__(self, connection: Proxy):
        self.connection = connection

    def callback(self, script):
        try:
            script = CScript(bytes(script))      
            witness_program = script[2:]   
            address = P2WPKHBitcoinAddress.from_bytes(0, witness_program)
            return self.connection._call("getaddressinfo", str(address))["ismine"]
        except Exception as e:
            print(f"An error occurred: {e}")
            return None



if __name__ == "__main__":
    unittest.main()
