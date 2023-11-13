import os
import sys
import time
# This script is in the 'tests' directory and the 'payjoin' module is in the 'src' directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

import hashlib
import unittest
from pprint import *
from payjoin import *
from bitcoin import SelectParams
from bitcoin.core import Hash160, CMutableTransaction, CTransaction
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
        rpc_connection._call('loadwallet', wallet_name)
        print(f"Wallet '{wallet_name}' loaded successfully.")
    except JSONRPCError as e:
        # Check if the error code indicates the wallet does not exist
        if e.error['code'] == -18:  # Wallet not found error code
            # Create the wallet since it does not exist using the _call method
            rpc_connection._call('createwallet', wallet_name)
            print(f"Wallet '{wallet_name}' created and loaded successfully.")
        else:
            # If it's not a 'wallet not found' error, re-raise the exception
            raise

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
        sender_balance = self.sender.getreceivedbyaddress(sender_address, 0)  # 0 confirmations for the balance including unconfirmed transactions
        print(f"Sender address balance: {sender_balance}")

        # Fetch and print the balance of the receiver address
        receiver_balance = self.receiver.getreceivedbyaddress(receiver_address, 0)  # 0 confirmations for the balance including unconfirmed transactions
        print(f"Receiver address balance: {receiver_balance}")
    
        pj_uri_address = self.receiver.getnewaddress()
        pj_uri_string = "{}?amount={}&pj=https://example.com".format(
            f"BITCOIN:{str(pj_uri_address).upper()}", 1
        )
        print(f"\npj_uri_string: {pj_uri_string}")
        prj_uri = Uri(pj_uri_string).check_pj_supported()
        print(f"\nprj_uri: {prj_uri}")
        outputs = {}
        outputs[prj_uri.address().as_string()] = prj_uri.amount().to_btc()
        pprint(outputs)
        pre_processed_psbt = self.sender._call(
            "walletcreatefundedpsbt",
            [],
            outputs,
            0,
            {"lockUnspents": True, "feeRate": 0.000020},
        )["psbt"]
        processed_psbt = self.sender._call("walletprocesspsbt", pre_processed_psbt)["psbt"]
        psbt = PartiallySignedTransaction.from_string(processed_psbt)
        pj_params = Configuration.with_fee_contribution(10000, None)
        prj_uri_req = prj_uri.create_pj_request(psbt, pj_params)
        req = prj_uri_req.request
        ctx = prj_uri_req.context
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
        checked_payjoin_proposal_psbt = ctx.process_response(response)
        payjoin_processed_psbt = self.sender._call(
            "walletprocesspsbt",
            checked_payjoin_proposal_psbt.as_string(),
        )["psbt"]

        payjoin_finalized_psbt = self.sender._call(
            "finalizepsbt",
            payjoin_processed_psbt,
        )["psbt"]

        payjoin_psbt = PartiallySignedTransaction(payjoin_finalized_psbt)
        print(
            f"Sender's Payjoin PSBT: {payjoin_psbt.as_string()}\n",
        )
        tx = payjoin_psbt.extract_tx()
        payjoin_tx_hex = bytes(tx.serialize()).hex()
        print(
            f"Sender's Tx hex: {payjoin_tx_hex}\n",
        )
        pprint(self.sender._call("sendrawtransaction", payjoin_tx_hex))

    def handle_pj_request(self, req: Request, headers: Headers, connection: Proxy):
        proposal = UncheckedProposal.from_request(req.body, req.url.query(), headers)
        _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast()
        maybe_inputs_owned = proposal.check_can_broadcast(
            can_broadcast=BroadcastCallBack(connection=connection)
        )

        mixed_inputs_scripts = maybe_inputs_owned.check_inputs_not_owned(
            OwnedScriptsCallBack(connection=connection)
        )
        inputs_seen = mixed_inputs_scripts.check_no_mixed_input_scripts()
        payjoin = inputs_seen.check_no_inputs_seen_before(
            OutputOwnedCallBack()
        ).identify_receiver_outputs(OwnedScriptsCallBack(connection=connection))
        available_inputs = connection._call("listunspent")
        candidate_inputs = {
            int(int(i["amount"] * 100000000)): OutPoint(str(i["txid"]), i["vout"])
            for i in available_inputs
            # if int(i["amount"] * 100000000) == 5000000000
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
            int(selected_utxo["amount"] * 100000000),
            ScriptBuf([int(byte) for byte in unhexlify(selected_utxo["scriptPubKey"])]),
        )
        outpoint_to_contribute = OutPoint(
            selected_utxo["txid"], int(selected_utxo["vout"])
        )
        payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute)
        receiver_substitute_address = connection.getnewaddress()
        payjoin.substitute_output_address(Address(str(receiver_substitute_address)))
        payjoin_proposal = payjoin.finalize_proposal(
            ProcessPartiallySignedTransactionCallBack(connection=connection),
            FeeRate.min(),
        )
        psbt = payjoin_proposal.psbt()
        print(f"Receiver's Payjoin proposal PSBT: {psbt.as_string()}")
        return psbt.as_string()


class ProcessPartiallySignedTransactionCallBack:
    def __init__(self, connection: Proxy):
        self.connection = connection

    def process_psbt(self, psbt: PartiallySignedTransaction):
        _psbt = self.connection._call(
            "walletprocesspsbt",
            psbt.as_string(),
        )["psbt"]
        return _psbt


class BroadcastCallBack:
    def __init__(self, connection: Proxy):
        self.connection = connection

    def test_mempool_accept(self, tx):
        return self.connection._call("testmempoolaccept", [bytes(tx).hex()])[0][
            "allowed"
        ]


class OutputOwnedCallBack:
    def is_known(self, outpoint: OutPoint):
        return False


class OwnedScriptsCallBack:
    def __init__(self, connection: Proxy):
        self.connection = connection

    def is_owned(self, script: ScriptBuf):
        address = Address.from_script(script, network=Network.REGTEST)
        return self.connection._call("getaddressinfo", address.as_string())["ismine"]

if __name__ == '__main__':
    unittest.main()