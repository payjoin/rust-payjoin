package org.payjoindevkit;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Full BIP 77 v2↔v2 round trip against the in-process directory, OHTTP relay, and bitcoind
 * regtest - {@code payjoin-test-utils}, the same test infrastructure the Kotlin bindings'
 * {@code IntegrationTests.kt} uses. A close Java port of that test's flow (same RPC sequence,
 * same receiver checklist, same final assertions - including that the broadcast transaction
 * spends coins from both wallets), adapted to the Java-native generated API: every type here
 * genuinely implements {@code AutoCloseable} (unlike the Kotlin bindings, where a couple of
 * types are only {@code Disposable} - see README.md), so this uses plain try-with-resources
 * throughout instead of a custom {@code useDisposable} helper.
 * <p>
 * No public production infrastructure - sender and receiver are both driven through
 * this Java binding target.
 */
class BIP77IntegrationTest {
    private static final long POLL_SLEEP_MS = 250L;
    private static final long POLL_TIMEOUT_NS = 30_000_000_000L;

    @Test
    void v2ToV2Payjoin() throws Exception {
        Payjoin.initTracing();
        try (TestServices services = TestServices.initialize()) {
            services.waitForServicesReady();
            String directory = services.directoryUrl();
            String relay = services.ohttpRelayUrl();
            try (OhttpKeys ohttpKeys = services.fetchOhttpKeys();
                    TestHttp http = new TestHttp(services);
                    BitcoindEnv env = Payjoin.initBitcoindSenderReceiver()) {
                try (RpcClient senderRpc = env.getSender(); RpcClient receiverRpc = env.getReceiver()) {
                    runV2ToV2(http, directory, relay, ohttpKeys, senderRpc, receiverRpc);
                }
            }
        }
    }

    private void runV2ToV2(TestHttp http, String directory, String relay, OhttpKeys ohttpKeys,
            RpcClient senderRpc, RpcClient receiverRpc) throws Exception {
        String receiverAddress = JsonRpc.stringResult(rpc(receiverRpc, "getnewaddress"));
        Set<OutpointRef> senderOutpoints = listOutpoints(senderRpc);
        Set<OutpointRef> receiverOutpoints = listOutpoints(receiverRpc);
        InMemoryPersisters.InMemoryReceiverPersister recvPersister = new InMemoryPersisters.InMemoryReceiverPersister();
        InMemoryPersisters.InMemorySenderPersister sendPersister = new InMemoryPersisters.InMemorySenderPersister();

        // Inside the receiver: start the session.
        Initialized session;
        try (ReceiverBuilder builder = new ReceiverBuilder(receiverAddress, directory, ohttpKeys)) {
            try (InitialReceiveTransition initial = builder.build()) {
                session = initial.save(recvPersister);
            }
        }
        try {
            UncheckedOriginalPayload firstPoll = pollReceiver(session, recvPersister, http, relay);
            assertEquals(null, firstPoll, "receiver mailbox should be empty before the sender posts");

            // Inside the sender: build and post the Original PSBT.
            PjUri pjUri = session.pjUri();
            try {
                String originalPsbt = buildSweepPsbt(senderRpc, pjUri);
                WithReplyKey withReplyKey;
                try (SenderBuilder senderBuilder = new SenderBuilder(originalPsbt, pjUri)) {
                    try (InitialSendTransition initial = senderBuilder.buildRecommended(1_000L)) {
                        withReplyKey = initial.save(sendPersister);
                    }
                }
                PollingForProposal pollingForProposal;
                try (RequestOhttpContext posted = withReplyKey.createV2PostRequest(relay)) {
                    byte[] body = http.post(posted.request());
                    try (WithReplyKeyTransition transition = withReplyKey.processResponse(body, posted.ohttpCtx())) {
                        pollingForProposal = transition.save(sendPersister);
                    }
                } finally {
                    withReplyKey.close();
                }

                try {
                    // Inside the receiver: wait for the sender's post, then work through the
                    // full receiver checklist to a finalized PayjoinProposal.
                    PayjoinProposal payjoinProposal = waitForReceiverProposal(session, recvPersister, http, relay, receiverRpc);
                    try {
                        try (RequestResponse posted = payjoinProposal.createPostRequest(relay)) {
                            byte[] body = http.post(posted.request());
                            try (PayjoinProposalTransition transition =
                                    payjoinProposal.processResponse(body, posted.clientResponse())) {
                                transition.save(recvPersister).close();
                            }
                        }

                        // Inside the sender: poll until the receiver's proposal comes back.
                        String psbtBase64 = waitForSenderProposal(pollingForProposal, sendPersister, http, relay);
                        finishPayjoin(senderRpc, receiverRpc, psbtBase64, senderOutpoints, receiverOutpoints);
                    } finally {
                        payjoinProposal.close();
                    }
                } finally {
                    pollingForProposal.close();
                }
            } finally {
                pjUri.close();
            }
        } finally {
            session.close();
        }

        recvPersister.closeSession();
        sendPersister.closeSession();
    }

    private UncheckedOriginalPayload pollReceiver(Initialized session, InMemoryPersisters.InMemoryReceiverPersister persister,
            TestHttp http, String relay) throws Exception {
        try (RequestResponse requestResponse = session.createPollRequest(relay)) {
            byte[] body = http.post(requestResponse.request());
            try (InitializedTransition transition = session.processResponse(body, requestResponse.clientResponse())) {
                InitializedTransitionOutcome outcome = transition.save(persister);
                if (outcome instanceof InitializedTransitionOutcome.Progress progress) {
                    // Progress retains the payload as the return value; closing the outcome
                    // wrapper would free that handle, so it's returned without closing.
                    return progress.inner();
                } else if (outcome instanceof InitializedTransitionOutcome.Stasis stasis) {
                    stasis.close();
                    return null;
                }
                throw new IllegalStateException("unreachable: unknown InitializedTransitionOutcome");
            }
        }
    }

    private PayjoinProposal waitForReceiverProposal(Initialized session, InMemoryPersisters.InMemoryReceiverPersister persister,
            TestHttp http, String relay, RpcClient receiverRpc) throws Exception {
        long deadline = System.nanoTime() + POLL_TIMEOUT_NS;
        int attempts = 0;
        while (System.nanoTime() < deadline) {
            attempts++;
            UncheckedOriginalPayload original = pollReceiver(session, persister, http, relay);
            if (original != null) {
                try {
                    return processUncheckedProposal(original, persister, receiverRpc);
                } finally {
                    original.close();
                }
            }
            Thread.sleep(POLL_SLEEP_MS);
        }
        fail("Timed out waiting for sender original after " + attempts + " poll(s)");
        throw new AssertionError("unreachable");
    }

    private PayjoinProposal processUncheckedProposal(UncheckedOriginalPayload proposal,
            InMemoryPersisters.InMemoryReceiverPersister persister, RpcClient receiverRpc) throws Exception {
        MaybeInputsOwned maybeInputsOwned;
        try (UncheckedOriginalPayloadTransition transition =
                proposal.checkBroadcastSuitability(null, new MempoolAcceptanceCallback(receiverRpc))) {
            maybeInputsOwned = transition.save(persister);
        }
        try {
            return processMaybeInputsOwned(maybeInputsOwned, persister, receiverRpc);
        } finally {
            maybeInputsOwned.close();
        }
    }

    private PayjoinProposal processMaybeInputsOwned(MaybeInputsOwned proposal,
            InMemoryPersisters.InMemoryReceiverPersister persister, RpcClient receiverRpc) throws Exception {
        MaybeInputsSeen maybeInputsSeen;
        try (MaybeInputsOwnedTransition transition = proposal.checkInputsNotOwned(new IsInputOwnedCallback(receiverRpc))) {
            maybeInputsSeen = transition.save(persister);
        }
        try {
            return processMaybeInputsSeen(maybeInputsSeen, persister, receiverRpc);
        } finally {
            maybeInputsSeen.close();
        }
    }

    private PayjoinProposal processMaybeInputsSeen(MaybeInputsSeen proposal,
            InMemoryPersisters.InMemoryReceiverPersister persister, RpcClient receiverRpc) throws Exception {
        OutputsUnknown outputsUnknown;
        try (MaybeInputsSeenTransition transition = proposal.checkNoInputsSeenBefore(new CheckInputsNotSeenCallback())) {
            outputsUnknown = transition.save(persister);
        }
        try {
            return processOutputsUnknown(outputsUnknown, persister, receiverRpc);
        } finally {
            outputsUnknown.close();
        }
    }

    private PayjoinProposal processOutputsUnknown(OutputsUnknown proposal,
            InMemoryPersisters.InMemoryReceiverPersister persister, RpcClient receiverRpc) throws Exception {
        WantsOutputs wantsOutputs;
        try (OutputsUnknownTransition transition = proposal.identifyReceiverOutputs(new IsScriptOwnedCallback(receiverRpc))) {
            wantsOutputs = transition.save(persister);
        }
        try {
            return processWantsOutputs(wantsOutputs, persister, receiverRpc);
        } finally {
            wantsOutputs.close();
        }
    }

    private PayjoinProposal processWantsOutputs(WantsOutputs proposal,
            InMemoryPersisters.InMemoryReceiverPersister persister, RpcClient receiverRpc) throws Exception {
        WantsInputs wantsInputs;
        try (WantsOutputsTransition transition = proposal.commitOutputs()) {
            wantsInputs = transition.save(persister);
        }
        try {
            return processWantsInputs(wantsInputs, persister, receiverRpc);
        } finally {
            wantsInputs.close();
        }
    }

    private PayjoinProposal processWantsInputs(WantsInputs proposal,
            InMemoryPersisters.InMemoryReceiverPersister persister, RpcClient receiverRpc) throws Exception {
        List<InputPair> inputs = getInputs(receiverRpc);
        WantsFeeRange wantsFeeRange;
        try {
            try (WantsInputs contributed = proposal.contributeInputs(inputs)) {
                try (WantsInputsTransition transition = contributed.commitInputs()) {
                    wantsFeeRange = transition.save(persister);
                }
            }
        } finally {
            for (InputPair input : inputs) {
                input.close();
            }
        }
        try {
            return processWantsFeeRange(wantsFeeRange, persister, receiverRpc);
        } finally {
            wantsFeeRange.close();
        }
    }

    private PayjoinProposal processWantsFeeRange(WantsFeeRange proposal,
            InMemoryPersisters.InMemoryReceiverPersister persister, RpcClient receiverRpc) throws Exception {
        ProvisionalProposal provisional;
        try (WantsFeeRangeTransition transition = proposal.applyFeeRange(1L, 10L)) {
            provisional = transition.save(persister);
        }
        try {
            return processProvisionalProposal(provisional, persister, receiverRpc);
        } finally {
            provisional.close();
        }
    }

    private PayjoinProposal processProvisionalProposal(ProvisionalProposal proposal,
            InMemoryPersisters.InMemoryReceiverPersister persister, RpcClient receiverRpc) throws Exception {
        try (ProvisionalProposalTransition transition = proposal.finalizeProposal(new ProcessPsbtCallback(receiverRpc))) {
            return transition.save(persister);
        }
    }

    private String waitForSenderProposal(PollingForProposal pollingForProposal,
            InMemoryPersisters.InMemorySenderPersister persister, TestHttp http, String relay) throws Exception {
        long deadline = System.nanoTime() + POLL_TIMEOUT_NS;
        int attempts = 0;
        PollingForProposal current = pollingForProposal;
        while (System.nanoTime() < deadline) {
            attempts++;
            PollingForProposalTransitionOutcome outcome;
            try (RequestOhttpContext posted = current.createPollRequest(relay)) {
                byte[] body = http.post(posted.request());
                try (PollingForProposalTransition transition = current.processResponse(body, posted.ohttpCtx())) {
                    outcome = transition.save(persister);
                }
            }
            if (outcome instanceof PollingForProposalTransitionOutcome.Progress progress) {
                // The final `current` handle is deliberately left for the UniFFI cleaner here -
                // same as the Kotlin bindings' IntegrationTests.kt in this exact case.
                return progress.psbtBase64();
            } else if (outcome instanceof PollingForProposalTransitionOutcome.Stasis stasis) {
                if (current != pollingForProposal) {
                    current.close();
                }
                current = stasis.inner();
                Thread.sleep(POLL_SLEEP_MS);
            } else {
                throw new IllegalStateException("unreachable: unknown PollingForProposalTransitionOutcome");
            }
        }
        fail("Timed out waiting for receiver proposal after " + attempts + " poll(s)");
        throw new AssertionError("unreachable");
    }

    private void finishPayjoin(RpcClient senderRpc, RpcClient receiverRpc, String psbtBase64,
            Set<OutpointRef> senderOutpoints, Set<OutpointRef> receiverOutpoints) throws Exception {
        String payjoinPsbt = JsonRpc.objectField(rpc(senderRpc, "walletprocesspsbt", jstr(psbtBase64)), "psbt");
        String finalPsbt = JsonRpc.objectField(rpc(senderRpc, "finalizepsbt", jstr(payjoinPsbt), "false"), "psbt");
        String finalTxHex = JsonRpc.objectField(rpc(senderRpc, "finalizepsbt", jstr(finalPsbt), "true"), "hex");
        String txid = JsonRpc.stringResult(rpc(senderRpc, "sendrawtransaction", jstr(finalTxHex)));
        assertTrue(!txid.isEmpty(), "sendrawtransaction should accept the payjoin");

        JsonRpc.Value decodedTx = JsonRpc.parse(rpc(senderRpc, "decoderawtransaction", jstr(finalTxHex)));
        List<JsonRpc.Value> vins = decodedTx.get("vin").asArray();
        List<JsonRpc.Value> vouts = decodedTx.get("vout").asArray();
        assertEquals(2, vins.size());
        assertEquals(1, vouts.size());

        Set<OutpointRef> spent = new HashSet<>();
        for (JsonRpc.Value vin : vins) {
            spent.add(new OutpointRef(vin.get("txid").asString(), (int) vin.get("vout").asDouble()));
        }
        assertTrue(spent.stream().anyMatch(senderOutpoints::contains), "final tx should spend a sender input");
        assertTrue(spent.stream().anyMatch(receiverOutpoints::contains), "final tx should spend a receiver input");
    }

    private static String rpc(RpcClient client, String method, String... params) throws Exception {
        List<String> paramList = new ArrayList<>(List.of(params));
        return client.call(method, paramList);
    }

    // String-valued RPC params go through jstr(); JSON structure ([], objects, numbers, true/false) is passed raw.
    private static String jstr(String value) {
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (char ch : value.toCharArray()) {
            if (ch == '\\' || ch == '"') {
                sb.append('\\');
            }
            sb.append(ch);
        }
        sb.append('"');
        return sb.toString();
    }

    private static String buildSweepPsbt(RpcClient sender, PjUri pjUri) throws Exception {
        String outputs = "{" + jstr(pjUri.address()) + ":50}";
        String options = "{\"lockUnspents\":true,\"fee_rate\":10,\"subtractFeeFromOutputs\":[0]}";
        String psbt = JsonRpc.objectField(
                rpc(sender, "walletcreatefundedpsbt", "[]", outputs, "0", options), "psbt");
        return JsonRpc.objectField(
                rpc(sender, "walletprocesspsbt", jstr(psbt), "true", jstr("ALL"), "false"), "psbt");
    }

    private static List<InputPair> getInputs(RpcClient rpcConnection) throws Exception {
        List<JsonRpc.Value> utxos = JsonRpc.parse(rpc(rpcConnection, "listunspent")).asArray();
        List<InputPair> pairs = new ArrayList<>();
        for (JsonRpc.Value utxo : utxos) {
            String txid = utxo.get("txid").asString();
            int vout = (int) utxo.get("vout").asDouble();
            byte[] scriptPubkey = hexDecode(utxo.get("scriptPubKey").asString());
            long amountSat = Math.round(utxo.get("amount").asDouble() * 100_000_000.0);
            TxIn txIn = new TxIn(new OutPoint(txid, vout), new byte[0], 0, List.of());
            PsbtInput psbtIn = new PsbtInput(new TxOut(amountSat, scriptPubkey), null, null);
            pairs.add(new InputPair(txIn, psbtIn, null));
        }
        return pairs;
    }

    private static Set<OutpointRef> listOutpoints(RpcClient client) throws Exception {
        List<JsonRpc.Value> utxos = JsonRpc.parse(rpc(client, "listunspent")).asArray();
        Set<OutpointRef> outpoints = new HashSet<>();
        for (JsonRpc.Value utxo : utxos) {
            outpoints.add(new OutpointRef(utxo.get("txid").asString(), (int) utxo.get("vout").asDouble()));
        }
        return outpoints;
    }

    private static byte[] hexDecode(String hex) {
        return java.util.HexFormat.of().parseHex(hex);
    }

    private record OutpointRef(String txid, int vout) {
    }

    /**
     * Kotlin PR #1869 review lesson (chavic, on the equivalent Kotlin callback): "Can we let RPC
     * errors fail the test here? Returning false treats an RPC failure as 'input not owned', so a
     * broken ownership check goes unnoticed." Every callback below follows the same rule: only a
     * cleanly-parsed, legitimate negative answer from bitcoind returns false. An RPC/transport
     * failure or a response that doesn't parse as expected throws ForeignException.InternalException
     * instead - the interfaces below all declare `throws ForeignException`, so this crosses the FFI
     * boundary as a real error and fails the test loudly, rather than silently becoming "not owned"/
     * "not broadcastable".
     */
    private static ForeignException.InternalException wrapRpcFailure(String what, Exception cause) {
        return new ForeignException.InternalException(what + ": " + cause);
    }

    private static final class MempoolAcceptanceCallback implements CanBroadcast {
        private final RpcClient connection;

        MempoolAcceptanceCallback(RpcClient connection) {
            this.connection = connection;
        }

        @Override
        public boolean callback(byte[] tx) throws ForeignException {
            // A real mempool rejection ("allowed": false, parsed successfully) is a legitimate
            // false; only the RPC call/response parsing itself throws.
            JsonRpc.Value result;
            try {
                String hexTx = java.util.HexFormat.of().formatHex(tx);
                result = JsonRpc.parse(rpc(connection, "testmempoolaccept", "[" + jstr(hexTx) + "]"));
            } catch (Exception e) {
                throw wrapRpcFailure("testmempoolaccept RPC failed", e);
            }
            try {
                return result.asArray().get(0).get("allowed").asBoolean();
            } catch (Exception e) {
                throw wrapRpcFailure("unexpected testmempoolaccept response shape: " + result, e);
            }
        }
    }

    private static final class IsScriptOwnedCallback implements IsScriptOwned {
        private final RpcClient connection;

        IsScriptOwnedCallback(RpcClient connection) {
            this.connection = connection;
        }

        @Override
        public boolean callback(byte[] script) throws ForeignException {
            JsonRpc.Value decoded;
            try {
                decoded = JsonRpc.parse(rpc(connection, "decodescript", jstr(java.util.HexFormat.of().formatHex(script))));
            } catch (Exception e) {
                throw wrapRpcFailure("decodescript RPC failed", e);
            }
            List<String> candidates = new ArrayList<>();
            if (decoded.has("address")) {
                candidates.add(decoded.get("address").asString());
            }
            if (decoded.has("addresses")) {
                for (JsonRpc.Value a : decoded.get("addresses").asArray()) {
                    candidates.add(a.asString());
                }
            }
            if (decoded.has("p2sh")) {
                candidates.add(decoded.get("p2sh").asString());
            }
            if (decoded.has("segwit")) {
                JsonRpc.Value segwit = decoded.get("segwit");
                if (segwit.has("address")) {
                    candidates.add(segwit.get("address").asString());
                }
                if (segwit.has("addresses")) {
                    for (JsonRpc.Value a : segwit.get("addresses").asArray()) {
                        candidates.add(a.asString());
                    }
                }
            }
            for (String addr : candidates) {
                JsonRpc.Value info;
                try {
                    info = JsonRpc.parse(rpc(connection, "getaddressinfo", jstr(addr)));
                } catch (Exception e) {
                    throw wrapRpcFailure("getaddressinfo RPC failed for " + addr, e);
                }
                if (info.has("ismine") && info.get("ismine").asBoolean()) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final class IsInputOwnedCallback implements IsInputOwned {
        private final RpcClient connection;

        IsInputOwnedCallback(RpcClient connection) {
            this.connection = connection;
        }

        @Override
        public boolean callback(OutPoint outpoint) throws ForeignException {
            JsonRpc.Value txOut;
            try {
                txOut = JsonRpc.parse(
                        rpc(connection, "gettxout", jstr(outpoint.txid()), String.valueOf(outpoint.vout()), "true"));
            } catch (Exception e) {
                throw wrapRpcFailure("gettxout RPC failed for " + outpoint.txid() + ":" + outpoint.vout(), e);
            }
            // A null result is bitcoind's normal answer for a spent/nonexistent output, not a
            // failure - legitimately "can't be ours" rather than "unknown".
            if (txOut.isNull()) {
                return false;
            }
            String scriptHex;
            try {
                scriptHex = txOut.get("scriptPubKey").get("hex").asString();
            } catch (Exception e) {
                throw wrapRpcFailure("unexpected gettxout response shape: " + txOut, e);
            }
            return new IsScriptOwnedCallback(connection).callback(hexDecode(scriptHex));
        }
    }

    private static final class CheckInputsNotSeenCallback implements IsOutputKnown {
        @Override
        public boolean callback(OutPoint outpoint) {
            return false;
        }
    }

    private static final class ProcessPsbtCallback implements ProcessPsbt {
        private final RpcClient connection;

        ProcessPsbtCallback(RpcClient connection) {
            this.connection = connection;
        }

        @Override
        public String callback(String psbt) throws ForeignException {
            try {
                return JsonRpc.objectField(rpc(connection, "walletprocesspsbt", jstr(psbt)), "psbt");
            } catch (Exception e) {
                throw wrapRpcFailure("walletprocesspsbt RPC failed", e);
            }
        }
    }
}
