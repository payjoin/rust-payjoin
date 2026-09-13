package org.payjoindevkit

import java.util.HexFormat
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Full BIP 77 v2↔v2 round trip against the in-process directory, OHTTP relay,
 * and bitcoind. Mirrors `payjoin-ffi/python/test/test_payjoin_integration_test.py`
 * (`test_integration_v2_to_v2`): same RPC sequence, same receiver checklist,
 * same final assertions, plus an explicit check that the broadcast transaction
 * spends coins from both wallets.
 *
 * Every [TestServices] call takes a global runtime mutex and blocks, so sender
 * and receiver are driven strictly in sequence.
 */
class IntegrationTests {
    @Test
    fun v2ToV2Payjoin() {
        initTracing()
        TestServices.initialize().use { services ->
            services.waitForServicesReady()
            val directory = services.directoryUrl()
            val relay = services.ohttpRelayUrl()
            services.fetchOhttpKeys().use { ohttpKeys ->
                TestHttp(services).use { http ->
                    initBitcoindSenderReceiver().use { env ->
                        env.getSender().use { senderRpc ->
                            env.getReceiver().use { receiverRpc ->
                                runV2ToV2(
                                    http,
                                    directory,
                                    relay,
                                    ohttpKeys,
                                    senderRpc,
                                    receiverRpc,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun runV2ToV2(
        http: TestHttp,
        directory: String,
        relay: String,
        ohttpKeys: OhttpKeys,
        senderRpc: RpcClient,
        receiverRpc: RpcClient,
    ) {
        val receiverAddress = Json.parseToJsonElement(rpc(receiverRpc, "getnewaddress")).jsonPrimitive.content
        val senderOutpoints = listOutpoints(senderRpc)
        val receiverOutpoints = listOutpoints(receiverRpc)
        val recvPersister = InMemoryReceiverPersister()
        val sendPersister = InMemorySenderPersister()

        // **********************
        // Inside the Receiver:
        val session = ReceiverBuilder(receiverAddress, directory, ohttpKeys).use { builder ->
            builder.build().use { it.save(recvPersister) }
        }
        session.use {
            val firstPoll = pollReceiver(session, recvPersister, http, relay)
            assertEquals(null, firstPoll, "receiver mailbox should be empty before the sender posts")

            // **********************
            // Inside the Sender:
            val pjUri = session.pjUri()
            pjUri.use {
                val originalPsbt = buildSweepPsbt(senderRpc, pjUri)
                val withReplyKey = SenderBuilder(originalPsbt, pjUri).use { senderBuilder ->
                    senderBuilder.buildRecommended(1000u).use { it.save(sendPersister) }
                }
                withReplyKey.use {
                    val pollingForProposal = withReplyKey.createV2PostRequest(relay).useDisposable { posted ->
                        val body = http.post(posted.request)
                        withReplyKey.processResponse(body, posted.ohttpCtx).use { it.save(sendPersister) }
                    }
                    pollingForProposal.use {
                        // **********************
                        // Inside the Receiver:
                        val payjoinProposal = waitForReceiverProposal(session, recvPersister, http, relay, receiverRpc)
                        payjoinProposal.use {
                            payjoinProposal.createPostRequest(relay).useDisposable { posted ->
                                val body = http.post(posted.request)
                                payjoinProposal.processResponse(body, posted.clientResponse).use { transition ->
                                    transition.save(recvPersister).use { }
                                }
                            }

                            // **********************
                            // Inside the Sender:
                            val psbtBase64 = waitForSenderProposal(pollingForProposal, sendPersister, http, relay)
                            finishPayjoin(
                                senderRpc,
                                receiverRpc,
                                psbtBase64,
                                senderOutpoints,
                                receiverOutpoints,
                            )
                        }
                    }
                }
            }
        }

        recvPersister.closeSession()
        sendPersister.closeSession()
    }

    private fun pollReceiver(
        session: Initialized,
        recvPersister: InMemoryReceiverPersister,
        http: TestHttp,
        relay: String,
    ): UncheckedOriginalPayload? {
        return session.createPollRequest(relay).useDisposable { requestResponse ->
            val body = http.post(requestResponse.request)
            session.processResponse(body, requestResponse.clientResponse).use { transition ->
                when (val outcome = transition.save(recvPersister)) {
                    // Progress retains outcome.inner as the return value; destroying the enum would free that handle.
                    is InitializedTransitionOutcome.Progress -> outcome.inner
                    is InitializedTransitionOutcome.Stasis -> {
                        outcome.destroy()
                        null
                    }
                }
            }
        }
    }

    private fun waitForReceiverProposal(
        session: Initialized,
        recvPersister: InMemoryReceiverPersister,
        http: TestHttp,
        relay: String,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        val deadline = System.nanoTime() + POLL_TIMEOUT_NS
        var attempts = 0
        while (System.nanoTime() < deadline) {
            attempts += 1
            val original = pollReceiver(session, recvPersister, http, relay)
            if (original != null) {
                return original.use { processUncheckedProposal(it, recvPersister, receiverRpc) }
            }
            Thread.sleep(POLL_SLEEP_MS)
        }
        fail("Timed out waiting for sender original after $attempts poll(s)")
    }

    private fun processUncheckedProposal(
        proposal: UncheckedOriginalPayload,
        recvPersister: InMemoryReceiverPersister,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        val maybeInputsOwned = proposal.checkBroadcastSuitability(null, MempoolAcceptanceCallback(receiverRpc))
            .use { it.save(recvPersister) }
        return maybeInputsOwned.use { processMaybeInputsOwned(it, recvPersister, receiverRpc) }
    }

    private fun processMaybeInputsOwned(
        proposal: MaybeInputsOwned,
        recvPersister: InMemoryReceiverPersister,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        val maybeInputsSeen = proposal.checkInputsNotOwned(IsInputOwnedCallback(receiverRpc))
            .use { it.save(recvPersister) }
        return maybeInputsSeen.use { processMaybeInputsSeen(it, recvPersister, receiverRpc) }
    }

    private fun processMaybeInputsSeen(
        proposal: MaybeInputsSeen,
        recvPersister: InMemoryReceiverPersister,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        val outputsUnknown = proposal.checkNoInputsSeenBefore(CheckInputsNotSeenCallback())
            .use { it.save(recvPersister) }
        return outputsUnknown.use { processOutputsUnknown(it, recvPersister, receiverRpc) }
    }

    private fun processOutputsUnknown(
        proposal: OutputsUnknown,
        recvPersister: InMemoryReceiverPersister,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        val wantsOutputs = proposal.identifyReceiverOutputs(IsScriptOwnedCallback(receiverRpc))
            .use { it.save(recvPersister) }
        return wantsOutputs.use { processWantsOutputs(it, recvPersister, receiverRpc) }
    }

    private fun processWantsOutputs(
        proposal: WantsOutputs,
        recvPersister: InMemoryReceiverPersister,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        val wantsInputs = proposal.commitOutputs().use { it.save(recvPersister) }
        return wantsInputs.use { processWantsInputs(it, recvPersister, receiverRpc) }
    }

    private fun processWantsInputs(
        proposal: WantsInputs,
        recvPersister: InMemoryReceiverPersister,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        val inputs = getInputs(receiverRpc)
        val wantsFeeRange = try {
            proposal.contributeInputs(inputs).use { contributed ->
                contributed.commitInputs().use { it.save(recvPersister) }
            }
        } finally {
            inputs.forEach { it.close() }
        }
        return wantsFeeRange.use { processWantsFeeRange(it, recvPersister, receiverRpc) }
    }

    private fun processWantsFeeRange(
        proposal: WantsFeeRange,
        recvPersister: InMemoryReceiverPersister,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        val provisional = proposal.applyFeeRange(1u, 10u).use { it.save(recvPersister) }
        return provisional.use { processProvisionalProposal(it, recvPersister, receiverRpc) }
    }

    private fun processProvisionalProposal(
        proposal: ProvisionalProposal,
        recvPersister: InMemoryReceiverPersister,
        receiverRpc: RpcClient,
    ): PayjoinProposal {
        return proposal.finalizeProposal(ProcessPsbtCallback(receiverRpc)).use { it.save(recvPersister) }
    }

    private fun waitForSenderProposal(
        pollingForProposal: PollingForProposal,
        sendPersister: InMemorySenderPersister,
        http: TestHttp,
        relay: String,
    ): String {
        val deadline = System.nanoTime() + POLL_TIMEOUT_NS
        var attempts = 0
        var sender = pollingForProposal
        while (System.nanoTime() < deadline) {
            attempts += 1
            val outcome = sender.createPollRequest(relay).useDisposable { pollReq ->
                val body = http.post(pollReq.request)
                sender.processResponse(body, pollReq.ohttpCtx).use { it.save(sendPersister) }
            }
            when (outcome) {
                // Progress returns a PSBT string, not a live handle; same rule as receiver Progress — do not destroy.
                is PollingForProposalTransitionOutcome.Progress -> return outcome.psbtBase64
                is PollingForProposalTransitionOutcome.Stasis -> {
                    if (sender !== pollingForProposal) {
                        sender.close()
                    }
                    sender = outcome.inner
                    Thread.sleep(POLL_SLEEP_MS)
                }
            }
        }
        fail("Timed out waiting for receiver proposal after $attempts poll(s)")
    }

    private fun finishPayjoin(
        senderRpc: RpcClient,
        receiverRpc: RpcClient,
        psbtBase64: String,
        senderOutpoints: Set<OutpointRef>,
        receiverOutpoints: Set<OutpointRef>,
    ) {
        val payjoinPsbt = Json.parseToJsonElement(rpc(senderRpc, "walletprocesspsbt", jstr(psbtBase64)))
            .jsonObject.getValue("psbt").jsonPrimitive.content
        val finalPsbt = Json.parseToJsonElement(rpc(senderRpc, "finalizepsbt", jstr(payjoinPsbt), "false"))
            .jsonObject.getValue("psbt").jsonPrimitive.content
        val finalTxHex = Json.parseToJsonElement(rpc(senderRpc, "finalizepsbt", jstr(finalPsbt), "true"))
            .jsonObject.getValue("hex").jsonPrimitive.content
        val txid = Json.parseToJsonElement(rpc(senderRpc, "sendrawtransaction", jstr(finalTxHex)))
            .jsonPrimitive.content
        assertTrue(txid.isNotEmpty(), "sendrawtransaction should accept the payjoin")

        val networkFees = Json.parseToJsonElement(rpc(senderRpc, "decodepsbt", jstr(finalPsbt)))
            .jsonObject.getValue("fee").jsonPrimitive.double
        val decodedTx = Json.parseToJsonElement(rpc(senderRpc, "decoderawtransaction", jstr(finalTxHex)))
            .jsonObject
        val vins = decodedTx.getValue("vin").jsonArray
        val vouts = decodedTx.getValue("vout").jsonArray
        assertEquals(2, vins.size)
        assertEquals(1, vouts.size)

        val spent = vins.map { vin ->
            val obj = vin.jsonObject
            OutpointRef(
                obj.getValue("txid").jsonPrimitive.content,
                obj.getValue("vout").jsonPrimitive.double.toInt().toUInt(),
            )
        }.toSet()
        assertTrue(spent.any { it in senderOutpoints }, "final tx should spend a sender input")
        assertTrue(spent.any { it in receiverOutpoints }, "final tx should spend a receiver input")

        val receiverPending = Json.parseToJsonElement(rpc(receiverRpc, "getbalances"))
            .jsonObject.getValue("mine").jsonObject.getValue("untrusted_pending").jsonPrimitive.double
        assertEquals(100.0 - networkFees, receiverPending, 1e-6)
        val senderBalance = Json.parseToJsonElement(rpc(senderRpc, "getbalance")).jsonPrimitive.double
        assertEquals(0.0, senderBalance, 1e-6)
    }
}

private const val POLL_SLEEP_MS = 250L
private const val POLL_TIMEOUT_NS = 30_000_000_000L

private data class OutpointRef(val txid: String, val vout: UInt)

private fun rpc(client: RpcClient, method: String, vararg params: String?): String =
    client.call(method, params.toList())

// String-valued RPC params go through jstr(); JSON structure ([], objects, numbers, true/false) is passed raw.
private fun jstr(value: String): String = buildString {
    append('"')
    for (ch in value) {
        when (ch) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            else -> append(ch)
        }
    }
    append('"')
}

private fun buildSweepPsbt(sender: RpcClient, pjUri: PjUri): String {
    val outputs = "{${jstr(pjUri.address())}:50}"
    val options = """{"lockUnspents":true,"fee_rate":10,"subtractFeeFromOutputs":[0]}"""
    val psbt = Json.parseToJsonElement(
        rpc(sender, "walletcreatefundedpsbt", "[]", outputs, "0", options),
    ).jsonObject.getValue("psbt").jsonPrimitive.content
    return Json.parseToJsonElement(rpc(sender, "walletprocesspsbt", jstr(psbt), "true", jstr("ALL"), "false"))
        .jsonObject.getValue("psbt").jsonPrimitive.content
}

private fun getInputs(rpcConnection: RpcClient): List<InputPair> {
    val utxos = Json.parseToJsonElement(rpc(rpcConnection, "listunspent")).jsonArray
    return utxos.map { utxo ->
        val obj = utxo.jsonObject
        val txid = obj.getValue("txid").jsonPrimitive.content
        val vout = obj.getValue("vout").jsonPrimitive.double.toInt().toUInt()
        val scriptPubkey = HexFormat.of().parseHex(obj.getValue("scriptPubKey").jsonPrimitive.content)
        val amountSat = kotlin.math.round(obj.getValue("amount").jsonPrimitive.double * 100_000_000.0).toULong()
        val txin = TxIn(
            previousOutput = OutPoint(txid, vout),
            scriptSig = ByteArray(0),
            sequence = 0u,
            witness = emptyList(),
        )
        val psbtIn = PsbtInput(
            witnessUtxo = TxOut(amountSat, scriptPubkey),
            redeemScript = null,
            witnessScript = null,
        )
        InputPair(txin, psbtIn, null)
    }
}

private fun listOutpoints(client: RpcClient): Set<OutpointRef> =
    Json.parseToJsonElement(rpc(client, "listunspent")).jsonArray.map { utxo ->
        val obj = utxo.jsonObject
        OutpointRef(
            obj.getValue("txid").jsonPrimitive.content,
            obj.getValue("vout").jsonPrimitive.double.toInt().toUInt(),
        )
    }.toSet()

private class MempoolAcceptanceCallback(private val connection: RpcClient) : CanBroadcast {
    override fun callback(tx: ByteArray): Boolean {
        return try {
            val hexTx = HexFormat.of().formatHex(tx)
            Json.parseToJsonElement(rpc(connection, "testmempoolaccept", "[${jstr(hexTx)}]"))
                .jsonArray[0]
                .jsonObject.getValue("allowed").jsonPrimitive.boolean
        } catch (_: Exception) {
            false
        }
    }
}

private class IsScriptOwnedCallback(private val connection: RpcClient) : IsScriptOwned {
    override fun callback(script: ByteArray): Boolean {
        val decoded = Json.parseToJsonElement(
            rpc(connection, "decodescript", jstr(HexFormat.of().formatHex(script))),
        ).jsonObject
        val candidates = mutableListOf<String>()
        decoded["address"]?.jsonPrimitive?.contentOrNull?.let { candidates.add(it) }
        decoded["addresses"]?.jsonArray?.forEach { item ->
            if (item.jsonPrimitive.isString) candidates.add(item.jsonPrimitive.content)
        }
        decoded["p2sh"]?.jsonPrimitive?.contentOrNull?.let { candidates.add(it) }
        decoded["segwit"]?.jsonObject?.let { segwit ->
            segwit["address"]?.jsonPrimitive?.contentOrNull?.let { candidates.add(it) }
            segwit["addresses"]?.jsonArray?.forEach { item ->
                if (item.jsonPrimitive.isString) candidates.add(item.jsonPrimitive.content)
            }
        }
        return candidates.any { addr ->
            Json.parseToJsonElement(rpc(connection, "getaddressinfo", jstr(addr)))
                .jsonObject["ismine"]?.jsonPrimitive?.booleanOrNull == true
        }
    }
}

private class IsInputOwnedCallback(private val connection: RpcClient) : IsInputOwned {
    override fun callback(outpoint: OutPoint): Boolean {
        val txOut = Json.parseToJsonElement(
            rpc(
                connection,
                "gettxout",
                jstr(outpoint.txid),
                outpoint.vout.toString(),
                "true",
            ),
        )
        if (txOut is JsonNull) return false
        val scriptHex = txOut.jsonObject.getValue("scriptPubKey").jsonObject.getValue("hex").jsonPrimitive.content
        return IsScriptOwnedCallback(connection).callback(HexFormat.of().parseHex(scriptHex))
    }
}

private class CheckInputsNotSeenCallback : IsOutputKnown {
    override fun callback(outpoint: OutPoint): Boolean = false
}

private class ProcessPsbtCallback(private val connection: RpcClient) : ProcessPsbt {
    override fun callback(psbt: String): String =
        Json.parseToJsonElement(rpc(connection, "walletprocesspsbt", jstr(psbt)))
            .jsonObject.getValue("psbt").jsonPrimitive.content
}
