using Payjoin.Http;
using System.Security.Authentication;
using System.Text.Json;
using Xunit;

namespace Payjoin.Tests
{
    /// <summary>
    /// End-to-end walkthrough of the BIP 77 (asynchronous payjoin) flow, and the
    /// usage reference the package README points at. <see cref="TestIntegrationV2ToV2"/>
    /// drives a complete payjoin between two regtest wallets: the receiver opens a
    /// session and produces a BIP 21 URI, the sender posts its original PSBT to an
    /// untrusted directory, the receiver checks that original, contributes an input,
    /// and posts a proposal back, and the sender signs and broadcasts the final
    /// transaction. Neither side talks to the other directly; every message travels
    /// through the directory, encapsulated in OHTTP so the directory cannot link
    /// client identity to session content.
    ///
    /// The callback classes at the top are the seams where the library asks the
    /// wallet questions it cannot answer itself (is this outpoint mine, is this
    /// transaction broadcastable, sign these inputs). A production integration
    /// implements the same interfaces against its own wallet backend.
    /// </summary>
    public class IntegrationTests : IAsyncLifetime
    {
        private static string RpcCall(RpcClient rpc, string method, params string?[] args) => rpc.Call(method, args);
        private TestServices? _services;
        private HttpClient? _httpClient;

        /// <summary>
        /// Answers whether a transaction would be accepted by the mempool, via
        /// Bitcoin Core's testmempoolaccept. The receiver runs this against the
        /// sender's original transaction before doing anything else: that original
        /// is the fallback that pays the receiver if the payjoin never completes,
        /// so a receiver must not build on an original that could never confirm.
        /// </summary>
        private sealed class MempoolAcceptanceCallback : CanBroadcast
        {
            private readonly RpcClient _connection;

            public MempoolAcceptanceCallback(RpcClient connection)
            {
                _connection = connection;
            }

            public bool Callback(byte[] tx)
            {
                try
                {
                    var hexTx = Convert.ToHexString(tx).ToLowerInvariant();
                    var resultJson = RpcCall(_connection, "testmempoolaccept", JsonSerializer.Serialize(new[] { hexTx }));
                    using var doc = JsonDocument.Parse(resultJson);

                    return doc.RootElement[0].GetProperty("allowed").GetBoolean();
                }
                catch
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Answers "does this script belong to my wallet?" by decoding the script
        /// to an address and asking Bitcoin Core getaddressinfo. The receiver uses
        /// this to identify which outputs of the original pay the receiver, since
        /// those are the outputs the payjoin may modify. Outputs are script-keyed
        /// because an output's script in the transaction is the real payment
        /// destination; input ownership uses the outpoint-keyed callback below.
        /// </summary>
        private sealed class IsScriptOwnedCallback : IsScriptOwned
        {
            private readonly RpcClient _connection;

            public IsScriptOwnedCallback(RpcClient connection)
            {
                _connection = connection;
            }

            public bool Callback(byte[] script)
            {
                try
                {
                    var scriptHex = Convert.ToHexString(script).ToLowerInvariant();
                    var decodedScriptJson = RpcCall(_connection, "decodescript", JsonSerializer.Serialize(scriptHex));
                    using var decodedScriptDoc = JsonDocument.Parse(decodedScriptJson);
                    var decoded = decodedScriptDoc.RootElement;

                    var candidates = new List<string>();

                    if (decoded.TryGetProperty("address", out var addressProp) && addressProp.ValueKind == JsonValueKind.String)
                    {
                        candidates.Add(addressProp.GetString()!);
                    }

                    if (decoded.TryGetProperty("addresses", out var addressesProp) && addressesProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var addr in addressesProp.EnumerateArray())
                        {
                            if (addr.ValueKind == JsonValueKind.String)
                            {
                                candidates.Add(addr.GetString()!);
                            }
                        }
                    }

                    if (decoded.TryGetProperty("segwit", out var segwitProp) && segwitProp.ValueKind == JsonValueKind.Object)
                    {
                        if (segwitProp.TryGetProperty("address", out var segwitAddr) && segwitAddr.ValueKind == JsonValueKind.String)
                        {
                            candidates.Add(segwitAddr.GetString()!);
                        }

                        if (segwitProp.TryGetProperty("addresses", out var segwitAddrs) && segwitAddrs.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var addr in segwitAddrs.EnumerateArray())
                            {
                                if (addr.ValueKind == JsonValueKind.String)
                                {
                                    candidates.Add(addr.GetString()!);
                                }
                            }
                        }
                    }

                    foreach (var addr in candidates)
                    {
                        var infoJson = RpcCall(_connection, "getaddressinfo", JsonSerializer.Serialize(addr));
                        using var infoDoc = JsonDocument.Parse(infoJson);
                        if (infoDoc.RootElement.TryGetProperty("ismine", out var isMineProp) && isMineProp.ValueKind == JsonValueKind.True)
                        {
                            return true;
                        }
                    }

                    return false;
                }
                catch
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Answers "does my wallet own the UTXO at this outpoint?". Input ownership
        /// is decided by outpoint, never by the PSBT's script data: a counterparty
        /// can forge a script through a bare witness_utxo, but the outpoint is the
        /// spend claim itself. This keeps the check aligned with how the wallet
        /// recognizes and signs its own inputs.
        /// </summary>
        private sealed class IsInputOwnedCallback : IsInputOwned
        {
            private readonly RpcClient _connection;

            public IsInputOwnedCallback(RpcClient connection)
            {
                _connection = connection;
            }

            public bool Callback(OutPoint outpoint)
            {
                try
                {
                    var txOutJson = RpcCall(
                        _connection,
                        "gettxout",
                        JsonSerializer.Serialize(outpoint.Txid),
                        JsonSerializer.Serialize(outpoint.Vout),
                        JsonSerializer.Serialize(true));
                    using var txOutDoc = JsonDocument.Parse(txOutJson);
                    if (txOutDoc.RootElement.ValueKind == JsonValueKind.Null)
                    {
                        return false;
                    }

                    var scriptHex = txOutDoc.RootElement
                        .GetProperty("scriptPubKey")
                        .GetProperty("hex")
                        .GetString()!;
                    return new IsScriptOwnedCallback(_connection)
                        .Callback(Convert.FromHexString(scriptHex));
                }
                catch
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Answers "have I seen this input in an earlier session?". Automated
        /// receivers track this to stop probing attacks, where a sender retries the
        /// same input across sessions to map the receiver's UTXO set. The test
        /// always answers no; a production receiver persists every outpoint it has
        /// seen and answers from that store.
        /// </summary>
        private sealed class CheckInputsNotSeenCallback : IsOutputKnown
        {
            public bool Callback(OutPoint _outpoint) => false;
        }

        /// <summary>
        /// Signs the receiver's contributed inputs in the finished proposal, via
        /// Bitcoin Core's walletprocesspsbt. This is the last receiver-side step:
        /// after it, the proposal goes back to the sender, who re-signs their own
        /// inputs and broadcasts.
        /// </summary>
        private sealed class ProcessPsbtCallback : ProcessPsbt
        {
            private readonly RpcClient _connection;

            public ProcessPsbtCallback(RpcClient connection)
            {
                _connection = connection;
            }

            public string Callback(string psbt)
            {
                var resJson = RpcCall(_connection, "walletprocesspsbt", JsonSerializer.Serialize(psbt));
                using var doc = JsonDocument.Parse(resJson);

                return doc.RootElement.GetProperty("psbt").GetString()!;
            }
        }

        /// <summary>
        /// Collects the receiver wallet's spendable UTXOs as InputPair candidates
        /// for contribution. An InputPair carries the transaction input plus the
        /// PSBT metadata (here a witness_utxo) the sender needs to see the coin
        /// being spent.
        /// </summary>
        private static InputPair[] GetInputs(RpcClient rpc)
        {
            var utxosJson = RpcCall(rpc, "listunspent");
            using var utxosDoc = JsonDocument.Parse(utxosJson);

            var inputs = new List<InputPair>();
            foreach (var utxo in utxosDoc.RootElement.EnumerateArray())
            {
                var txid = utxo.GetProperty("txid").GetString()!;
                var vout = utxo.GetProperty("vout").GetUInt32();
                var scriptPubKeyHex = utxo.GetProperty("scriptPubKey").GetString()!;
                var amountBtc = utxo.GetProperty("amount").GetDouble();
                var valueSat = (ulong)Math.Round(amountBtc * 100_000_000.0);

                var txin = new TxIn(
                    new OutPoint(txid, vout),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>());

                var txout = new TxOut(valueSat, Convert.FromHexString(scriptPubKeyHex));
                var psbtIn = new PsbtInput(txout, null, null);

                inputs.Add(new InputPair(txin, psbtIn, null));
            }

            return inputs.ToArray();
        }

        /// <summary>
        /// One receiver poll of the directory mailbox, through the OHTTP relay.
        /// The relay sees an encrypted blob and the client address; the directory
        /// sees the blob only. Save persists the step to the session's event log,
        /// and the outcome is either Stasis (nothing arrived yet, poll again
        /// later) or Progress (the sender's original PSBT arrived), in which case
        /// the receiver checklist below runs to completion.
        ///
        /// Each state transition here follows the same shape the whole API uses:
        /// the state object creates a request, the application relays it with its
        /// own HTTP client, the response feeds ProcessResponse, and Save moves the
        /// session to the next persisted state. A crashed application replays the
        /// event log with PayjoinMethods.ReplayReceiverEventLog and resumes from
        /// the same state.
        /// </summary>
        private async Task<PayjoinProposal?> RetrieveReceiverProposal(
            Initialized receiver,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister,
            string ohttpRelay,
            CancellationToken cancellationToken)
        {
            var request = receiver.CreatePollRequest(ohttpRelay);
            var response = await _httpClient!.PostAsync(
                request.Request.Url,
                new ByteArrayContent(request.Request.Body)
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(request.Request.ContentType) }
                },
                cancellationToken);

            var responseBuffer = await response.Content.ReadAsByteArrayAsync(cancellationToken);

            using var transition = receiver.ProcessResponse(responseBuffer, request.ClientResponse);
            using var outcome = transition.Save(recvPersister);

            if (outcome is InitializedTransitionOutcome.Stasis)
            {
                return null;
            }

            if (outcome is InitializedTransitionOutcome.Progress progress)
            {
                using var proposal = progress.Inner;
                return await ProcessUncheckedProposal(proposal, receiverRpc, recvPersister);
            }

            throw new InvalidOperationException("Unknown initialized transition outcome");
        }

        // The methods below are the receiver checklist from BIP 78, one typestate
        // per check. The compiler enforces the order: each state exposes only its
        // own check, and Save yields the next state. A receiver that skips a check
        // does not typecheck.

        /// <summary>
        /// Check 1: the sender's original transaction must be broadcastable. It is
        /// the fallback payment if the payjoin does not complete, and its fee rate
        /// also bounds what the merged transaction can look like.
        /// </summary>
        private Task<PayjoinProposal> ProcessUncheckedProposal(
            UncheckedOriginalPayload proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var checkedTransition = proposal.CheckBroadcastSuitability(null, new MempoolAcceptanceCallback(receiverRpc));
            using var maybeInputsOwned = checkedTransition.Save(recvPersister);

            return ProcessMaybeInputsOwned(maybeInputsOwned, receiverRpc, recvPersister);
        }

        /// <summary>
        /// Check 2: none of the original's inputs may belong to the receiver,
        /// decided by outpoint against the wallet's own records.
        /// Otherwise a malicious sender could get the receiver to sign away a coin
        /// the receiver already owns.
        /// </summary>
        private Task<PayjoinProposal> ProcessMaybeInputsOwned(
            MaybeInputsOwned proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.CheckInputsNotOwned(new IsInputOwnedCallback(receiverRpc));
            using var maybeInputsSeen = transition.Save(recvPersister);

            return ProcessMaybeInputsSeen(maybeInputsSeen, receiverRpc, recvPersister);
        }

        /// <summary>
        /// Check 3: none of the original's inputs may have appeared in an earlier
        /// session. Retried inputs are how a prober maps the receiver's wallet.
        /// </summary>
        private Task<PayjoinProposal> ProcessMaybeInputsSeen(
            MaybeInputsSeen proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.CheckNoInputsSeenBefore(new CheckInputsNotSeenCallback());
            using var outputsUnknown = transition.Save(recvPersister);

            return ProcessOutputsUnknown(outputsUnknown, receiverRpc, recvPersister);
        }

        /// <summary>
        /// Check 4: find which outputs of the original pay the receiver. These are
        /// the outputs the payjoin is allowed to substitute or amend; everything
        /// else belongs to the sender and stays untouched.
        /// </summary>
        private Task<PayjoinProposal> ProcessOutputsUnknown(
            OutputsUnknown proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.IdentifyReceiverOutputs(new IsScriptOwnedCallback(receiverRpc));
            using var wantsOutputs = transition.Save(recvPersister);

            return ProcessWantsOutputs(wantsOutputs, receiverRpc, recvPersister);
        }

        /// <summary>
        /// The receiver may replace its output set here, for example to substitute
        /// a fresh address or split the payment. This walkthrough keeps the
        /// original outputs and just commits them.
        /// </summary>
        private Task<PayjoinProposal> ProcessWantsOutputs(
            WantsOutputs proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.CommitOutputs();
            using var wantsInputs = transition.Save(recvPersister);

            return ProcessWantsInputs(wantsInputs, receiverRpc, recvPersister);
        }

        /// <summary>
        /// The heart of the payjoin: the receiver contributes its own input. The
        /// merged transaction now spends coins from both parties, which is what
        /// breaks the common-input-ownership heuristic. The library selects from
        /// the candidates to avoid unnecessary-input heuristics where it can.
        /// </summary>
        private Task<PayjoinProposal> ProcessWantsInputs(
            WantsInputs proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var contributed = proposal.ContributeInputs(GetInputs(receiverRpc));
            using var transition = contributed.CommitInputs();
            using var wantsFeeRange = transition.Save(recvPersister);

            return ProcessWantsFeeRange(wantsFeeRange, receiverRpc, recvPersister);
        }

        /// <summary>
        /// The receiver's added input makes the transaction larger, and someone
        /// must pay for those bytes. ApplyFeeRange(min, max) bounds the fee rate
        /// the receiver will accept; the library deducts the receiver's share from
        /// the receiver's own output so the sender never pays for the receiver's
        /// contribution.
        /// </summary>
        private Task<PayjoinProposal> ProcessWantsFeeRange(
            WantsFeeRange proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.ApplyFeeRange(1, 10);
            using var provisional = transition.Save(recvPersister);

            return ProcessProvisionalProposal(provisional, receiverRpc, recvPersister);
        }

        /// <summary>
        /// Finalization: the wallet signs the receiver's contributed inputs (see
        /// ProcessPsbtCallback), and the result is the proposal to post back to
        /// the directory for the sender to pick up.
        /// </summary>
        private Task<PayjoinProposal> ProcessProvisionalProposal(
            ProvisionalProposal proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.FinalizeProposal(new ProcessPsbtCallback(receiverRpc));
            var payjoinProposal = transition.Save(recvPersister);

            return Task.FromResult(payjoinProposal);
        }

        public ValueTask InitializeAsync()
        {
            _httpClient = new HttpClient();
            _services = TestServices.Initialize();

            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            _httpClient?.Dispose();
            _services?.Dispose();

            return ValueTask.CompletedTask;
        }

        /// <summary>
        /// Session bootstrap: fetch the directory's OHTTP keys through an OHTTP
        /// relay, so the directory never learns the client's IP address. This is
        /// the first network step of every session; on mainnet the cert parameter
        /// is null and the relay's real TLS certificate is used.
        /// </summary>
        [Fact]
        public async Task FetchAndDecodeOhttpKeysViaRelayProxy()
        {
            var cancellationToken = TestContext.Current.CancellationToken;

            Assert.NotNull(_services);
            _services.WaitForServicesReady();
            var ohttpRelay = _services.OhttpRelayUrl();
            var directory = _services.DirectoryUrl();
            var cert = _services.Cert();

            using var ohttpClient = new OhttpKeysClient(new System.Uri(ohttpRelay), cert);
            using var keys = await ohttpClient.GetOhttpKeysAsync(new System.Uri(directory), cancellationToken);

            Assert.NotNull(keys);
        }

        [Fact]
        public async Task FetchOhttpKeysWithoutTestCertificateThrowsException()
        {
            var cancellationToken = TestContext.Current.CancellationToken;

            Assert.NotNull(_services);
            _services.WaitForServicesReady();
            var ohttpRelay = _services.OhttpRelayUrl();
            var directory = _services.DirectoryUrl();

            using var ohttpClient = new OhttpKeysClient(new System.Uri(ohttpRelay));
            var ex = await Assert.ThrowsAsync<HttpRequestException>(
                () => ohttpClient.GetOhttpKeysAsync(new System.Uri(directory), cancellationToken));

            Assert.IsType<AuthenticationException>(ex.InnerException);
        }

        [Fact]
        public void TestFfiValidation()
        {
            var tooLargeAmount = 21_000_000UL * 100_000_000UL + 1;

            var invalidTxid = new string('0', 128);
            Assert.Throws<InputPairException.InvalidOutPoint>(() =>
            {
                var txin = new TxIn(
                    new OutPoint(invalidTxid, 0),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>()
                );
                var psbtIn = new PsbtInput(
                    new TxOut(tooLargeAmount, new byte[] { 0x6a }),
                    null,
                    null
                );
                new InputPair(txin, psbtIn, null);
            });

            var validTxid = new string('0', 64);
            var amountOutOfRange = Assert.Throws<InputPairException.FfiValidation>(() =>
            {
                var txin = new TxIn(
                    new OutPoint(validTxid, 0),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>()
                );
                var psbtIn = new PsbtInput(
                    new TxOut(tooLargeAmount, new byte[] { 0x6a }),
                    null,
                    null
                );
                new InputPair(txin, psbtIn, null);
            });
            Assert.IsType<FfiValidationException.AmountOutOfRange>(amountOutOfRange.v1);

            var hugeScript = new byte[10_001];
            Array.Fill(hugeScript, (byte)0x51);
            var scriptTooLarge = Assert.Throws<InputPairException.FfiValidation>(() =>
            {
                var txin = new TxIn(
                    new OutPoint(validTxid, 0),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>()
                );
                var psbtIn = new PsbtInput(
                    new TxOut(1, hugeScript),
                    null,
                    null
                );
                new InputPair(txin, psbtIn, null);
            });
            Assert.IsType<FfiValidationException.ScriptTooLarge>(scriptTooLarge.v1);

            var weightOutOfRange = Assert.Throws<InputPairException.FfiValidation>(() =>
            {
                var txin = new TxIn(
                    new OutPoint(validTxid, 0),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>()
                );
                var psbtIn = new PsbtInput(
                    new TxOut(1, new byte[] { 0x6a }),
                    null,
                    null
                );
                new InputPair(txin, psbtIn, new Weight(0));
            });
            Assert.IsType<FfiValidationException.WeightOutOfRange>(weightOutOfRange.v1);

            Assert.NotNull(_services);
            var directory = _services.DirectoryUrl();
            _services.WaitForServicesReady();
            var ohttpKeys = _services.FetchOhttpKeys();

            var recvPersister = new InMemoryReceiverPersister();
            using var receiverBuilder = new ReceiverBuilder("2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", directory, ohttpKeys);
            using var receiveTransition = receiverBuilder.Build();
            using var receiver = receiveTransition.Save(recvPersister);
            using var pjUri = receiver.PjUri();

            var psbt = PayjoinMethods.OriginalPsbt();

            var feeRateOutOfRange = Assert.Throws<SenderInputException.FfiValidation>(() =>
            {
                new SenderBuilder(psbt, pjUri).BuildRecommended(ulong.MaxValue);
            });
            Assert.IsType<FfiValidationException.FeeRateOutOfRange>(feeRateOutOfRange.v1);

            Assert.Throws<FfiValidationException.AmountOutOfRange>(() =>
            {
                pjUri.SetAmountSats(tooLargeAmount);
            });
        }

        /// <summary>
        /// The complete BIP 77 payjoin, receiver and sender in one place. In a real
        /// deployment these are two applications that never talk directly; the
        /// directory carries every message between them, and both sides survive a
        /// restart because every state transition is saved to a persister first.
        /// </summary>
        [Fact]
        public async Task TestIntegrationV2ToV2()
        {
            var cancellationToken = TestContext.Current.CancellationToken;

            using var env = PayjoinMethods.InitBitcoindSenderReceiver();
            using var bitcoind = env.GetBitcoind();
            using var receiver = env.GetReceiver();
            using var sender = env.GetSender();

            var receiverAddressJson = RpcCall(receiver, "getnewaddress");
            var receiverAddress = JsonSerializer.Deserialize<string>(receiverAddressJson)!;

            Assert.NotNull(_services);
            var directory = _services.DirectoryUrl();
            var ohttpRelay = _services.OhttpRelayUrl();
            _services.WaitForServicesReady();

            var ohttpKeys = _services.FetchOhttpKeys();

            // The persisters are the session event logs. Implement
            // JsonReceiverSessionPersister and JsonSenderSessionPersister over your
            // own storage (these in-memory versions append each event to a list);
            // async variants exist for database-backed stores.
            var recvPersister = new InMemoryReceiverPersister();
            var senderPersister = new InMemorySenderPersister();

            // *****************************
            // RECEIVER SIDE
            // Open a session for the receiving address. Save persists the opening
            // event and yields the Initialized state, whose PjUri() is the BIP 21
            // URI to show the sender. Any wallet can pay this URI: a payjoin-aware
            // sender upgrades to a payjoin, any other wallet just sends to the
            // address.
            using var receiverBuilder = new ReceiverBuilder(receiverAddress, directory, ohttpKeys);
            using var receiveTransition = receiverBuilder.Build();
            using var session = receiveTransition.Save(recvPersister);

            // First poll: the sender has not posted anything yet, so the outcome
            // is Stasis and the helper returns null. A production receiver polls
            // on a timer.
            var initial = await RetrieveReceiverProposal(session, receiver, recvPersister, ohttpRelay, cancellationToken);
            Assert.Null(initial);

            // *****************************
            // SENDER SIDE
            // The sender starts from the receiver's BIP 21 URI. In production this
            // arrives as a scanned QR code or a pasted string, and
            // Payjoin.Uri.Parse(...).CheckPjSupported() turns it into the PjUri
            // used below.
            using var pjUri = session.PjUri();

            // The original PSBT is a normal transaction paying the URI's address,
            // built and signed by the sender's wallet. It doubles as the fallback:
            // if the payjoin never completes, this is the transaction that pays
            // the receiver.
            var psbt = BuildSweepPsbt(sender, pjUri);

            // BuildRecommended validates the original against the URI and sets the
            // minimum fee rate (sat/kWU) the sender will accept for the merged
            // transaction. Save persists the sender session the same way the
            // receiver side persists its own.
            using var senderBuilder = new SenderBuilder(psbt, pjUri);
            using var senderTransition = senderBuilder.BuildRecommended(1000);
            using var reqCtx = senderTransition.Save(senderPersister);

            // Post the original PSBT to the receiver's directory mailbox, OHTTP
            // encapsulated like every other hop.
            using var request = reqCtx.CreateV2PostRequest(ohttpRelay);
            var response = await _httpClient!.PostAsync(
                request.Request.Url,
                new ByteArrayContent(request.Request.Body)
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(request.Request.ContentType) }
                },
                cancellationToken);

            var responseBuffer = await response.Content.ReadAsByteArrayAsync(cancellationToken);

            // Process sender response
            using var senderResponseTransition = reqCtx.ProcessResponse(responseBuffer, request.OhttpCtx);
            using var sendCtx = senderResponseTransition.Save(senderPersister);

            // *********************
            // RECEIVER SIDE
            // This poll finds the sender's original in the mailbox and runs the
            // whole receiver pipeline (checks 1 through 4, output commit, input
            // contribution, fee range, signing; see the Process* methods above).
            // The result is the receiver-signed payjoin proposal.
            using var payjoinProposal = await RetrieveReceiverProposal(session, receiver, recvPersister, ohttpRelay, cancellationToken);
            Assert.NotNull(payjoinProposal);
            Assert.IsType<PayjoinProposal>(payjoinProposal);

            // Post the proposal to the sender's mailbox and confirm the directory
            // accepted it.
            using var proposalRequest = payjoinProposal!.CreatePostRequest(ohttpRelay);
            using var proposalResponse = await _httpClient.PostAsync(
                proposalRequest.Request.Url,
                new ByteArrayContent(proposalRequest.Request.Body)
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(proposalRequest.Request.ContentType) }
                },
                cancellationToken);

            var proposalResponseBuffer = await proposalResponse.Content.ReadAsByteArrayAsync(cancellationToken);
            payjoinProposal.ProcessResponse(proposalResponseBuffer, proposalRequest.ClientResponse);

            // *******************************
            // SENDER SIDE (FINALIZATION)
            // Poll the sender mailbox until the receiver's proposal arrives
            // (Stasis until then, like the receiver's poll). The library has
            // already validated the proposal against the original during
            // ProcessResponse; what comes out is the payjoin PSBT waiting for the
            // sender's signatures.
            PollingForProposalTransitionOutcome? pollOutcome = null;
            var attempts = 0;
            while (true)
            {
                using var pollRequest = sendCtx.CreatePollRequest(ohttpRelay);
                using var pollResponse = await _httpClient.PostAsync(
                    pollRequest.Request.Url,
                    new ByteArrayContent(pollRequest.Request.Body)
                    {
                        Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(pollRequest.Request.ContentType) }
                    },
                    cancellationToken);

                var pollResponseBuffer = await pollResponse.Content.ReadAsByteArrayAsync(cancellationToken);
                using var pollTransition = sendCtx.ProcessResponse(pollResponseBuffer, pollRequest.OhttpCtx);
                pollOutcome = pollTransition.Save(senderPersister);

                if (pollOutcome is PollingForProposalTransitionOutcome.Progress)
                {
                    break;
                }

                attempts += 1;
                if (attempts >= 3)
                {
                    Assert.Fail("Timed out waiting for receiver");
                    return;
                }
            }

            var progressOutcome = (PollingForProposalTransitionOutcome.Progress)pollOutcome!;

            // The sender re-signs its own inputs. The receiver's contributed input
            // changed the transaction, so the original signatures no longer apply.
            var payjoinPsbt = progressOutcome.PsbtBase64;
            var processedPsbtJson = RpcCall(sender, "walletprocesspsbt", JsonSerializer.Serialize(payjoinPsbt));
            using var processedDoc = JsonDocument.Parse(processedPsbtJson);
            var processedPsbt = processedDoc.RootElement.GetProperty("psbt").GetString()!;

            // Finalize PSBT with the sender client
            var finalPsbtJson = RpcCall(sender, "finalizepsbt", JsonSerializer.Serialize(processedPsbt), JsonSerializer.Serialize(false));
            using var finalDoc = JsonDocument.Parse(finalPsbtJson);
            var finalPsbt = finalDoc.RootElement.GetProperty("psbt").GetString()!;

            // Extract and broadcast transaction
            var extractionJson = RpcCall(sender, "finalizepsbt", JsonSerializer.Serialize(processedPsbt), JsonSerializer.Serialize(true));
            using var extractionDoc = JsonDocument.Parse(extractionJson);
            var finalHex = extractionDoc.RootElement.GetProperty("hex").GetString()!;
            RpcCall(sender, "sendrawtransaction", JsonSerializer.Serialize(finalHex));

            // *******************************
            // VERIFY RESULTS
            // The broadcast transaction spends one input from each party into the
            // receiver's output: on chain it is indistinguishable from an ordinary
            // transaction, which is the point.
            // Decode PSBT to get network fees
            var decodedPsbtJson = RpcCall(sender, "decodepsbt", JsonSerializer.Serialize(finalPsbt));
            using var decodedPsbtDoc = JsonDocument.Parse(decodedPsbtJson);
            var networkFees = decodedPsbtDoc.RootElement.GetProperty("fee").GetDouble();

            // Decode transaction to verify structure
            var decodedTxJson = RpcCall(sender, "decoderawtransaction", JsonSerializer.Serialize(finalHex));
            using var decodedTxDoc = JsonDocument.Parse(decodedTxJson);
            var decodedTx = decodedTxDoc.RootElement;

            var inputCount = decodedTx.GetProperty("vin").GetArrayLength();
            var outputCount = decodedTx.GetProperty("vout").GetArrayLength();

            Assert.Equal(2, inputCount); // Should have 2 inputs (sender + receiver)
            Assert.Equal(1, outputCount); // Should have 1 output (to receiver)

            // Verify receiver balance
            var receiverBalancesJson = RpcCall(receiver, "getbalances");
            using var receiverBalancesDoc = JsonDocument.Parse(receiverBalancesJson);
            var receiverBalance = receiverBalancesDoc.RootElement
                .GetProperty("mine")
                .GetProperty("untrusted_pending")
                .GetDouble();

            Assert.Equal(100 - networkFees, receiverBalance, 6); // 100 BTC minus network fees

            // Verify sender balance (should be 0 after sweeping)
            var senderBalanceJson = RpcCall(sender, "getbalance");
            var senderBalance = JsonSerializer.Deserialize<double>(senderBalanceJson);
            Assert.Equal(0.0, senderBalance);
        }

        private static string BuildSweepPsbt(RpcClient sender, PjUri pjUri)
        {
            var outputs = new Dictionary<string, double>
            {
                [pjUri.Address()] = 50
            };

            var psbtJson = RpcCall(
                sender,
                "walletcreatefundedpsbt",
                JsonSerializer.Serialize(Array.Empty<object>()),
                JsonSerializer.Serialize(outputs),
                JsonSerializer.Serialize(0),
                JsonSerializer.Serialize(new { lockUnspents = true, fee_rate = 10, subtractFeeFromOutputs = new[] { 0 } }));
            using var psbtDoc = JsonDocument.Parse(psbtJson);
            var psbt = psbtDoc.RootElement.GetProperty("psbt").GetString()!;

            var processed = RpcCall(
                sender,
                "walletprocesspsbt",
                JsonSerializer.Serialize(psbt),
                JsonSerializer.Serialize(true),
                JsonSerializer.Serialize("ALL"),
                JsonSerializer.Serialize(false));
            using var processedDoc = JsonDocument.Parse(processed);
            return processedDoc.RootElement.GetProperty("psbt").GetString()!;
        }
    }
}
