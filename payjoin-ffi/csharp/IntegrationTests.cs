using System.Text.Json;
using uniffi.payjoin;
using Xunit;

namespace Payjoin.Tests
{
    public class IntegrationTests : IAsyncLifetime
    {
        private static string RpcCall(RpcClient rpc, string method, params string?[] args) => rpc.Call(method, args);
        private BitcoindEnv? _env;
        private TestServices? _services;
        private HttpClient? _httpClient;

        private sealed class InMemoryReceiverPersister : JsonReceiverSessionPersister
        {
            private readonly List<string> _events = new();
            public RpcClient? Connection { get; set; }

            public void Save(string @event) => _events.Add(@event);
            public string[] Load() => _events.ToArray();
            public void Close() { }
        }

        private sealed class InMemorySenderPersister : JsonSenderSessionPersister
        {
            private readonly List<string> _events = new();

            public void Save(string @event) => _events.Add(@event);
            public string[] Load() => _events.ToArray();
            public void Close() { }
        }

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

        private sealed class CheckInputsNotSeenCallback : IsOutputKnown
        {
            public bool Callback(PlainOutPoint _outpoint) => false;
        }

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

                var txin = new PlainTxIn(
                    new PlainOutPoint(txid, vout),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>());

                var txout = new PlainTxOut(valueSat, Convert.FromHexString(scriptPubKeyHex));
                var psbtIn = new PlainPsbtInput(txout, null, null);

                inputs.Add(new InputPair(txin, psbtIn, null));
            }

            return inputs.ToArray();
        }

        private async Task<PayjoinProposal?> RetrieveReceiverProposal(
            Initialized receiver,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister,
            string ohttpRelay,
            CancellationToken cancellationToken)
        {
            var request = receiver.CreatePollRequest(ohttpRelay);
            var response = await _httpClient!.PostAsync(
                request.request.url,
                new ByteArrayContent(request.request.body)
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(request.request.contentType) }
                },
                cancellationToken);

            var responseBuffer = await response.Content.ReadAsByteArrayAsync(cancellationToken);

            using var transition = receiver.ProcessResponse(responseBuffer, request.clientResponse);
            using var outcome = transition.Save(recvPersister);

            if (outcome is InitializedTransitionOutcome.Stasis)
            {
                return null;
            }

            if (outcome is InitializedTransitionOutcome.Progress progress)
            {
                using var proposal = progress.inner;
                return await ProcessUncheckedProposal(proposal, receiverRpc, recvPersister);
            }

            throw new InvalidOperationException("Unknown initialized transition outcome");
        }

        private Task<PayjoinProposal> ProcessUncheckedProposal(
            UncheckedOriginalPayload proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var checkedTransition = proposal.CheckBroadcastSuitability(null, new MempoolAcceptanceCallback(receiverRpc));
            using var maybeInputsOwned = checkedTransition.Save(recvPersister);

            return ProcessMaybeInputsOwned(maybeInputsOwned, receiverRpc, recvPersister);
        }

        private Task<PayjoinProposal> ProcessMaybeInputsOwned(
            MaybeInputsOwned proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.CheckInputsNotOwned(new IsScriptOwnedCallback(receiverRpc));
            using var maybeInputsSeen = transition.Save(recvPersister);

            return ProcessMaybeInputsSeen(maybeInputsSeen, receiverRpc, recvPersister);
        }

        private Task<PayjoinProposal> ProcessMaybeInputsSeen(
            MaybeInputsSeen proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.CheckNoInputsSeenBefore(new CheckInputsNotSeenCallback());
            using var outputsUnknown = transition.Save(recvPersister);

            return ProcessOutputsUnknown(outputsUnknown, receiverRpc, recvPersister);
        }

        private Task<PayjoinProposal> ProcessOutputsUnknown(
            OutputsUnknown proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.IdentifyReceiverOutputs(new IsScriptOwnedCallback(receiverRpc));
            using var wantsOutputs = transition.Save(recvPersister);

            return ProcessWantsOutputs(wantsOutputs, receiverRpc, recvPersister);
        }

        private Task<PayjoinProposal> ProcessWantsOutputs(
            WantsOutputs proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.CommitOutputs();
            using var wantsInputs = transition.Save(recvPersister);

            return ProcessWantsInputs(wantsInputs, receiverRpc, recvPersister);
        }

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

        private Task<PayjoinProposal> ProcessWantsFeeRange(
            WantsFeeRange proposal,
            RpcClient receiverRpc,
            InMemoryReceiverPersister recvPersister)
        {
            using var transition = proposal.ApplyFeeRange(1, 10);
            using var provisional = transition.Save(recvPersister);

            return ProcessProvisionalProposal(provisional, receiverRpc, recvPersister);
        }

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
            _env?.Dispose();

            return ValueTask.CompletedTask;
        }

        [Fact]
        public void TestFfiValidation()
        {
            var tooLargeAmount = 21_000_000UL * 100_000_000UL + 1;

            var invalidTxid = new string('0', 128);
            Assert.Throws<InputPairException.InvalidOutPoint>(() =>
            {
                var txin = new PlainTxIn(
                    new PlainOutPoint(invalidTxid, 0),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>()
                );
                var psbtIn = new PlainPsbtInput(
                    new PlainTxOut(tooLargeAmount, new byte[] { 0x6a }),
                    null,
                    null
                );
                new InputPair(txin, psbtIn, null);
            });

            var validTxid = new string('0', 64);
            Assert.Throws<InputPairException.FfiValidation>(() =>
            {
                var txin = new PlainTxIn(
                    new PlainOutPoint(validTxid, 0),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>()
                );
                var psbtIn = new PlainPsbtInput(
                    new PlainTxOut(tooLargeAmount, new byte[] { 0x6a }),
                    null,
                    null
                );
                new InputPair(txin, psbtIn, null);
            });

            var hugeScript = new byte[10_001];
            Array.Fill(hugeScript, (byte)0x51);
            Assert.Throws<InputPairException.FfiValidation>(() =>
            {
                var txin = new PlainTxIn(
                    new PlainOutPoint(validTxid, 0),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>()
                );
                var psbtIn = new PlainPsbtInput(
                    new PlainTxOut(1, hugeScript),
                    null,
                    null
                );
                new InputPair(txin, psbtIn, null);
            });

            Assert.Throws<InputPairException.FfiValidation>(() =>
            {
                var txin = new PlainTxIn(
                    new PlainOutPoint(validTxid, 0),
                    Array.Empty<byte>(),
                    0,
                    Array.Empty<byte[]>()
                );
                var psbtIn = new PlainPsbtInput(
                    new PlainTxOut(1, new byte[] { 0x6a }),
                    null,
                    null
                );
                new InputPair(txin, psbtIn, new PlainWeight(0));
            });
            
            var directory = _services!.DirectoryUrl();
            _services.WaitForServicesReady();
            var ohttpKeys = _services.FetchOhttpKeys();

            var recvPersister = new InMemoryReceiverPersister();
            using var receiverBuilder = new ReceiverBuilder("2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", directory, ohttpKeys);
            using var receiveTransition = receiverBuilder.Build();
            using var receiver = receiveTransition.Save(recvPersister);
            using var pjUri = receiver.PjUri();

            var psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

            Assert.Throws<SenderInputException.FfiValidation>(() =>
            {
                new SenderBuilder(psbt, pjUri).BuildRecommended(ulong.MaxValue);
            });

            Assert.Throws<FfiValidationException.AmountOutOfRange>(() =>
            {
                pjUri.SetAmountSats(tooLargeAmount);
            });
        }

        [Fact]
        public async Task TestIntegrationV2ToV2()
        {
            var cancellationToken = TestContext.Current.CancellationToken;
            try
            {
                _env = PayjoinMethods.InitBitcoindSenderReceiver();
            }
            catch (Exception ex)
            {
                Assert.Skip($"test-utils are not available: {ex.GetType().Name}: {ex.Message}");
            }

            _ = _env.GetBitcoind();
            var receiver = _env.GetReceiver();
            var sender = _env.GetSender();

            var receiverAddressJson = RpcCall(receiver, "getnewaddress");
            var receiverAddress = JsonSerializer.Deserialize<string>(receiverAddressJson)!;

            var directory = _services!.DirectoryUrl();
            var ohttpRelay = _services.OhttpRelayUrl();
            _services.WaitForServicesReady();

            var ohttpKeys = _services.FetchOhttpKeys();

            var recvPersister = new InMemoryReceiverPersister { Connection = receiver };
            var senderPersister = new InMemorySenderPersister();

            using var receiverBuilder = new ReceiverBuilder(receiverAddress, directory, ohttpKeys);
            using var receiveTransition = receiverBuilder.Build();
            using var session = receiveTransition.Save(recvPersister);

            var initial = await RetrieveReceiverProposal(session, receiver, recvPersister, ohttpRelay, cancellationToken);
            Assert.Null(initial);

            // *****************************
            // SENDER SIDE
            // Get PayJoin URI from receiver
            using var pjUri = session.PjUri();

            // Create a funded PSBT that sweeps all funds to receiver
            var psbt = BuildSweepPsbt(sender, pjUri);

            // Build sender request context
            using var senderBuilder = new SenderBuilder(psbt, pjUri);
            using var senderTransition = senderBuilder.BuildRecommended(1000);
            using var reqCtx = senderTransition.Save(senderPersister);

            // Create V2 POST request with OHTTP
            using var request = reqCtx.CreateV2PostRequest(ohttpRelay);
            var response = await _httpClient!.PostAsync(
                request.request.url,
                new ByteArrayContent(request.request.body)
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(request.request.contentType) }
                },
                cancellationToken);

            var responseBuffer = await response.Content.ReadAsByteArrayAsync(cancellationToken);

            // Process sender response
            using var senderResponseTransition = reqCtx.ProcessResponse(responseBuffer, request.ohttpCtx);
            using var sendCtx = senderResponseTransition.Save(senderPersister);

            // *********************
            // RECEIVER SIDE
            // Poll for the proposal
            using var payjoinProposal = await RetrieveReceiverProposal(session, receiver, recvPersister, ohttpRelay, cancellationToken);
            Assert.NotNull(payjoinProposal);
            Assert.IsType<PayjoinProposal>(payjoinProposal);

            // Post the payjoin proposal back to the directory
            using var proposalRequest = payjoinProposal!.CreatePostRequest(ohttpRelay);
            using var proposalResponse = await _httpClient.PostAsync(
                proposalRequest.request.url,
                new ByteArrayContent(proposalRequest.request.body)
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(proposalRequest.request.contentType) }
                },
                cancellationToken);

            var proposalResponseBuffer = await proposalResponse.Content.ReadAsByteArrayAsync(cancellationToken);
            payjoinProposal.ProcessResponse(proposalResponseBuffer, proposalRequest.clientResponse);

            // *******************************
            // SENDER SIDE (FINALIZATION)
            // Poll for the final payjoin PSBT
            PollingForProposalTransitionOutcome? pollOutcome = null;
            var attempts = 0;
            while (true)
            {
                using var pollRequest = sendCtx.CreatePollRequest(ohttpRelay);
                using var pollResponse = await _httpClient.PostAsync(
                    pollRequest.request.url,
                    new ByteArrayContent(pollRequest.request.body)
                    {
                        Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(pollRequest.request.contentType) }
                    },
                    cancellationToken);

                var pollResponseBuffer = await pollResponse.Content.ReadAsByteArrayAsync(cancellationToken);
                using var pollTransition = sendCtx.ProcessResponse(pollResponseBuffer, pollRequest.ohttpCtx);
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

            // Sign the payjoin PSBT
            var payjoinPsbt = progressOutcome.psbtBase64;
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
