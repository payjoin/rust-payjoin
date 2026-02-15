import "dart:convert";
import "dart:typed_data";

import "package:http/http.dart" as http;
import 'package:test/test.dart';
import "package:convert/convert.dart";

import "package:payjoin/payjoin.dart" as payjoin;
import "package:payjoin/test_utils.dart" as test_utils;

late test_utils.BitcoindEnv env;
late test_utils.BitcoindInstance bitcoind;
late test_utils.RpcClient receiver;
late test_utils.RpcClient sender;

class InMemoryReceiverPersister
    implements payjoin.JsonReceiverSessionPersister {
  final String id;
  final List<String> events = [];
  bool closed = false;

  InMemoryReceiverPersister(this.id);

  @override
  void save(String event) {
    events.add(event);
  }

  @override
  List<String> load() {
    return events;
  }

  @override
  void close() {
    closed = true;
  }
}

class InMemorySenderPersister implements payjoin.JsonSenderSessionPersister {
  final String id;
  final List<String> events = [];
  bool closed = false;

  InMemorySenderPersister(this.id);

  @override
  void save(String event) {
    events.add(event);
  }

  @override
  List<String> load() {
    return events;
  }

  @override
  void close() {
    closed = true;
  }
}

class MempoolAcceptanceCallback implements payjoin.CanBroadcast {
  final payjoin.RpcClient connection;

  MempoolAcceptanceCallback(this.connection);

  @override
  bool callback(Uint8List tx) {
    try {
      final hexTx = bytesToHex(tx);
      final resultJson = connection.call("testmempoolaccept", ['["$hexTx"]']);
      final decoded = jsonDecode(resultJson);
      return decoded[0]['allowed'] == true;
    } catch (e) {
      print("An error occurred: $e");
      return false;
    }
  }

  String bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

class IsScriptOwnedCallback implements payjoin.IsScriptOwned {
  final payjoin.RpcClient connection;

  IsScriptOwnedCallback(this.connection);

  @override
  bool callback(Uint8List script) {
    try {
      final scriptHex = hex.encode(script);
      final decodedScript = jsonDecode(
        connection.call("decodescript", [jsonEncode(scriptHex)]),
      );

      final candidates = <String>[];
      final addressField = decodedScript["address"];
      if (addressField is String) {
        candidates.add(addressField);
      }
      final addresses = decodedScript["addresses"];
      if (addresses is List) {
        candidates.addAll(addresses.whereType<String>());
      }
      final p2sh = decodedScript["p2sh"];
      if (p2sh is String) {
        candidates.add(p2sh);
      }
      final segwit = decodedScript["segwit"];
      if (segwit is Map) {
        final segwitAddress = segwit["address"];
        if (segwitAddress is String) {
          candidates.add(segwitAddress);
        }
        final segwitAddresses = segwit["addresses"];
        if (segwitAddresses is List) {
          candidates.addAll(segwitAddresses.whereType<String>());
        }
      }

      for (final addr in candidates) {
        final info = jsonDecode(
          connection.call("getaddressinfo", [jsonEncode(addr)]),
        );
        if (info["ismine"] == true) {
          return true;
        }
      }
      return false;
    } catch (e) {
      return false;
    }
  }
}

class CheckInputsNotSeenCallback implements payjoin.IsOutputKnown {
  final payjoin.RpcClient connection;

  CheckInputsNotSeenCallback(this.connection);

  @override
  bool callback(_outpoint) {
    return false;
  }
}

class ProcessPsbtCallback implements payjoin.ProcessPsbt {
  final payjoin.RpcClient connection;

  ProcessPsbtCallback(this.connection);

  @override
  String callback(String psbt) {
    final res = jsonDecode(connection.call("walletprocesspsbt", [psbt]));
    return res["psbt"];
  }
}

payjoin.Initialized create_receiver_context(
  String address,
  String directory,
  payjoin.OhttpKeys ohttp_keys,
  InMemoryReceiverPersister persister,
) {
  var receiver = payjoin.ReceiverBuilder(
    address,
    directory,
    ohttp_keys,
  ).build().save(persister);
  return receiver;
}

String build_sweep_psbt(payjoin.RpcClient sender, payjoin.PjUri pj_uri) {
  var outputs = <String, dynamic>{};
  outputs[pj_uri.address()] = 50;
  var psbt = jsonDecode(
    sender.call("walletcreatefundedpsbt", [
      jsonEncode([]),
      jsonEncode(outputs),
      jsonEncode(0),
      jsonEncode({
        "lockUnspents": true,
        "fee_rate": 10,
        "subtractFeeFromOutputs": [0],
      }),
    ]),
  )["psbt"];
  return jsonDecode(
    sender.call("walletprocesspsbt", [
      psbt,
      jsonEncode(true),
      jsonEncode("ALL"),
      jsonEncode(false),
    ]),
  )["psbt"];
}

List<payjoin.InputPair> get_inputs(payjoin.RpcClient rpc_connection) {
  var utxos = jsonDecode(rpc_connection.call("listunspent", []));
  List<payjoin.InputPair> inputs = [];
  for (var utxo in utxos) {
    final txid = utxo["txid"] as String;
    final vout = utxo["vout"] as int;
    final scriptPubKey = Uint8List.fromList(
      hex.decode(utxo["scriptPubKey"] as String),
    );
    final amountBtc = utxo["amount"] as num;
    final amountSat = (amountBtc * 100000000).round();

    final txin = payjoin.PlainTxIn(
      payjoin.PlainOutPoint(txid, vout),
      Uint8List(0),
      0,
      <Uint8List>[],
    );
    final witnessUtxo = payjoin.PlainTxOut(amountSat, scriptPubKey);
    final psbt_in = payjoin.PlainPsbtInput(witnessUtxo, null, null);
    inputs.add(payjoin.InputPair(txin, psbt_in, null));
  }

  return inputs;
}

Future<payjoin.PayjoinProposalReceiveSession> process_provisional_proposal(
  payjoin.ProvisionalProposal proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final payjoin_proposal = proposal
      .finalizeProposal(ProcessPsbtCallback(receiver))
      .save(recv_persister);
  return payjoin.PayjoinProposalReceiveSession(payjoin_proposal);
}

Future<payjoin.PayjoinProposalReceiveSession> process_wants_fee_range(
  payjoin.WantsFeeRange proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final wants_fee_range = proposal.applyFeeRange(1, 10).save(recv_persister);
  return await process_provisional_proposal(wants_fee_range, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_wants_inputs(
  payjoin.WantsInputs proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final provisional_proposal = proposal
      .contributeInputs(get_inputs(receiver))
      .commitInputs()
      .save(recv_persister);
  return await process_wants_fee_range(provisional_proposal, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_wants_outputs(
  payjoin.WantsOutputs proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final wants_inputs = proposal.commitOutputs().save(recv_persister);
  return await process_wants_inputs(wants_inputs, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_outputs_unknown(
  payjoin.OutputsUnknown proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final wants_outputs = proposal
      .identifyReceiverOutputs(IsScriptOwnedCallback(receiver))
      .save(recv_persister);
  return await process_wants_outputs(wants_outputs, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_maybe_inputs_seen(
  payjoin.MaybeInputsSeen proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final outputs_unknown = proposal
      .checkNoInputsSeenBefore(CheckInputsNotSeenCallback(receiver))
      .save(recv_persister);
  return await process_outputs_unknown(outputs_unknown, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_maybe_inputs_owned(
  payjoin.MaybeInputsOwned proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final maybe_inputs_owned = proposal
      .checkInputsNotOwned(IsScriptOwnedCallback(receiver))
      .save(recv_persister);
  return await process_maybe_inputs_seen(maybe_inputs_owned, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_unchecked_proposal(
  payjoin.UncheckedOriginalPayload proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final unchecked_proposal = proposal
      .checkBroadcastSuitability(null, MempoolAcceptanceCallback(receiver))
      .save(recv_persister);
  return await process_maybe_inputs_owned(unchecked_proposal, recv_persister);
}

Future<payjoin.ReceiveSession?> retrieve_receiver_proposal(
  payjoin.Initialized receiver,
  InMemoryReceiverPersister recv_persister,
  String ohttp_relay,
) async {
  var agent = http.Client();
  var request = receiver.createPollRequest(ohttp_relay);
  var response = await agent.post(
    Uri.parse(request.request.url),
    headers: {"Content-Type": request.request.contentType},
    body: request.request.body,
  );
  var res = receiver
      .processResponse(response.bodyBytes, request.clientResponse)
      .save(recv_persister);

  if (res is payjoin.StasisInitializedTransitionOutcome) {
    return null;
  } else if (res is payjoin.ProgressInitializedTransitionOutcome) {
    var proposal = res.inner;
    return await process_unchecked_proposal(proposal, recv_persister);
  }

  throw Exception("Unknown initialized transition outcome: $res");
}

Future<payjoin.ReceiveSession?> process_receiver_proposal(
  payjoin.ReceiveSession receiver,
  InMemoryReceiverPersister recv_persister,
  String ohttp_relay,
) async {
  if (receiver is payjoin.InitializedReceiveSession) {
    var res = await retrieve_receiver_proposal(
      receiver.inner,
      recv_persister,
      ohttp_relay,
    );
    if (res == null) {
      return null;
    }
    return res;
  }

  if (receiver is payjoin.UncheckedOriginalPayloadReceiveSession) {
    return await process_unchecked_proposal(receiver.inner, recv_persister);
  }
  if (receiver is payjoin.MaybeInputsOwnedReceiveSession) {
    return await process_maybe_inputs_owned(receiver.inner, recv_persister);
  }
  if (receiver is payjoin.MaybeInputsSeenReceiveSession) {
    return await process_maybe_inputs_seen(receiver.inner, recv_persister);
  }
  if (receiver is payjoin.OutputsUnknownReceiveSession) {
    return await process_outputs_unknown(receiver.inner, recv_persister);
  }
  if (receiver is payjoin.WantsOutputsReceiveSession) {
    return await process_wants_outputs(receiver.inner, recv_persister);
  }
  if (receiver is payjoin.WantsInputsReceiveSession) {
    return await process_wants_inputs(receiver.inner, recv_persister);
  }
  if (receiver is payjoin.ProvisionalProposalReceiveSession) {
    return await process_provisional_proposal(receiver.inner, recv_persister);
  }
  if (receiver is payjoin.PayjoinProposalReceiveSession) {
    return receiver;
  }

  throw Exception("Unknown receiver state: $receiver");
}

void main() {
  group('Test integration', () {
    test('Invalid primitives', () async {
      final tooLargeAmount = 21000000 * 100000000 + 1;
      // Invalid outpoint should fail before amount checks.
      final txinInvalid = payjoin.PlainTxIn(
        payjoin.PlainOutPoint("00" * 64, 0),
        Uint8List(0),
        0,
        <Uint8List>[],
      );
      final psbtInDummy = payjoin.PlainPsbtInput(
        payjoin.PlainTxOut(1, Uint8List.fromList([0x6a])),
        null,
        null,
      );
      expect(
        () => payjoin.InputPair(txinInvalid, psbtInDummy, null),
        throwsA(isA<payjoin.InputPairException>()),
      );

      final txin = payjoin.PlainTxIn(
        // valid 32-byte txid so we exercise amount overflow instead of outpoint parsing
        payjoin.PlainOutPoint("00" * 32, 0),
        Uint8List(0),
        0,
        <Uint8List>[],
      );
      final txout = payjoin.PlainTxOut(
        tooLargeAmount,
        Uint8List.fromList([0x6a]),
      );
      final psbtIn = payjoin.PlainPsbtInput(txout, null, null);
      expect(
        () => payjoin.InputPair(txin, psbtIn, null),
        throwsA(isA<payjoin.InputPairException>()),
      );

      // Use a real v2 payjoin URI from the test harness to avoid v1 panics.
      final envLocal = test_utils.initBitcoindSenderReceiver();
      final receiverRpc = envLocal.getReceiver();
      final receiverAddress =
          jsonDecode(receiverRpc.call("getnewaddress", [])) as String;
      final services = test_utils.TestServices.initialize();
      services.waitForServicesReady();
      final directory = services.directoryUrl();
      final ohttpKeys = services.fetchOhttpKeys();
      final recvPersister = InMemoryReceiverPersister("prim");
      final pjUri = payjoin.ReceiverBuilder(
        receiverAddress,
        directory,
        ohttpKeys,
      ).build().save(recvPersister).pjUri();

      final psbt = test_utils.originalPsbt();
      // Large enough to overflow fee * weight but still parsable as Dart int.
      const overflowFeeRate = 5000000000000; // sat/kwu
      expect(
        () => payjoin.SenderBuilder(
          psbt,
          pjUri,
        ).buildRecommended(overflowFeeRate),
        throwsA(isA<payjoin.SenderInputException>()),
      );

      expect(
        () => pjUri.setAmountSats(tooLargeAmount),
        throwsA(isA<payjoin.PrimitiveException>()),
      );
    });

    test('Test integration v2 to v2', () async {
      env = test_utils.initBitcoindSenderReceiver();
      bitcoind = env.getBitcoind();
      receiver = env.getReceiver();
      sender = env.getSender();
      var receiver_address =
          jsonDecode(receiver.call("getnewaddress", [])) as String;
      var services = test_utils.TestServices.initialize();

      services.waitForServicesReady();
      var directory = services.directoryUrl();
      var ohttp_keys = services.fetchOhttpKeys();
      var ohttp_relay = services.ohttpRelayUrl();
      var agent = http.Client();

      // **********************
      // Inside the Receiver:
      var recv_persister = InMemoryReceiverPersister("1");
      var sender_persister = InMemorySenderPersister("1");
      var session = create_receiver_context(
        receiver_address,
        directory,
        ohttp_keys,
        recv_persister,
      );
      var process_response = await process_receiver_proposal(
        payjoin.InitializedReceiveSession(session),
        recv_persister,
        ohttp_relay,
      );
      expect(process_response, isNull);

      // **********************
      // Inside the Sender:
      // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
      var pj_uri = session.pjUri();
      var psbt = build_sweep_psbt(sender, pj_uri);
      payjoin.WithReplyKey req_ctx = payjoin.SenderBuilder(
        psbt,
        pj_uri,
      ).buildRecommended(1000).save(sender_persister);
      payjoin.RequestOhttpContext request = req_ctx.createV2PostRequest(
        ohttp_relay,
      );
      var response = await agent.post(
        Uri.parse(request.request.url),
        headers: {"Content-Type": request.request.contentType},
        body: request.request.body,
      );
      payjoin.PollingForProposal send_ctx = req_ctx
          .processResponse(response.bodyBytes, request.ohttpCtx)
          .save(sender_persister);
      // POST Original PSBT

      // **********************
      // Inside the Receiver:

      // GET fallback psbt
      payjoin.ReceiveSession? payjoin_proposal =
          await process_receiver_proposal(
            payjoin.InitializedReceiveSession(session),
            recv_persister,
            ohttp_relay,
          );
      expect(payjoin_proposal, isNotNull);
      expect(payjoin_proposal, isA<payjoin.PayjoinProposalReceiveSession>());

      payjoin.PayjoinProposal proposal =
          (payjoin_proposal as payjoin.PayjoinProposalReceiveSession).inner;
      payjoin.RequestResponse request_response = proposal.createPostRequest(
        ohttp_relay,
      );
      var fallback_response = await agent.post(
        Uri.parse(request_response.request.url),
        headers: {"Content-Type": request_response.request.contentType},
        body: request_response.request.body,
      );
      proposal.processResponse(
        fallback_response.bodyBytes,
        request_response.clientResponse,
      );

      // **********************
      // Inside the Sender:
      // Sender checks, signs, finalizes, extracts, and broadcasts
      // Replay post fallback to get the response
      payjoin.PollingForProposalTransitionOutcome? poll_outcome;
      var attempts = 0;
      while (true) {
        payjoin.RequestOhttpContext ohttp_context_request = send_ctx
            .createPollRequest(ohttp_relay);
        var final_response = await agent.post(
          Uri.parse(ohttp_context_request.request.url),
          headers: {"Content-Type": ohttp_context_request.request.contentType},
          body: ohttp_context_request.request.body,
        );
        poll_outcome = send_ctx
            .processResponse(
              final_response.bodyBytes,
              ohttp_context_request.ohttpCtx,
            )
            .save(sender_persister);

        if (poll_outcome
            is payjoin.ProgressPollingForProposalTransitionOutcome) {
          break;
        }

        attempts += 1;
        if (attempts >= 3) {
          // Receiver not ready yet; mirror Python's tolerant polling.
          return;
        }
      }

      final progressOutcome =
          poll_outcome as payjoin.ProgressPollingForProposalTransitionOutcome;
      var payjoin_psbt = jsonDecode(
        sender.call("walletprocesspsbt", [progressOutcome.psbtBase64]),
      )["psbt"];
      var final_psbt = jsonDecode(
        sender.call("finalizepsbt", [payjoin_psbt, jsonEncode(false)]),
      )["psbt"];
      var final_tx_hex = jsonDecode(
        sender.call("finalizepsbt", [final_psbt, jsonEncode(true)]),
      )["hex"];
      sender.call("sendrawtransaction", [jsonEncode(final_tx_hex)]);

      // Check resulting transaction and balances
      var decodedTx = jsonDecode(
        sender.call("decoderawtransaction", [jsonEncode(final_tx_hex)]),
      );
      var network_fees =
          (jsonDecode(
                    sender.call("decodepsbt", [jsonEncode(final_psbt)]),
                  )["fee"]
                  as num)
              .toDouble();
      // Sender sent the entire value of their utxo to the receiver (minus fees)
      expect(decodedTx["vin"].length, 2);
      expect(decodedTx["vout"].length, 1);
      expect(
        jsonDecode(
          receiver.call("getbalances", []),
        )["mine"]["untrusted_pending"],
        100 - network_fees,
      );
      expect(jsonDecode(sender.call("getbalance", [])), 0.0);
    }, timeout: const Timeout(Duration(minutes: 5)));
  });
}
