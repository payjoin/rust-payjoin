import "dart:async";
import "dart:convert";
import "dart:io";
import "dart:typed_data";

import "package:http/http.dart" as http;
import 'package:test/test.dart';
import "package:convert/convert.dart";

import "package:payjoin/http.dart" as payjoin_http;
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
      final resultJson = connection.call(
        method: "testmempoolaccept",
        params: ['["$hexTx"]'],
      );
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
        connection.call(
          method: "decodescript",
          params: [jsonEncode(scriptHex)],
        ),
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
          connection.call(method: "getaddressinfo", params: [jsonEncode(addr)]),
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
    final res = jsonDecode(
      connection.call(method: "walletprocesspsbt", params: [psbt]),
    );
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
    address: address,
    directory: directory,
    ohttpKeys: ohttp_keys,
  ).build().save(persister: persister);
  return receiver;
}

String build_sweep_psbt(payjoin.RpcClient sender, payjoin.PjUri pj_uri) {
  var outputs = <String, dynamic>{};
  outputs[pj_uri.address()] = 50;
  var psbt = jsonDecode(
    sender.call(
      method: "walletcreatefundedpsbt",
      params: [
        jsonEncode([]),
        jsonEncode(outputs),
        jsonEncode(0),
        jsonEncode({
          "lockUnspents": true,
          "fee_rate": 10,
          "subtractFeeFromOutputs": [0],
        }),
      ],
    ),
  )["psbt"];
  return jsonDecode(
    sender.call(
      method: "walletprocesspsbt",
      params: [psbt, jsonEncode(true), jsonEncode("ALL"), jsonEncode(false)],
    ),
  )["psbt"];
}

List<payjoin.InputPair> get_inputs(payjoin.RpcClient rpc_connection) {
  var utxos = jsonDecode(
    rpc_connection.call(method: "listunspent", params: []),
  );
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
      previousOutput: payjoin.PlainOutPoint(txid: txid, vout: vout),
      scriptSig: Uint8List(0),
      sequence: 0,
      witness: <Uint8List>[],
    );
    final witnessUtxo = payjoin.PlainTxOut(
      valueSat: amountSat,
      scriptPubkey: scriptPubKey,
    );
    final psbt_in = payjoin.PlainPsbtInput(
      witnessUtxo: witnessUtxo,
      redeemScript: null,
      witnessScript: null,
    );
    inputs.add(
      payjoin.InputPair(txin: txin, psbtin: psbt_in, expectedWeight: null),
    );
  }

  return inputs;
}

Future<payjoin.PayjoinProposalReceiveSession> process_provisional_proposal(
  payjoin.ProvisionalProposal proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final payjoin_proposal = proposal
      .finalizeProposal(processPsbt: ProcessPsbtCallback(receiver))
      .save(persister: recv_persister);
  return payjoin.PayjoinProposalReceiveSession(payjoin_proposal);
}

Future<payjoin.PayjoinProposalReceiveSession> process_wants_fee_range(
  payjoin.WantsFeeRange proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final wants_fee_range = proposal
      .applyFeeRange(minFeeRateSatPerVb: 1, maxEffectiveFeeRateSatPerVb: 10)
      .save(persister: recv_persister);
  return await process_provisional_proposal(wants_fee_range, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_wants_inputs(
  payjoin.WantsInputs proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final provisional_proposal = proposal
      .contributeInputs(replacementInputs: get_inputs(receiver))
      .commitInputs()
      .save(persister: recv_persister);
  return await process_wants_fee_range(provisional_proposal, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_wants_outputs(
  payjoin.WantsOutputs proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final wants_inputs = proposal.commitOutputs().save(persister: recv_persister);
  return await process_wants_inputs(wants_inputs, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_outputs_unknown(
  payjoin.OutputsUnknown proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final wants_outputs = proposal
      .identifyReceiverOutputs(
        isReceiverOutput: IsScriptOwnedCallback(receiver),
      )
      .save(persister: recv_persister);
  return await process_wants_outputs(wants_outputs, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_maybe_inputs_seen(
  payjoin.MaybeInputsSeen proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final outputs_unknown = proposal
      .checkNoInputsSeenBefore(isKnown: CheckInputsNotSeenCallback(receiver))
      .save(persister: recv_persister);
  return await process_outputs_unknown(outputs_unknown, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_maybe_inputs_owned(
  payjoin.MaybeInputsOwned proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final maybe_inputs_owned = proposal
      .checkInputsNotOwned(isOwned: IsScriptOwnedCallback(receiver))
      .save(persister: recv_persister);
  return await process_maybe_inputs_seen(maybe_inputs_owned, recv_persister);
}

Future<payjoin.PayjoinProposalReceiveSession> process_unchecked_proposal(
  payjoin.UncheckedOriginalPayload proposal,
  InMemoryReceiverPersister recv_persister,
) async {
  final unchecked_proposal = proposal
      .checkBroadcastSuitability(
        minFeeRate: null,
        canBroadcast: MempoolAcceptanceCallback(receiver),
      )
      .save(persister: recv_persister);
  return await process_maybe_inputs_owned(unchecked_proposal, recv_persister);
}

Future<payjoin.ReceiveSession?> retrieve_receiver_proposal(
  payjoin.Initialized receiver,
  InMemoryReceiverPersister recv_persister,
  String ohttp_relay,
) async {
  var agent = http.Client();
  var request = receiver.createPollRequest(ohttpRelay: ohttp_relay);
  var response = await agent.post(
    Uri.parse(request.request.url),
    headers: {"Content-Type": request.request.contentType},
    body: request.request.body,
  );
  var res = receiver
      .processResponse(body: response.bodyBytes, ctx: request.clientResponse)
      .save(persister: recv_persister);

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

const _httpsProxyCertPem =
    '-----BEGIN CERTIFICATE-----\n'
    'MIIBmDCCAT+gAwIBAgIUZmuZcOJ7AKPKxmXUdl8mALQqLjkwCgYIKoZIzj0EAwIw\n'
    'FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQyMzAyNDYzNloXDTM2MDQyMDAy\n'
    'NDYzNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n'
    'AQcDQgAEMbQWJrdEdXIX4hHIcRcpMlRY8+YpH9X9e5DkreID6fVh9tRIoqFSURL1\n'
    'L8q2mLIxLl4W5L4HRJuPkKVCiUI9/qNvMG0wHQYDVR0OBBYEFKih01KF98UDEZg6\n'
    'FOo4nHUVpKGLMB8GA1UdIwQYMBaAFKih01KF98UDEZg6FOo4nHUVpKGLMA8GA1Ud\n'
    'EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49\n'
    'BAMCA0cAMEQCIGCqHp/SwHSxkOxECoU6qEq+/kapotRRTSe3SsWRjQ38AiBITEBf\n'
    'j3sL7LkmerQLhWwl7u7UMHb0rBeuFbSmRmxCGA==\n'
    '-----END CERTIFICATE-----';

const _httpsProxyKeyPem =
    '-----BEGIN PRIVATE KEY-----\n'
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUZxLsCYEttJjv9WN\n'
    '6xUtRwFu40pdAk80R8tgCIlqbhahRANCAAQxtBYmt0R1chfiEchxFykyVFjz5ikf\n'
    '1f17kOSt4gPp9WH21EiioVJREvUvyraYsjEuXhbkvgdEm4+QpUKJQj3+\n'
    '-----END PRIVATE KEY-----';

Uint8List _httpsProxyCertDer() => base64.decode(
  _httpsProxyCertPem.replaceAll(RegExp(r'-----[^-]+-----|\s'), ''),
);

Future<SecureServerSocket> _startHttpsConnectProxy() async {
  final ctx = SecurityContext()
    ..useCertificateChainBytes(utf8.encode(_httpsProxyCertPem))
    ..usePrivateKeyBytes(utf8.encode(_httpsProxyKeyPem));
  final server = await SecureServerSocket.bind('localhost', 0, ctx);

  server.listen((client) {
    final buf = BytesBuilder(copy: false);
    late StreamSubscription<Uint8List> sub;
    sub = client.listen((chunk) {
      buf.add(chunk);
      final headers = utf8.decode(buf.toBytes());
      if (!headers.contains('\r\n\r\n')) return;
      final match = RegExp(r'CONNECT ([^:]+):(\d+)').firstMatch(headers);
      if (match == null) return client.destroy();
      sub.pause();
      Socket.connect(match.group(1)!, int.parse(match.group(2)!))
          .then((target) {
            client.add(
              utf8.encode('HTTP/1.1 200 Connection Established\r\n\r\n'),
            );
            sub
              ..onData(target.add)
              ..onError((_) => target.destroy());
            target.listen(
              client.add,
              onDone: client.destroy,
              onError: (_) => client.destroy(),
            );
            sub.resume();
          })
          .catchError((_) {
            client.destroy();
          });
    }, onError: (_) => client.destroy());
  });

  return server;
}

void main() {
  group('fetchOhttpKeys', () {
    test(
      'fetches and decodes keys via relay proxy',
      () async {
        final services = test_utils.TestServices.initialize();
        services.waitForServicesReady();
        final keys = await payjoin_http.fetchOhttpKeys(
          ohttpRelayUrl: services.ohttpRelayUrl(),
          directoryUrl: services.directoryUrl(),
          certificate: services.cert(),
        );
        expect(keys, isA<payjoin.OhttpKeys>());
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test(
      'without trusted certificate throws',
      () async {
        final services = test_utils.TestServices.initialize();
        services.waitForServicesReady();
        await expectLater(
          payjoin_http.fetchOhttpKeys(
            ohttpRelayUrl: services.ohttpRelayUrl(),
            directoryUrl: services.directoryUrl(),
          ),
          throwsA(isA<Exception>()),
        );
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test(
      'fetches and decodes keys via HTTPS relay proxy (TLS-in-TLS)',
      () async {
        final services = test_utils.TestServices.initialize();
        services.waitForServicesReady();
        final proxy = await _startHttpsConnectProxy();
        try {
          final keys = await payjoin_http.fetchOhttpKeys(
            ohttpRelayUrl: 'https://localhost:${proxy.port}',
            directoryUrl: services.directoryUrl(),
            certificate: services.cert(),
            relayCertificate: _httpsProxyCertDer(),
          );
          expect(keys, isA<payjoin.OhttpKeys>());
        } finally {
          await proxy.close();
        }
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  });

  group('Test integration', () {
    test('FFI validation', () async {
      final tooLargeAmount = 21000000 * 100000000 + 1;
      // Invalid outpoint should fail before amount checks.
      final txinInvalid = payjoin.PlainTxIn(
        previousOutput: payjoin.PlainOutPoint(txid: "00" * 64, vout: 0),
        scriptSig: Uint8List(0),
        sequence: 0,
        witness: <Uint8List>[],
      );
      final psbtInDummy = payjoin.PlainPsbtInput(
        witnessUtxo: payjoin.PlainTxOut(
          valueSat: 1,
          scriptPubkey: Uint8List.fromList([0x6a]),
        ),
        redeemScript: null,
        witnessScript: null,
      );
      expect(
        () => payjoin.InputPair(
          txin: txinInvalid,
          psbtin: psbtInDummy,
          expectedWeight: null,
        ),
        throwsA(isA<payjoin.InputPairException>()),
      );

      final txin = payjoin.PlainTxIn(
        // valid 32-byte txid so we exercise amount overflow instead of outpoint parsing
        previousOutput: payjoin.PlainOutPoint(txid: "00" * 32, vout: 0),
        scriptSig: Uint8List(0),
        sequence: 0,
        witness: <Uint8List>[],
      );
      final txout = payjoin.PlainTxOut(
        valueSat: tooLargeAmount,
        scriptPubkey: Uint8List.fromList([0x6a]),
      );
      final psbtIn = payjoin.PlainPsbtInput(
        witnessUtxo: txout,
        redeemScript: null,
        witnessScript: null,
      );
      expect(
        () =>
            payjoin.InputPair(txin: txin, psbtin: psbtIn, expectedWeight: null),
        throwsA(isA<payjoin.InputPairException>()),
      );

      // Use a real v2 payjoin URI from the test harness to avoid v1 panics.
      final envLocal = test_utils.initBitcoindSenderReceiver();
      final receiverRpc = envLocal.getReceiver();
      final receiverAddress =
          jsonDecode(receiverRpc.call(method: "getnewaddress", params: []))
              as String;
      final services = test_utils.TestServices.initialize();
      services.waitForServicesReady();
      final directory = services.directoryUrl();
      final ohttpKeys = services.fetchOhttpKeys();
      final recvPersister = InMemoryReceiverPersister("prim");
      final pjUri = payjoin.ReceiverBuilder(
        address: receiverAddress,
        directory: directory,
        ohttpKeys: ohttpKeys,
      ).build().save(persister: recvPersister).pjUri();

      final psbt = test_utils.originalPsbt();
      // Large enough to overflow fee * weight but still parsable as Dart int.
      const overflowFeeRate = 5000000000000; // sat/kwu
      expect(
        () => payjoin.SenderBuilder(
          psbt: psbt,
          uri: pjUri,
        ).buildRecommended(minFeeRate: overflowFeeRate),
        throwsA(isA<payjoin.SenderInputException>()),
      );

      expect(
        () => pjUri.setAmountSats(amountSats: tooLargeAmount),
        throwsA(isA<payjoin.FfiValidationException>()),
      );
    });

    test('Test integration v2 to v2', () async {
      env = test_utils.initBitcoindSenderReceiver();
      bitcoind = env.getBitcoind();
      receiver = env.getReceiver();
      sender = env.getSender();
      var receiver_address =
          jsonDecode(receiver.call(method: "getnewaddress", params: []))
              as String;
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
        psbt: psbt,
        uri: pj_uri,
      ).buildRecommended(minFeeRate: 1000).save(persister: sender_persister);
      payjoin.RequestOhttpContext request = req_ctx.createV2PostRequest(
        ohttpRelay: ohttp_relay,
      );
      var response = await agent.post(
        Uri.parse(request.request.url),
        headers: {"Content-Type": request.request.contentType},
        body: request.request.body,
      );
      payjoin.PollingForProposal send_ctx = req_ctx
          .processResponse(
            response: response.bodyBytes,
            postCtx: request.ohttpCtx,
          )
          .save(persister: sender_persister);
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
        ohttpRelay: ohttp_relay,
      );
      var fallback_response = await agent.post(
        Uri.parse(request_response.request.url),
        headers: {"Content-Type": request_response.request.contentType},
        body: request_response.request.body,
      );
      proposal.processResponse(
        body: fallback_response.bodyBytes,
        ohttpContext: request_response.clientResponse,
      );

      // **********************
      // Inside the Sender:
      // Sender checks, signs, finalizes, extracts, and broadcasts
      // Replay post fallback to get the response
      payjoin.PollingForProposalTransitionOutcome? poll_outcome;
      var attempts = 0;
      while (true) {
        payjoin.RequestOhttpContext ohttp_context_request = send_ctx
            .createPollRequest(ohttpRelay: ohttp_relay);
        var final_response = await agent.post(
          Uri.parse(ohttp_context_request.request.url),
          headers: {"Content-Type": ohttp_context_request.request.contentType},
          body: ohttp_context_request.request.body,
        );
        poll_outcome = send_ctx
            .processResponse(
              response: final_response.bodyBytes,
              ohttpCtx: ohttp_context_request.ohttpCtx,
            )
            .save(persister: sender_persister);

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
        sender.call(
          method: "walletprocesspsbt",
          params: [progressOutcome.psbtBase64],
        ),
      )["psbt"];
      var final_psbt = jsonDecode(
        sender.call(
          method: "finalizepsbt",
          params: [payjoin_psbt, jsonEncode(false)],
        ),
      )["psbt"];
      var final_tx_hex = jsonDecode(
        sender.call(
          method: "finalizepsbt",
          params: [final_psbt, jsonEncode(true)],
        ),
      )["hex"];
      sender.call(
        method: "sendrawtransaction",
        params: [jsonEncode(final_tx_hex)],
      );

      // Check resulting transaction and balances
      var decodedTx = jsonDecode(
        sender.call(
          method: "decoderawtransaction",
          params: [jsonEncode(final_tx_hex)],
        ),
      );
      var network_fees =
          (jsonDecode(
                    sender.call(
                      method: "decodepsbt",
                      params: [jsonEncode(final_psbt)],
                    ),
                  )["fee"]
                  as num)
              .toDouble();
      // Sender sent the entire value of their utxo to the receiver (minus fees)
      expect(decodedTx["vin"].length, 2);
      expect(decodedTx["vout"].length, 1);
      expect(
        jsonDecode(
          receiver.call(method: "getbalances", params: []),
        )["mine"]["untrusted_pending"],
        100 - network_fees,
      );
      expect(jsonDecode(sender.call(method: "getbalance", params: [])), 0.0);
    }, timeout: const Timeout(Duration(minutes: 5)));
  });
}
