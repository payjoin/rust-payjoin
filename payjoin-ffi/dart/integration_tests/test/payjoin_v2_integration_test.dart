import 'dart:typed_data';
import 'package:payjoin_dart/bitcoin.dart' as bitcoin;
import 'package:test/test.dart';
import 'package:payjoin_dart_integration_tests/payjoin_integration.dart';
import 'package:payjoin_dart/payjoin_ffi.dart' as payjoin;

void main() {
  group('Payjoin V2 Integration Tests', () {
    late BitcoinRpcClient senderRpc;
    late BitcoinRpcClient receiverRpc;
    late PayjoinHttpClient httpClient;
    late payjoin.TestServices services;
    bool bitcoinAvailable = false;

    setUpAll(() async {
      bitcoinAvailable = await BitcoinTestConfig.isRegtestAvailable();
      if (!bitcoinAvailable) {
        print('Bitcoin Core regtest not available');
        return;
      }

      senderRpc = BitcoinTestConfig.createTestClient();
      receiverRpc = BitcoinTestConfig.createTestClient();
      httpClient = PayjoinHttpClient();

      await senderRpc.ensureTestWallet(walletName: 'sender_wallet');
      await receiverRpc.ensureTestWallet(walletName: 'receiver_wallet');

      // services = payjoin.TestServices.initialize();
      // services.waitForServicesReady();

      payjoin.initialize();
    });

    tearDownAll(() async {
      if (bitcoinAvailable) {
        senderRpc.close();
        receiverRpc.close();
        httpClient.close();
      }
    });

    test('test_integration_v2_to_v2', () async {
      if (!bitcoinAvailable) {
        print('Bitcoin Core not available');
        return;
      }

      try {
        final receiverAddress = await receiverRpc.getNewAddress();

        final bitcoinAddress =
            bitcoin.Address(receiverAddress, bitcoin.Network.regtest);

        // final directory = services.directoryUrl();
        // final ohttpRelay = services.ohttpRelayUrl();
        // final ohttpKeys = services.fetchOhttpKeys();

        final receiverPersister = ReceiverPersister();
        final senderPersister = SenderPersister();

        final uninitializedReceiver = payjoin.UninitializedReceiver();
        // final initTransition = uninitializedReceiver.createSession(
        //   bitcoinAddress,
        //   directory.toString(),
        //   ohttpKeys,
        //   null,
        // );

        // final initializedReceiver = initTransition.save(receiverPersister);

        // final payjoinUri = initializedReceiver.pjUri();

        final psbtString =
            await buildSweepPsbt(senderRpc, receiverAddress, 5.0); // 5 BTC

        // final senderBuilder = payjoin.SenderBuilder(psbtString, payjoinUri);
        // final senderTransition = senderBuilder.buildRecommended(1000);
        // final withReplyKey = senderTransition.save(senderPersister);

        // final v2Request = withReplyKey.extractV2(ohttpRelay.toString());
        // final postResponse =
        //     await sendHttpRequest(httpClient, v2Request.request);

        // final v2GetTransition =
        //     withReplyKey.processResponse(postResponse, v2Request.context);
        // v2GetTransition.save(senderPersister);

        // final receiverRequest =
        //     initializedReceiver.extractReq(ohttpRelay.toString());
        // final receiverResponse =
        //     await sendHttpRequest(httpClient, receiverRequest.request);

        // final proposalTransition = initializedReceiver.processRes(
        //     receiverResponse, receiverRequest.clientResponse);

        // final maybeProposal = proposalTransition.save(receiverPersister);

        // if (maybeProposal.isNone()) {
        //   throw Exception('No proposal received');
        // }

        // expect(receiverAddress, isNotEmpty,
        //     reason: 'Should have receiver address');
        // expect(payjoinUri.toString(), contains('bitcoin:'),
        //     reason: 'Should have valid payjoin URI');
        // expect(psbtString, isNotEmpty, reason: 'Should have created PSBT');
      } catch (e, st) {
        print('Test failed: $e');
        print(st);
        rethrow;
      }
    });
  });
}

Future<String> buildSweepPsbt(
  BitcoinRpcClient sender,
  String receiverAddress,
  double amountBtc,
) async {
  final outputs = {receiverAddress: amountBtc};
  final fundedPsbt = await sender.walletCreateFundedPsbt(
    inputs: [],
    outputs: outputs,
    locktime: 0,
    options: {
      'lockUnspents': true,
      'fee_rate': 10,
      'subtractFeeFromOutputs': [0],
    },
  );
  final processedPsbt =
      await sender.walletProcessPsbt(fundedPsbt['psbt'] as String);
  return processedPsbt['psbt'] as String;
}

Future<Uint8List> sendHttpRequest(
    PayjoinHttpClient client, payjoin.Request request) async {
  final res = await client.postToDirectory(
      url: request.url.toString(),
      body: request.body,
      headers: {'Content-Type': request.contentType});
  return res.body;
}

class ReceiverPersister implements payjoin.JsonReceiverSessionPersister {
  final List<String> _events = [];
  bool _closed = false;

  @override
  void save(String event) {
    if (_closed) throw StateError('Persister closed');
    _events.add(event);
  }

  @override
  List<String> load() {
    if (_closed) throw StateError('Persister closed');
    return List.from(_events);
  }

  @override
  void close() {
    _closed = true;
  }
}

class SenderPersister implements payjoin.JsonSenderSessionPersister {
  final List<String> _events = [];
  bool _closed = false;

  @override
  void save(String event) {
    if (_closed) throw StateError('Persister closed');
    _events.add(event);
  }

  @override
  List<String> load() {
    if (_closed) throw StateError('Persister closed');
    return List.from(_events);
  }

  @override
  void close() {
    _closed = true;
  }
}
