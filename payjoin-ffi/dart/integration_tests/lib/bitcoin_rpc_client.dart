import 'dart:convert';
import 'dart:typed_data';
import 'http_client.dart';

class BitcoinRpcClient {
  final PayjoinHttpClient _httpClient;
  final String _rpcUrl;
  final String _basicAuth;

  int _requestId = 0;

  BitcoinRpcClient({
    required String rpcUrl,
    required String rpcUser,
    required String rpcPassword,
    Duration? timeout,
  })  : _rpcUrl = rpcUrl,
        _basicAuth = base64Encode(utf8.encode('$rpcUser:$rpcPassword')),
        _httpClient = PayjoinHttpClient(
          timeout: timeout ?? const Duration(seconds: 30),
          defaultHeaders: {
            'Content-Type': 'application/json',
            'Authorization':
                'Basic ${base64Encode(utf8.encode('$rpcUser:$rpcPassword'))}',
          },
        );

  Future<bool> testMempoolAccept(String rawTx) async {
    try {
      final result = await _callRpc('testmempoolaccept', [
        [rawTx]
      ]);

      if (result is List && result.isNotEmpty) {
        final firstResult = result[0] as Map<String, dynamic>;
        return firstResult['allowed'] == true;
      }
      return false;
    } catch (e) {
      print('testMempoolAccept failed: $e');
      return false;
    }
  }

  Future<List<Map<String, dynamic>>> testMempoolAcceptMultiple(
      List<String> rawtxs) async {
    final result = await _callRpc('testmempoolaccept', [rawtxs]);
    return List<Map<String, dynamic>>.from(result as List);
  }

  Future<String> sendRawTransaction(String rawTx) async {
    final result = await _callRpc('sendrawtransaction', [rawTx]);
    return result as String;
  }

  Future<Map<String, dynamic>> getBlockchainInfo() async {
    final result = await _callRpc('getblockchaininfo', []);
    return result as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> walletProcessPsbt(String psbt,
      {bool sign = true}) async {
    final result = await _callRpc('walletprocesspsbt', [psbt, sign]);
    return result as Map<String, dynamic>;
  }

  Future<List<Map<String, dynamic>>> listUnspent({
    int minconf = 1,
    int maxconf = 9999999,
    List<String>? addresses,
  }) async {
    final params = <dynamic>[minconf, maxconf];
    if (addresses != null) {
      params.add(addresses);
    }

    final result = await _callRpc('listunspent', params);
    return List<Map<String, dynamic>>.from(result as List);
  }

  Future<List<String>> generateToAddress(int nblocks, String address) async {
    final result = await _callRpc('generatetoaddress', [nblocks, address]);
    return List<String>.from(result as List);
  }

  Future<String> getNewAddress({String? label, String? addressType}) async {
    final params = <dynamic>[];
    if (label != null) params.add(label);
    if (addressType != null) params.add(addressType);

    final result = await _callRpc('getnewaddress', params);
    return result as String;
  }

  Future<double> getBalance() async {
    final result = await _callRpc('getbalance', []);
    return (result as num).toDouble();
  }

  Future<bool> isTransactionInMempool(String txid) async {
    try {
      final mempoolInfo = await _callRpc('getmempoolentry', [txid]);
      return mempoolInfo != null;
    } catch (e) {
      return false;
    }
  }

  Future<Map<String, dynamic>> getRawTransaction(String txid,
      {bool verbose = true}) async {
    final result = await _callRpc('getrawtransaction', [txid, verbose]);
    return result as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> createWallet(String walletName,
      {bool disablePrivateKeys = false, bool blank = false}) async {
    final result = await _callRpc('createwallet', [
      walletName,
      disablePrivateKeys,
      blank,
    ]);
    return result as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> loadWallet(String walletName) async {
    final result = await _callRpc('loadwallet', [walletName]);
    return result as Map<String, dynamic>;
  }

  Future<List<String>> listWallets() async {
    final result = await _callRpc('listwallets', []);
    return List<String>.from(result as List);
  }

  Future<void> ensureTestWallet({String walletName = 'test_wallet'}) async {
    try {
      final loadedWallets = await listWallets();

      if (loadedWallets.isNotEmpty) {
        print('Wallet already loaded: ${loadedWallets.first}');
        return;
      }

      try {
        await loadWallet(walletName);
        return;
      } catch (e) {
        print('wallet $walletName not found');
      }

      final result = await createWallet(walletName);
      print('Created test wallet: ${result['name']}');
    } catch (e) {
      throw BitcoinRpcException('Failed to ensure test wallet: $e');
    }
  }

  Future<Map<String, dynamic>> walletCreateFundedPsbt({
    required List<Map<String, dynamic>> inputs,
    required Map<String, dynamic> outputs,
    int? locktime,
    Map<String, dynamic>? options,
  }) async {
    final params = <dynamic>[inputs, outputs];
    if (locktime != null) params.add(locktime);
    if (options != null) params.add(options);

    final result = await _callRpc('walletcreatefundedpsbt', params);
    return result as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> finalizePsbt(String psbt,
      {bool extract = true}) async {
    final result = await _callRpc('finalizepsbt', [psbt, extract]);
    return result as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> decodeRawTransaction(String hexstring) async {
    final result = await _callRpc('decoderawtransaction', [hexstring]);
    return result as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> getBalances() async {
    final result = await _callRpc('getbalances', []);
    return result as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> getTransaction(String txid,
      {bool verbose = true}) async {
    final result = await _callRpc('gettransaction', [txid, verbose]);
    return result as Map<String, dynamic>;
  }

  Future<List<String>> getRawMempool() async {
    final result = await _callRpc('getrawmempool', []);
    return List<String>.from(result as List);
  }

  Future<Map<String, dynamic>> getAddressInfo(String address) async {
    final result = await _callRpc('getaddressinfo', [address]);
    return result as Map<String, dynamic>;
  }

  Future<dynamic> callRpc(String method, List<dynamic> params) async {
    return await _callRpc(method, params);
  }

  Future<dynamic> _callRpc(String method, List<dynamic> params) async {
    final requestId = ++_requestId;

    final requestBody = {
      'jsonrpc': '2.0',
      'id': requestId,
      'method': method,
      'params': params,
    };

    final jsonRequest = json.encode(requestBody);
    final requestBytes = Uint8List.fromList(utf8.encode(jsonRequest));

    final response = await _httpClient.postToDirectory(
      url: _rpcUrl,
      body: requestBytes,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic $_basicAuth',
      },
    );

    if (!response.isSuccessful) {
      throw BitcoinRpcException(
        'RPC call failed with status ${response.statusCode}: ${response.bodyAsString}',
      );
    }

    final responseJson =
        json.decode(response.bodyAsString) as Map<String, dynamic>;

    if (responseJson.containsKey('error') && responseJson['error'] != null) {
      final error = responseJson['error'] as Map<String, dynamic>;
      throw BitcoinRpcException(
        'Bitcoin RPC error ${error['code']}: ${error['message']}',
      );
    }

    return responseJson['result'];
  }

  void close() {
    _httpClient.close();
  }
}

class BitcoinTestConfig {
  static const String defaultRpcUrl = 'http://localhost:18443';
  static const String defaultRpcUser = 'test';
  static const String defaultRpcPassword = 'test';
  static const Duration defaultTimeout = Duration(seconds: 30);

  static BitcoinRpcClient createTestClient({
    String? rpcUrl,
    String? rpcUser,
    String? rpcPassword,
    Duration? timeout,
  }) {
    return BitcoinRpcClient(
      rpcUrl: rpcUrl ?? defaultRpcUrl,
      rpcUser: rpcUser ?? defaultRpcUser,
      rpcPassword: rpcPassword ?? defaultRpcPassword,
      timeout: timeout ?? defaultTimeout,
    );
  }

  static Future<bool> isRegtestAvailable({BitcoinRpcClient? client}) async {
    final rpcClient = client ?? createTestClient();
    try {
      final info = await rpcClient.getBlockchainInfo();
      final isRegtest = info['chain'] == 'regtest';
      if (client == null) rpcClient.close();
      return isRegtest;
    } catch (e) {
      if (client == null) rpcClient.close();
      return false;
    }
  }
}

class BitcoinRpcException implements Exception {
  final String message;

  const BitcoinRpcException(this.message);

  @override
  String toString() => 'BitcoinRpcException: $message';
}
