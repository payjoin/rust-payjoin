import 'dart:typed_data';
import 'package:payjoin_dart_integration_tests/bitcoin_rpc_client.dart';

import 'package:payjoin_dart/payjoin_ffi.dart' as payjoin;
import 'package:payjoin_dart/bitcoin.dart' as bitcoin;

class CanBroadcastCallback implements payjoin.CanBroadcast {
  final BitcoinRpcClient _rpc;
  bool? _cachedResult;
  String? _lastError;

  CanBroadcastCallback(this._rpc);

  Future<void> cacheMempoolAcceptance(String rawTx) async {
    try {
      _cachedResult = await _rpc.testMempoolAccept(rawTx);
      if (!_cachedResult!) {
        final details = await _rpc.testMempoolAcceptMultiple([rawTx]);
        if (details.isNotEmpty) {
          _lastError = details[0]['reject-reason'] as String?;
        }
      }
    } catch (e) {
      _lastError = e.toString();
      rethrow;
    }
  }

  String? getLastError() => _lastError;

  @override
  bool callback(Uint8List tx) {
    if (_cachedResult == null) {
      throw StateError(
          'cacheMempoolAcceptance must be called before the FFI invokes this callback.');
    }
    final result = _cachedResult!;
    _cachedResult = null;
    return result;
  }
}

class IsScriptOwnedCallback implements payjoin.IsScriptOwned {
  final BitcoinRpcClient _rpc;
  final Set<String> _ownedScripts = <String>{};
  final Map<String, String> _scriptAddresses = <String, String>{};

  IsScriptOwnedCallback(this._rpc);

  Future<void> findOwnedScripts(bitcoin.Psbt psbt) async {
    try {
      final tx = psbt.extractTx();
      final scripts = tx.output().map((o) => o.scriptPubkey.toBytes()).toList();

      for (final script in scripts) {
        try {
          final address = bitcoin.Address.fromScript(
              bitcoin.Script(script), bitcoin.Network.regtest);
          final scriptHex =
              script.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
          _scriptAddresses[scriptHex] = address.toString();

          final addressInfo = await _rpc.getAddressInfo(address.toString());
          final isOwned = addressInfo['ismine'] as bool? ?? false;
          if (isOwned) {
            _ownedScripts.add(scriptHex);
          } else {}
        } catch (e) {
          print('Failed to check script: ${e.toString()}');
        }
      }
    } catch (e) {
      print('Script ownership check failed: ${e.toString()}');
      rethrow;
    }
  }

  String? getAddressForScript(String scriptHex) => _scriptAddresses[scriptHex];

  @override
  bool callback(Uint8List script) {
    final scriptHex =
        script.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return _ownedScripts.contains(scriptHex);
  }
}

class IsOutputKnownCallback implements payjoin.IsOutputKnown {
  final Set<String> _seenOutpoints = <String>{};
  final Map<String, DateTime> _seenTimestamps = <String, DateTime>{};

  @override
  bool callback(bitcoin.OutPoint outpoint) {
    final key = '${outpoint.txid}:${outpoint.vout}';

    if (_seenOutpoints.contains(key)) {
      return true;
    }

    _seenOutpoints.add(key);
    _seenTimestamps[key] = DateTime.now();
    return false;
  }

  bool hasBeenSeen(String txid, int vout) {
    final key = '$txid:$vout';
    return _seenOutpoints.contains(key);
  }

  Map<String, DateTime> getSeenOutpointsWithTimestamps() {
    return Map.from(_seenTimestamps);
  }

  void clear() {
    _seenOutpoints.clear();
    _seenTimestamps.clear();
  }
}

class ProcessPsbtCallback implements payjoin.ProcessPsbt {
  final BitcoinRpcClient _rpc;
  String? _cachedPsbt;
  String? _lastError;

  ProcessPsbtCallback(this._rpc);

  Future<void> cacheProcessedPsbt(String psbt) async {
    try {
      final result = await _rpc.walletProcessPsbt(psbt);
      _cachedPsbt = result['psbt'] as String;

      final complete = result['complete'] as bool? ?? false;
      if (!complete) {
        _lastError = 'PSBT processing incomplete';
      }
    } catch (e) {
      _lastError = e.toString();
      rethrow;
    }
  }

  String? getLastError() => _lastError;

  @override
  String callback(String psbt) {
    if (_cachedPsbt == null) {
      throw StateError(
          'cacheProcessedPsbt must be called before the FFI invokes this callback.');
    }
    final result = _cachedPsbt!;
    _cachedPsbt = null;
    return result;
  }
}
