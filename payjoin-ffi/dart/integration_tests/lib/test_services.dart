import 'dart:typed_data';
import 'package:payjoin_dart/payjoin_ffi.dart' as payjoin;

class TestServices {
  final payjoin.TestServices _inner;
  bool _isInitialized = false;
  bool _isReady = false;
  DateTime? _startTime;
  final Map<String, dynamic> _serviceStatus = {};

  TestServices._(this._inner) {
    _startTime = DateTime.now();
  }

  static Future<TestServices> initialize() async {
    try {
      final services = payjoin.TestServices.initialize();
      final instance = TestServices._(services);
      instance._isInitialized = true;
      return instance;
    } catch (e, st) {
      throw Exception('Failed to initialize test services: $e');
    }
  }

  String get directoryUrl {
    _checkInitialized();
    final url = _inner.directoryUrl().toString();
    _serviceStatus['directory_url'] = url;
    return url;
  }

  String get ohttpRelayUrl {
    _checkInitialized();
    final url = _inner.ohttpRelayUrl().toString();
    _serviceStatus['ohttp_relay_url'] = url;
    return url;
  }

  Uint8List get cert {
    _checkInitialized();
    return _inner.cert();
  }

  payjoin.OhttpKeys fetchOhttpKeys() {
    _checkInitialized();
    try {
      final keys = _inner.fetchOhttpKeys();
      _serviceStatus['ohttp_keys_fetched'] = true;
      return keys;
    } catch (e) {
      _serviceStatus['ohttp_keys_fetched'] = false;
      rethrow;
    }
  }

  Future<void> waitForServicesReady() async {
    _checkInitialized();

    try {
      _inner.waitForServicesReady();
      _isReady = true;
      final duration = DateTime.now().difference(_startTime!);
      _serviceStatus['ready'] = true;
      _serviceStatus['startup_duration_ms'] = duration.inMilliseconds;
    } catch (e) {
      _serviceStatus['ready'] = false;
      _serviceStatus['error'] = e.toString();
      rethrow;
    }
  }

  payjoin.JoinHandle takeDirectoryHandle() {
    _checkInitialized();
    try {
      return _inner.takeDirectoryHandle();
    } catch (e) {
      rethrow;
    }
  }

  payjoin.JoinHandle takeOhttpRelayHandle() {
    _checkInitialized();
    try {
      return _inner.takeOhttpRelayHandle();
    } catch (e) {
      rethrow;
    }
  }

  Map<String, dynamic> getServiceStatus() {
    return Map.from(_serviceStatus);
  }

  void _checkInitialized() {
    if (!_isInitialized) {
      throw StateError(
          'Test services not initialized. Call initialize() first.');
    }
  }

  bool get isReady => _isReady;

  Duration get uptime {
    if (_startTime == null) {
      throw StateError('Services not started');
    }
    return DateTime.now().difference(_startTime!);
  }
}
