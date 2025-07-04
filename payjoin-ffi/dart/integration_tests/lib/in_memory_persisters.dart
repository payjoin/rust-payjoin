import 'package:payjoin_dart/payjoin_ffi.dart';

class InMemoryReceiverSessionEventLog implements JsonReceiverSessionPersister {
  final List<String> _events = [];
  final String sessionId;
  bool _closed = false;

  InMemoryReceiverSessionEventLog(this.sessionId);

  @override
  void save(String event) {
    if (_closed) {
      throw StateError('Session is closed');
    }
    _events.add(event);
  }

  @override
  List<String> load() {
    if (_closed) {
      throw StateError('Session is closed');
    }
    return List.unmodifiable(_events);
  }

  @override
  void close() {
    _closed = true;
  }

  int get eventCount => _events.length;

  bool get isClosed => _closed;

  void clear() {
    _events.clear();
  }

  String? get lastEvent => _events.isEmpty ? null : _events.last;

  bool hasEvent(String event) => _events.contains(event);
}

class InMemorySenderSessionEventLog implements JsonSenderSessionPersister {
  final List<String> _events = [];
  final String sessionId;
  bool _closed = false;

  InMemorySenderSessionEventLog(this.sessionId);

  @override
  void save(String event) {
    if (_closed) {
      throw StateError('Session is closed');
    }
    _events.add(event);
  }

  @override
  List<String> load() {
    if (_closed) {
      throw StateError('Session is closed');
    }
    return List.unmodifiable(_events);
  }

  @override
  void close() {
    _closed = true;
  }

  int get eventCount => _events.length;

  bool get isClosed => _closed;

  void clear() {
    _events.clear();
  }

  String? get lastEvent => _events.isEmpty ? null : _events.last;

  bool hasEvent(String event) => _events.contains(event);
}

class PersisterTestManager {
  final Map<String, InMemoryReceiverSessionEventLog> _receiverSessions = {};
  final Map<String, InMemorySenderSessionEventLog> _senderSessions = {};

  InMemoryReceiverSessionEventLog createReceiverSession(String sessionId) {
    final persister = InMemoryReceiverSessionEventLog(sessionId);
    _receiverSessions[sessionId] = persister;
    return persister;
  }

  InMemorySenderSessionEventLog createSenderSession(String sessionId) {
    final persister = InMemorySenderSessionEventLog(sessionId);
    _senderSessions[sessionId] = persister;
    return persister;
  }

  List<String> get receiverSessionIds => _receiverSessions.keys.toList();

  List<String> get senderSessionIds => _senderSessions.keys.toList();

  void closeAllSessions() {
    for (final persister in _receiverSessions.values) {
      if (!persister.isClosed) {
        persister.close();
      }
    }
    for (final persister in _senderSessions.values) {
      if (!persister.isClosed) {
        persister.close();
      }
    }
  }

  void clearAllSessions() {
    for (final persister in _receiverSessions.values) {
      persister.clear();
    }
    for (final persister in _senderSessions.values) {
      persister.clear();
    }
  }

  int get totalEventCount {
    int total = 0;
    for (final persister in _receiverSessions.values) {
      total += persister.eventCount;
    }
    for (final persister in _senderSessions.values) {
      total += persister.eventCount;
    }
    return total;
  }
}
