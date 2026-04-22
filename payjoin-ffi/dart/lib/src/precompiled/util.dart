import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;

List<int> decodeHex(String hex) {
  final normalized = hex.trim().toLowerCase();
  if (normalized.length.isOdd) {
    throw FormatException('Invalid hex length');
  }
  final out = <int>[];
  for (var i = 0; i < normalized.length; i += 2) {
    final byte = int.parse(normalized.substring(i, i + 2), radix: 16);
    out.add(byte);
  }
  return out;
}

String hexEncode(List<int> bytes) {
  final b = StringBuffer();
  for (final v in bytes) {
    b.write(v.toRadixString(16).padLeft(2, '0'));
  }
  return b.toString();
}

Future<http.Response> httpGetWithRetry(
  Uri url, {
  Map<String, String>? headers,
  int maxAttempts = 4,
  Duration timeout = const Duration(seconds: 30),
  Duration retryDelay = const Duration(seconds: 1),
}) async {
  final client = http.Client();
  var attempt = 0;
  try {
    while (true) {
      attempt++;
      try {
        return await client.get(url, headers: headers).timeout(timeout);
      } on TimeoutException {
        if (attempt >= maxAttempts) rethrow;
      } on SocketException {
        if (attempt >= maxAttempts) rethrow;
      } on http.ClientException {
        if (attempt >= maxAttempts) rethrow;
      } on HttpException {
        if (attempt >= maxAttempts) rethrow;
      }
      await Future.delayed(retryDelay);
    }
  } finally {
    client.close();
  }
}

Future<void> writeBytesAtomically(File file, List<int> bytes) async {
  final directory = file.parent;
  if (!directory.existsSync()) {
    directory.createSync(recursive: true);
  }

  final tempPath = '${file.path}.${DateTime.now().microsecondsSinceEpoch}.tmp';
  final tempFile = File(tempPath);

  await tempFile.writeAsBytes(bytes, flush: true);

  try {
    await tempFile.rename(file.path);
  } on FileSystemException {
    if (file.existsSync()) {
      await file.delete();
    }
    await tempFile.rename(file.path);
  }
}
