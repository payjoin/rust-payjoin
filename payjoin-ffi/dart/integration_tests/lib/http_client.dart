import 'dart:typed_data';
import 'package:dio/dio.dart';

class PayjoinHttpClient {
  final Dio _dio;

  PayjoinHttpClient({
    Duration? timeout,
    Map<String, String>? defaultHeaders,
  }) : _dio = Dio(BaseOptions(
          connectTimeout: timeout ?? const Duration(seconds: 30),
          receiveTimeout: timeout ?? const Duration(seconds: 30),
          headers: defaultHeaders ?? {},
        ));

  Future<PayjoinHttpResponse> postToDirectory({
    required String url,
    required Uint8List body,
    required Map<String, String> headers,
  }) async {
    try {
      final response = await _dio.post(
        url,
        data: body,
        options: Options(
          headers: headers,
          responseType: ResponseType.bytes,
          validateStatus: (status) => true,
        ),
      );

      return PayjoinHttpResponse(
        statusCode: response.statusCode ?? 0,
        body: response.data is Uint8List ? response.data : Uint8List(0),
        headers: response.headers.map.map((k, v) => MapEntry(k, v.join(', '))),
      );
    } on DioException catch (e) {
      throw PayjoinHttpException('HTTP request failed: ${e.message}', e);
    }
  }

  Future<PayjoinHttpResponse> get({
    required String url,
    Map<String, String>? headers,
  }) async {
    try {
      final response = await _dio.get(
        url,
        options: Options(
          headers: headers,
          responseType: ResponseType.bytes,
          validateStatus: (status) => true,
        ),
      );

      return PayjoinHttpResponse(
        statusCode: response.statusCode ?? 0,
        body: response.data is Uint8List ? response.data : Uint8List(0),
        headers: response.headers.map.map((k, v) => MapEntry(k, v.join(', '))),
      );
    } on DioException catch (e) {
      throw PayjoinHttpException('HTTP request failed: ${e.message}', e);
    }
  }

  void close() {
    _dio.close();
  }
}

class PayjoinHttpResponse {
  final int statusCode;
  final Uint8List body;
  final Map<String, String> headers;

  const PayjoinHttpResponse({
    required this.statusCode,
    required this.body,
    required this.headers,
  });

  bool get isSuccessful => statusCode >= 200 && statusCode < 300;

  String get bodyAsString => String.fromCharCodes(body);
}

class PayjoinHttpException implements Exception {
  final String message;
  final DioException? cause;

  const PayjoinHttpException(this.message, [this.cause]);

  @override
  String toString() => 'PayjoinHttpException: $message';
}
