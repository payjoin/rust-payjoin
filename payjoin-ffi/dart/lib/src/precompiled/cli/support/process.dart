import 'dart:io';

Future<void> runOrThrow(
  String exe,
  List<String> args, {
  required bool verbose,
  Map<String, String>? environment,
  String? workingDirectory,
}) async {
  if (verbose) stderr.writeln('> $exe ${args.join(' ')}');
  final res = await Process.run(
    exe,
    args,
    environment: environment,
    workingDirectory: workingDirectory,
  );
  stdout.write(res.stdout);
  stderr.write(res.stderr);
  if (res.exitCode != 0) {
    exitCode = res.exitCode;
    throw StateError('Command failed: $exe ${args.join(' ')}');
  }
}
