import 'dart:io';

import 'commands/gen_key.dart' as gen_key;
import 'commands/hash.dart' as hash;
import 'commands/precompile_binaries.dart' as precompile_binaries;
import 'commands/sign.dart' as sign_cmd;
import 'commands/targets.dart' as targets;

Future<void> runCli(List<String> args) async {
  if (args.isEmpty) {
    _printUsage();
    exitCode = 2;
    return;
  }

  final command = args[0];
  final commandArgs = args.sublist(1);

  switch (command) {
    case 'precompile-binaries':
      await precompile_binaries.run(commandArgs);
      return;
    case 'hash':
      await hash.run(commandArgs);
      return;
    case 'targets':
      await targets.run(commandArgs);
      return;
    case 'sign':
      await sign_cmd.run(commandArgs);
      return;
    case 'gen-key':
      await gen_key.run(commandArgs);
      return;
    default:
      stderr.writeln('Unknown command: $command');
      _printUsage();
      exitCode = 2;
  }
}

void _printUsage() {
  stdout.writeln('''
Usage: dart run payjoin <command> [options]

Commands:
  precompile-binaries  Precompile binaries for all targets
  hash                 Compute crate hash
  targets              Resolve toolchain targets
  sign                 Sign a file
  gen-key              Generate Ed25519 keypair

Run 'dart run payjoin <command> --help' for command-specific help.
''');
}
