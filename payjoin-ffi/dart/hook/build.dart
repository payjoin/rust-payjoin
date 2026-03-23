import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    await RustBuilder(
      assetName: 'uniffi:payjoin_ffi',
      features: ['_test-utils-bitcoind'],
    ).run(input: input, output: output);
  });
}
