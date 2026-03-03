import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart' as ntr;
import 'package:payjoin/src/precompiled/precompiled_builder.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.linkingEnabled) {
      return;
    }
    final builder = PrecompiledBuilder(
      assetName: 'uniffi:payjoin_ffi',
      buildModeName: ntr.BuildMode.release.name,
      fallback: (input, output, assetRouting, logger) async {
        final rustBuilder = ntr.RustBuilder(
          assetName: 'uniffi:payjoin_ffi',
          buildMode: ntr.BuildMode.release,
          features: ['_test-utils'],
        );
        await rustBuilder.run(
          input: input,
          output: output,
          assetRouting: assetRouting,
          logger: logger,
        );
      },
    );
    await builder.run(input: input, output: output);
  });
}
