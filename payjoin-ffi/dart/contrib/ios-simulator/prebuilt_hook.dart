import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

// Replaces the package's build hook in the iOS simulator check, so the app
// bundles the library cross-built on Linux instead of building its own.
void main(List<String> args) async {
  await build(args, (input, output) async {
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: 'uniffi:payjoin_ffi',
        linkMode: DynamicLoadingBundled(),
        file: input.packageRoot.resolve(
          'prebuilt/aarch64-apple-ios-sim/libpayjoin_ffi.dylib',
        ),
      ),
    );
  });
}
