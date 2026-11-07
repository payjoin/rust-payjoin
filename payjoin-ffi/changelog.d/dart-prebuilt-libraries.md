- Dart: the package now ships the release's prebuilt native libraries,
  and the build hook uses them instead of compiling Rust, so apps no
  longer need a Rust toolchain or network access at build time. Set
  `build: source` under `hooks: user_defines: payjoin:` in your app's
  `pubspec.yaml` to keep compiling it.
