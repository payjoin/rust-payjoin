# Payjoin Java Bindings

Java bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/), generated from `payjoin-ffi`
with [`uniffi-bindgen-java`](https://github.com/IronCoreLabs/uniffi-bindgen-java). These bindings
implement [BIP 78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and
[BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md).

## Stability

**Early / not release-ready.** The Java API is generated, not hand-maintained - if something reads
awkwardly from Java, the fix belongs in the generator (or its config), not a patch to the checked
output. Nothing here is published anywhere (see "Generator provenance" below for why, and no,
Maven publication is not part of this).

**Platforms:** CI targets Linux and macOS (`.github/workflows/java.yml`). **Windows is currently
unvalidated** - neither the generator build, the FFM native-library loading path, nor
`payjoin-test-utils`' bitcoind integration has been exercised on Windows for this target. Treat
Windows as untested, not merely "probably fine," until CI or a real run there says otherwise.

Everything else in this document describing a passing result (compiling, tests, generation) was
run locally on macOS/aarch64, not yet through this repository's own CI - see this PR's own
description for exactly what was run and when.

## Requirements

Without nix, generating and testing this target needs, on `PATH`:

* **A Rust toolchain new enough to build the pinned generator** - see "Generator provenance"
  below. Its own MSRV is 1.87.0, newer than this workspace's own MSRV (1.85.0) used to build
  `payjoin-ffi` itself; `scripts/generate_bindings.sh` does not switch toolchains for you (see
  that script's own comment on why not), so make sure whatever `cargo`/`rustc` is active satisfies
  the generator's MSRV before running it.
* **JDK 22+**: `javac` and `jar`. Generated bindings use Java's
  [Foreign Function & Memory API](https://docs.oracle.com/en/java/javase/22/core/foreign-function-and-memory-api.html)
  (Project Panama), not JNA - JDK 22 is the first release where that API is finalized rather than
  preview (JEP 454), which is why this floor is higher than Kotlin's (JDK 21+). No
  `--enable-preview` flag is needed for the FFM API itself on 22+.
* **Python 3** - `scripts/generate_bindings.sh` uses it to hash the local patch file (for its
  generator build cache key) and to parse Cargo's JSON build output and locate the compiled
  native library reliably (see "Generating bindings" below).
* **Git** - `scripts/generate_bindings.sh` fetches and verifies the pinned generator commit with
  it directly (see "Generator provenance" below), not through Cargo's own `git` dependency
  support.
* **The Gradle wrapper** (`./gradlew`, checked in) - no separately-installed Gradle needed.

Inside `nix develop .#java`, all of the above (Rust, JDK 25, Python 3, Git) are already on `PATH`.

At runtime, the JVM must additionally allow restricted native-method access:
`--enable-native-access=ALL-UNNAMED` for classpath-based apps (what `build.gradle.kts`'s `test`
task sets), or `--enable-native-access=your.module.name` for a JPMS module. Native `payjoin_ffi`
is loaded via `System.load`/`System.loadLibrary` (the JDK's own mechanism, not a third-party
library) - see "Native library loading" below.

## Generator provenance

`payjoin-ffi` is on UniFFI 0.31.x. `uniffi-bindgen-java`'s published releases split cleanly on
that line:

* **0.4.2** (latest tagged release) reads UniFFI 0.31 metadata, but its Java error-type templates
  emit code that doesn't compile: invalid multiple inheritance
  (`extends Foo, AutoCloseable` - Java classes can only extend one class), package-private
  `close()` that doesn't satisfy the `AutoCloseable` interface, and an empty field identifier for
  unnamed tuple/newtype fields (`this.);` instead of `this.v1;`). See
  [IronCoreLabs/uniffi-bindgen-java#68](https://github.com/IronCoreLabs/uniffi-bindgen-java/issues/68),
  which tracks a 0.31-compatible release for exactly this - open, unanswered at the time of
  writing, and this work does not block on it.
* **0.5.x** (unreleased; `main` is versioned `0.5.0` upstream) fixes exactly this, but requires
  UniFFI 0.32, which `payjoin-ffi` is not on and this work does not migrate it to.

Until `payjoin-ffi` moves to UniFFI 0.32 and can consume a released upstream `uniffi-bindgen-java`
0.5.x directly, `scripts/generate_bindings.sh` builds the generator itself from canonical
upstream, patched locally:

* Source: `https://github.com/IronCoreLabs/uniffi-bindgen-java`, pinned to the exact commit the
  `0.4.2` tag points to - `559bd72e680e0be7feda6ac3a93819376db030d9` (`Nullness annotations (#62)`).
  Pinned by commit SHA, not the tag name, so a future upstream re-tag can't silently change what
  this builds.
* Patch: `payjoin-ffi/java/patches/0001-error-autocloseable-and-destroy-fields.patch` - a
  `git apply --unidiff-zero`-able diff touching only `src/templates/ErrorTemplate.java` and
  `src/templates/macros.java` (13 insertions, 5 deletions). Generated with zero context lines
  (`git diff -U0`, safe since it's always applied against this one pinned commit) so upstream's
  own incidental whitespace in the surrounding template text never ends up embedded in the patch
  file itself. This is a direct backport of the fix already on upstream's unreleased `main` (see
  above) for exactly the three `0.4.2` failures listed above, nothing else - not a
  payjoin-specific hack in a generic template.
* No fork, nothing vendored: the generator's own source is never committed here, only the small
  patch is. `scripts/generate_bindings.sh` fetches the pinned commit into a scratch directory,
  applies the patch, builds, and discards the scratch checkout - see that script for the exact
  mechanics and why the cache key includes a hash of the patch file.

**Migration plan:** this patched-canonical-source build is intended to be temporary. Once
`payjoin-ffi` moves to UniFFI 0.32 (tracked separately from this work), `scripts/generate_bindings.sh`
should switch to installing a released upstream `uniffi-bindgen-java` 0.5.x tag directly, dropping
both the pinned commit and the local patch. The patch's fix is already on upstream `main` as of
this writing, which is *evidence* that switch should be small - but not a guarantee: whatever
0.5.x actually ships by the time payjoin-ffi is on UniFFI 0.32 could differ from `main` today, and
the UniFFI 0.32 migration itself may touch this directory in ways unrelated to the generator swap.
Re-running `scripts/generate_bindings.sh` and the full Java test suite (unit tests + the BIP77
integration test) after the migration is what should actually confirm it, not an assumption made
here.

## Generating bindings

```shell
cd payjoin-ffi/java
bash ./scripts/generate_bindings.sh
./gradlew test
```

Or `bash ./contrib/test.sh` from this directory (uses `Cargo-recent.lock`, matching the other
binding targets' contrib scripts).

Generated sources are not committed - `scripts/generate_bindings.sh` is the reproducible build
step that (re)creates `src/main/java/org/` and `lib/` before every build or test run, the same
way the Kotlin/Python targets work. `JAVA_BINDGEN_REV`/`JAVA_BINDGEN_GIT_URL` environment
variables override the pinned generator commit/source for local experimentation; leave them unset
for the default, reproducible build, which does not depend on anyone's personal fork.
`patches/0001-error-autocloseable-and-destroy-fields.patch` is still applied on top of whatever
commit is checked out either way - an override only makes sense pointed at another 0.4.2-era
commit the patch still `git apply`s cleanly against (upstream 0.5.0 already contains this fix, so
pointing there fails the patch step rather than silently doing nothing).

By default, development generation enables `_test-utils` (needed for the BIP77 integration test
below). For production bindings, set `PAYJOIN_FFI_FEATURES` to empty:

```shell
PAYJOIN_FFI_FEATURES= bash ./scripts/generate_bindings.sh
```

## Native library loading

Generated code resolves the native library through
`System.getProperty("uniffi.component.payjoin.libraryOverride")` first (an absolute path, loaded
via `System.load`), falling back to `System.loadLibrary("payjoin_ffi")` (searches
`java.library.path`) if that property isn't set - this is UniFFI's own convention, identical in
spirit to the Kotlin bindings' JNA `libraryOverride` property, just backed by the JDK's own FFM
loader instead of JNA. `build.gradle.kts`'s `test` task sets the override to
`lib/libpayjoin_ffi.{dylib,so,dll}` (populated by `scripts/generate_bindings.sh`) so tests find the
library without needing `java.library.path` configured separately.

## Tests

`src/test/java/org/payjoindevkit/` - a focused Java port of the Kotlin/Python FFI test suites
(URI parsing, sender builder construction, persistence, basic validation), not a mechanical
line-for-line port of every existing test.

`BIP77IntegrationTest.java` drives a complete v2↔v2 round trip - local in-process payjoin
directory, local OHTTP relay, real regtest `bitcoind` (all from `payjoin-test-utils`, the same
test infrastructure `payjoin-ffi/kotlin`'s `IntegrationTests.kt` uses), receiver and sender both
through the generated Java API - and asserts the final broadcast transaction spends coins from
both wallets. No public production infrastructure: everything runs locally against in-process
test services.

## Async / callbacks

Generated async methods return `java.util.concurrent.CompletableFuture<T>`, not
`kotlinx.coroutines`/`suspend` (the Kotlin bindings' model) - each also gets a second overload
taking an explicit `java.util.concurrent.Executor` for where callbacks run. Callback interfaces
(session persisters, `IsScriptOwned`, `CanBroadcast`, etc.) are plain Java interfaces invoked
synchronously on the calling thread via an FFM upcall stub - the same threading model UniFFI's
other bindings use, just backed by `java.lang.foreign` instead of JNA.

**Verified:** every async type and method (`JsonReceiverSessionPersisterAsync`,
`JsonSenderSessionPersisterAsync`, every `saveAsync`/`*Async` overload) compiles cleanly as part
of the full 480-file generated API - this was checked directly (`javac` against every generated
source, not sampled). **Not verified:** actual runtime behavior of the async persister path
(`CompletableFuture` completion, the `Executor` overload, cancellation) - this target's tests,
including the full BIP77 v2↔v2 integration test, only exercise the synchronous persister API,
which is what the integration test needs and is now proven correct end to end at runtime. The
async path compiling is evidence it's not structurally broken, not evidence it's runtime-correct;
treat it as an untested surface until someone adds coverage for it.
