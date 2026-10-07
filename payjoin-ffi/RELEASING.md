# Bindings version policy

Starting with 0.25.0, Python, JavaScript, Dart, and C# share the payjoin-ffi
version. The skipped numbers align the previous independent sequences.
Python and npm publish it without core metadata. Dart and the C# project retain
`+payjoin-1.2.0` metadata, and JavaScript records it in `releaseTag`.
NuGet removes metadata from its package filenames.

Update every package version and its lockfile together. Validate the
versions with `nix develop .#release -c python3 contrib/release/bindings-version.py`.
A change in only one language or in only the wrapped core still requires
a new common version.
Consumers with version constraints limited to an old minor must upgrade
those constraints explicitly. Historical releases remain available.

Prereleases use `-alpha.N`, `-beta.N`, `-rc.N`, or `-preview.N`. Python uses
the corresponding PEP 440 spelling, for example `0.26.0-rc.1` becomes
`0.26.0rc1`; alpha becomes `a`, beta becomes `b`, and preview becomes `rc`.
Choose either rc or preview for a release series because Python treats
them as the same phase.
