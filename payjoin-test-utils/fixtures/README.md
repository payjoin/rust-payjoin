# Shared binding test vectors

Rust and the Python, Dart, JavaScript, and C# binding tests read these files
from this repository. Update the fixture here instead of copying its contents
into a language test. Language-specific loaders belong in the test directories;
these files do not require new exports from the production bindings.

The `.base64` files preserve the existing Rust test constants byte for byte,
including the intentionally invalid input. They have no trailing newline so
`include_str!` preserves the constants' values.

| File                                       | Origin and purpose                                                         |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| `original-psbt.base64`                     | BIP 78 original PSBT, used to build sender sessions                        |
| `payjoin-proposal.base64`                  | BIP 78 proposal                                                            |
| `payjoin-proposal-with-sender-info.base64` | BIP 78 proposal with sender information                                    |
| `receiver-input-contribution.base64`       | Receiver input contribution from the BIP 78 vector                         |
| `invalid-psbt.base64`                      | Existing BIP 174 invalid input, preserved including its HTML entities      |
| `ohttp-keys.hex`                           | Fixed public key configuration previously embedded in each binding's tests |

The PSBT vectors originate from [BIP 78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#test-vectors)
and [BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#test-vectors).

The OHTTP fixture exercises decoding and session construction. It is not a
snapshot of `ohttp_key_config_bytes()` and has no corresponding private key
in these tests. Tests that decrypt requests must continue to use the matching
`ohttp_key_config_bytes()` / `ohttp_server()` pair or live `TestServices` keys.

Python and JavaScript resolve fixture paths relative to their test source.
Dart resolves them relative to the package source. C# copies the shared files
into its test output directory through `Payjoin.Tests.csproj`. Run the binding
suites through each language's `contrib/test.sh` from a repository checkout.
