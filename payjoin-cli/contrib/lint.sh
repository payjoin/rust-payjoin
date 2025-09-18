 #!/usr/bin/env bash
set -e

# Individual features with no defaults.
features=("v1" "v2")

for feature in "${features[@]}"; do
  # Don't duplicate --all-targets clippy. Clilppy end-user code, not tests.
  cargo clippy --no-default-features --features "$feature,pki-https" -- -D warnings
  cargo clippy --no-default-features --features "$feature,_manual-tls" -- -D warnings
done
