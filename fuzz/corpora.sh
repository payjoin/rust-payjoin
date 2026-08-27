#!/usr/bin/env bash
# Manages fuzz corpora between rust-payjoin and payjoin/qa-assets.
#
# Subcommands:
#   seed <qa-assets-dir> <target>
#       Copy corpus from qa-assets into fuzz/corpus/<target>/ so the
#       fuzzer starts from the accumulated seeds rather than empty.
#
#   refresh <incoming-dir> <targets-file>
#       Minimise each target's corpus with -merge=1 and write the
#       result back into the qa-assets checkout so it can be pushed.
#
#   push
#       Commit the refreshed corpora and open a PR to origin.
#       Expects to be run from inside the qa-assets checkout.
#       Requires SOURCE and RUN_URL env vars set by the CI job.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
QA_ASSETS_CORPUS_DIR="fuzz_corpora"

cmd="${1:-}"
shift || true

case "$cmd" in
    seed)
        qa_assets_dir="$1"
        target="$2"
        src="$qa_assets_dir/$QA_ASSETS_CORPUS_DIR/$target"
        dst="$REPO_DIR/fuzz/corpus/$target"
        if [[ -d $src ]]; then
            mkdir -p "$dst"
            cp "$src"/* "$dst/" 2>/dev/null || true
            echo "Seeded $target from $src ($(find "$dst" -maxdepth 1 -type f | wc -l) inputs)"
        else
            echo "No existing corpus for $target in qa-assets, starting empty"
        fi
        ;;

    refresh)
        incoming_dir="$1"
        targets_file="$2"
        while IFS= read -r target; do
            incoming="$incoming_dir/corpus-$target/$target"
            if [[ ! -d $incoming ]]; then
                echo "No incoming corpus for $target, skipping"
                continue
            fi
            dst="$QA_ASSETS_CORPUS_DIR/$target"
            mkdir -p "$dst"
            # Merge minimises the corpus: only inputs that add coverage
            # are kept. Run from the repo root so cargo fuzz can find
            # the manifest.
            (
                cd "$REPO_DIR/fuzz"
                cargo fuzz run "$target" -- \
                    -merge=1 \
                    "$OLDPWD/$dst" \
                    "$OLDPWD/$incoming"
            )
            echo "Refreshed $target: $(find "$dst" -maxdepth 1 -type f | wc -l) inputs"
        done <"$targets_file"
        ;;

    push)
        source="${SOURCE:-unknown}"
        run_url="${RUN_URL:-unknown}"
        branch="corpus-refresh-$(date +%Y%m%d)"

        git checkout -b "$branch"
        git add fuzz_corpora/
        if git diff --cached --quiet; then
            echo "No corpus changes"
            exit 0
        fi
        git config user.name "github-actions[bot]"
        git config user.email "github-actions[bot]@users.noreply.github.com"
        git commit -m "Refresh fuzz corpora

Source: $source
Run: $run_url"
        git push origin "$branch"
        gh pr create \
            --title "Refresh fuzz corpora $(date +%Y-%m-%d)" \
            --body "Automated corpus refresh from $run_url" \
            --base master \
            --head "$branch"
        ;;

    *)
        echo "Usage: $0 {seed <qa-assets-dir> <target>|refresh <incoming-dir> <targets-file>|push}" >&2
        exit 1
        ;;
esac
