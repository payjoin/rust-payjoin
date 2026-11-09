#!/usr/bin/env bash
# Check that folding preserves item content and trims structural spacing.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/fragments"

cat >"$WORK/fragments/a.md" <<'EOF'

- First paragraph.

  Second paragraph.


- Example:
  ```python
  message = """first


  second"""
  ```


### Fixes

- First fix.


EOF
cat >"$WORK/fragments/b.md" <<'EOF'

- Another item.

### Fixes

- Second fix.
EOF
cat >"$WORK/expected" <<'EOF'
- First paragraph.

  Second paragraph.
- Example:
  ```python
  message = """first


  second"""
  ```
- Another item.

### Fixes

- First fix.
- Second fix.
EOF
"$DIR/changelog-fragments.sh" "$WORK/fragments" >"$WORK/actual"
diff -u "$WORK/expected" "$WORK/actual"

# A later fold reads the existing section through --first.
rm "$WORK/fragments/"*.md
printf '%s\n' '### Fixes' '- Late fix.' >"$WORK/fragments/late.md"
printf '%s\n' '- Late fix.' >>"$WORK/expected"
"$DIR/changelog-fragments.sh" --first "$WORK/actual" "$WORK/fragments" >"$WORK/refolded"
diff -u "$WORK/expected" "$WORK/refolded"

# Whitespace on blank lines within an item is content too.
printf '\n- Item.\n  \n\t\n  Continuation.\n\n' >"$WORK/fragments/late.md"
printf '%s\n' '- Item.' '  ' $'\t' '  Continuation.' >"$WORK/expected"
"$DIR/changelog-fragments.sh" "$WORK/fragments" >"$WORK/actual"
diff -u "$WORK/expected" "$WORK/actual"
