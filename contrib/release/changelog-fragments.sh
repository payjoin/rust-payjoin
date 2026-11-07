#!/usr/bin/env bash
#
# Print the changelog section that a changelog.d directory holds, without
# its version heading. Each pull request adds its own uniquely named
# fragment, so concurrent pull requests never edit the same lines of
# CHANGELOG.md. bump.sh moves the fragments into the version's section and
# deletes them.
#
# A fragment is a Markdown file of one or more "- " list items, optionally
# grouped under "### " headings. Lines that continue an item are indented
# by at least two spaces or a tab, as Markdown needs to keep them in it.
# Items outside a heading come first, then each heading in the order it
# first appears, with the items every fragment puts under it. Fragments are
# read in file name order and blank lines are dropped, so the lists stay
# tight. Prints nothing when there is nothing to read. Fails, naming the
# file and where it can the line, on anything else, such as prose or a
# "## " heading, which would end the version's section early. Every entry
# in the directory must be a visible, regular .md file, because bump.sh
# deletes the fragments it reads and check-invariants counts what is left.
#
# usage: changelog-fragments.sh [--first <file>] <dir>
#   --first   read <file>, in fragment form, before the directory's
#             fragments; bump.sh passes the items a version's section
#             already holds, so they keep their place
set -euo pipefail

first=()
if [ "${1:-}" = "--first" ] && [ "$#" -ge 2 ]; then
    [ -s "$2" ] && first=("$2")
    shift 2
fi
[ "$#" -eq 1 ] || {
    sed -n '2,23p' "$0" >&2
    exit 1
}
dir="$1"

shopt -s nullglob dotglob
export LC_ALL=C
files=()
[ -d "$dir" ] && files=("$dir"/*)
reject() {
    echo "changelog-fragments: $1 $2" >&2
    exit 1
}
for f in "${files[@]}"; do
    case "${f##*/}" in
        .*) reject "$f" "is hidden; name fragments <topic>.md" ;;
        *.md) ;;
        *) reject "$f" "is not a .md fragment" ;;
    esac
    [ ! -L "$f" ] || reject "$f" "is a symlink"
    [ -f "$f" ] || reject "$f" "is not a regular file"
    [ -s "$f" ] || reject "$f" "is empty"
done
files=("${first[@]}" "${files[@]}")
[ "${#files[@]}" -gt 0 ] || exit 0

awk '
    function fail(why) {
        printf "changelog-fragments: %s:%d: %s\n", FILENAME, FNR, why > "/dev/stderr"
        failed = 1
        exit 1
    }
    function close_fragment() {
        if (file == "") return
        if (!items) fail_file(file, "has no list items")
        if (group != "" && !grouped) fail_file(file, "has no items under \"" group "\"")
    }
    function fail_file(f, why) {
        printf "changelog-fragments: %s %s\n", f, why > "/dev/stderr"
        failed = 1
        exit 1
    }
    FNR == 1 { close_fragment(); file = FILENAME; group = ""; items = 0; grouped = 1; item = 0 }
    /\r/ { fail("has a carriage return; save the fragment with LF line endings") }
    /^[[:space:]]*$/ { next }
    /^### .*[[:space:]]$/ { fail("trailing whitespace after the heading") }
    /^### [^[:space:]]/ {
        if (group != "" && !grouped) fail("no items under \"" group "\"")
        group = $0
        grouped = 0
        item = 0
        if (!(group in seen)) { seen[group] = 1; order[++groups] = group }
        next
    }
    /^#/ { fail("only \"### \" headings may appear in a fragment") }
    /^- / { items++; grouped = 1; item = 1; body[group] = body[group] $0 "\n"; next }
    /^(  |\t)/ {
        if (!item) fail("indented line outside a list item")
        body[group] = body[group] $0 "\n"
        next
    }
    /^[[:space:]]/ { fail("indent a continuation line by at least two spaces") }
    { fail("expected a \"- \" list item, an indented continuation or a \"### \" heading") }
    END {
        if (failed) exit 1
        close_fragment()
        out = body[""]
        for (i = 1; i <= groups; i++) {
            if (out != "") out = out "\n"
            out = out order[i] "\n\n" body[order[i]]
        }
        printf "%s", out
    }
' "${files[@]}"
