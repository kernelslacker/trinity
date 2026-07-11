#!/bin/bash
#
# doc-pointer-exists: verify that every code comment pointing at one of
# Trinity's own Documentation/*.md design notes points at a file that
# actually exists.
#
# Large design essays were carved out of the source into
# Documentation/*.md and replaced in the code with short one-line
# pointers ("see Documentation/deferred-free.md").  Carving only pays
# off if the pointer stays valid: a dangling pointer is worse than none,
# because it sends a reader chasing a note that was renamed or deleted.
# A broken code->doc pointer is the one failure mode the carve-out
# introduces, and it is cheap to catch here rather than in review.
#
# Scope is deliberately narrow.  Only *flat* Documentation/<name>.md
# paths are checked -- those are Trinity's own notes, living directly in
# Documentation/.  A reference with a subdirectory
# (Documentation/networking/foo.rst, Documentation/ABI/...) points into
# the *Linux kernel* documentation tree, is outside this repo, and is
# intentionally ignored.

set -u

NAME="doc-pointer-exists"
ROOT="${REPO_ROOT:-$(pwd)}"

# Flat .md references only (no subdirectory slash after Documentation/)
# => Trinity's own docs.  Matching stops at ".md", so a trailing
# sentence period in the comment is not captured.
refs=$(grep -rEno 'Documentation/[A-Za-z0-9_-]+\.md' "$ROOT" \
	--include='*.c' --include='*.h' 2>/dev/null)

missing=$(
	printf '%s\n' "$refs" | while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		doc="${hit##*:}"                 # Documentation/<name>.md
		[ -f "$ROOT/$doc" ] || printf '%s\n' "${hit#"$ROOT"/}"
	done
)

if [ -n "$missing" ]; then
	echo "FAIL: $NAME: dangling Documentation/*.md pointer(s):" >&2
	printf '%s\n' "$missing" | while IFS= read -r m; do
		echo "  ${m%:*} -> ${m##*:} (no such file)" >&2
	done
	n=$(printf '%s\n' "$missing" | grep -c .)
	echo "FAIL: $NAME: $n dangling Documentation/*.md pointer(s)"
	exit 1
fi

total=$(printf '%s\n' "$refs" | grep -c .)
docs=$(printf '%s\n' "$refs" | awk -F: '{print $NF}' | sort -u | grep -c .)
echo "PASS: $NAME ($total pointer(s) to $docs doc(s), all present)"
exit 0
