#!/bin/bash
#
# doc-pointer-exists: verify that every code comment (or help string)
# pointing at one of Trinity's own Documentation/*.md design notes
# points at a file that actually exists, and -- if the pointer includes
# a #section anchor -- that the file actually contains a heading whose
# text matches the anchor.
#
# Large design essays were carved out of the source into
# Documentation/*.md and replaced in the code with short one-line
# pointers ("see Documentation/deferred-free.md").  Carving only pays
# off if the pointer stays valid: a dangling pointer is worse than none,
# because it sends a reader chasing a note that was renamed or deleted.
# A broken code->doc pointer is the one failure mode the carve-out
# introduces, and it is cheap to catch here rather than in review.
#
# --help entries in main/params/help.c also carve out their rationale
# into Documentation/params-*.md (and the existing per-topic docs) with
# per-option #anchor pointers, so a bad anchor breaks the trail from
# --help to the design note the same way a bad file path does.
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
# => Trinity's own docs.  An optional #anchor may follow the .md;
# anchor chars are letters/digits/hyphens/underscores.
refs=$(grep -rEno 'Documentation/[A-Za-z0-9_-]+\.md(#[A-Za-z0-9_-]+)?' "$ROOT" \
	--include='*.c' --include='*.h' 2>/dev/null)

missing_files=""
missing_anchors=""

while IFS= read -r hit; do
	[ -n "$hit" ] || continue
	# hit format: <path>:<line>:<match>
	match="${hit##*:}"                  # Documentation/<name>.md[#anchor]
	src="${hit%:*}"                     # <path>:<line>
	src="${src#"$ROOT"/}"

	doc="${match%%#*}"                  # Documentation/<name>.md
	anchor=""
	[ "$match" != "$doc" ] && anchor="${match#*#}"

	if [ ! -f "$ROOT/$doc" ]; then
		missing_files=$(printf '%s\n  %s -> %s (no such file)' \
			"$missing_files" "$src" "$doc")
		continue
	fi

	[ -z "$anchor" ] && continue

	# Anchor check: the doc must contain a markdown heading (line
	# starting with one-or-more '#' + space) whose text contains
	# the anchor string.  This is deliberately permissive: the
	# anchor is a grep target, not a rendered GFM slug, so any
	# heading that mentions the anchor counts.
	if ! grep -qE "^#+ .*${anchor}([^A-Za-z0-9_-]|$)" "$ROOT/$doc"; then
		missing_anchors=$(printf '%s\n  %s -> %s#%s (no matching heading)' \
			"$missing_anchors" "$src" "$doc" "$anchor")
	fi
done <<EOF
$refs
EOF

fail=0

if [ -n "$missing_files" ]; then
	echo "FAIL: $NAME: dangling Documentation/*.md pointer(s):$missing_files" >&2
	fail=1
fi

if [ -n "$missing_anchors" ]; then
	echo "FAIL: $NAME: unresolved Documentation/*.md#anchor pointer(s):$missing_anchors" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	n_files=$(printf '%s' "$missing_files" | grep -c '^  ' || true)
	n_anch=$(printf '%s' "$missing_anchors" | grep -c '^  ' || true)
	echo "FAIL: $NAME: $n_files dangling file(s), $n_anch unresolved anchor(s)"
	exit 1
fi

total=$(printf '%s\n' "$refs" | grep -c . || true)
docs=$(printf '%s\n' "$refs" | awk -F: '{print $NF}' | sed 's/#.*//' | sort -u | grep -c . || true)
anchors=$(printf '%s\n' "$refs" | awk -F: '{print $NF}' | grep -c '#' || true)
echo "PASS: $NAME ($total pointer(s) to $docs doc(s), $anchors with anchors, all resolved)"
exit 0
