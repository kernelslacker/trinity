#!/bin/bash
#
# fd-from-object-coverage: verify that fd_from_object() switches on
# every OBJ_FD_* value in `enum objecttype`.
#
# fd_from_object() in objects.c maps an object back to its underlying
# fd.  It is the gate used by add_object() to reject objects whose fd
# lookup would fail (objects.c:592), and several other call sites use
# it the same way.  Any OBJ_FD_* enum member missing from the switch
# falls through to `default: return -1`, which causes every object of
# that type to be silently dropped from its pool -- the provider
# compiles, the syscalls register, and at runtime the pool stays
# empty with no diagnostic.
#
# This exact divergence shipped once already with OBJ_FD_SPARSE_FILE,
# where the provider landed but the fd_from_object case was forgotten
# and the SPARSE_FILE pool was dead-on-arrival.  This check exists so
# it can't happen again.
#
# What this check enforces:
#   1. Every OBJ_FD_* member of `enum objecttype` (include/object-
#      types.h) has a corresponding `case OBJ_FD_*:` label inside the
#      body of fd_from_object() in objects.c.
#   2. Conversely, every case label inside fd_from_object() refers to
#      a name that still exists in the enum (catches stale cases left
#      behind after a rename or removal).

set -u

NAME="fd-from-object-coverage"
ROOT="${REPO_ROOT:-$(pwd)}"

OBJTYPES_H="$ROOT/include/object-types.h"
OBJECTS_C="$ROOT/objects.c"

fail() {
	echo "FAIL: $NAME: $1"
	shift
	for line in "$@"; do
		echo "  $line" >&2
	done
	exit 1
}

[ -r "$OBJTYPES_H" ] || fail "cannot read $OBJTYPES_H"
[ -r "$OBJECTS_C" ]  || fail "cannot read $OBJECTS_C"

# Extract OBJ_FD_* members from `enum objecttype { ... }`.
enum_members=$(awk '
	/enum objecttype \{/ { inside = 1; next }
	inside && /^\}/      { inside = 0 }
	inside && /^[[:space:]]*OBJ_FD_[A-Z0-9_]+[[:space:]]*,/ {
		gsub(/[[:space:],]/, "")
		print
	}
' "$OBJTYPES_H" | sort -u)

enum_count=$(printf '%s\n' "$enum_members" | grep -c '^OBJ_FD_' || true)

if [ "$enum_count" -eq 0 ]; then
	fail "found 0 OBJ_FD_* members in $OBJTYPES_H (parser broke?)"
fi

# Extract case labels strictly inside the body of fd_from_object().
# objects.c has many other switch statements (add_object, release_obj,
# etc.) that also case on OBJ_FD_* values; we only want this one
# function's labels.  Enter on the signature, track brace depth, leave
# when the body closes.
cased_members=$(awk '
	/^int fd_from_object\(/ { inside = 1; brace = 0; next }
	inside {
		for (i = 1; i <= length($0); i++) {
			c = substr($0, i, 1)
			if (c == "{") brace++
			else if (c == "}") {
				brace--
				if (brace == 0) { inside = 0; next }
			}
		}
		if (inside && match($0, /case OBJ_FD_[A-Z0-9_]+/))
			print substr($0, RSTART + 5, RLENGTH - 5)
	}
' "$OBJECTS_C" | sort -u)

cased_count=$(printf '%s\n' "$cased_members" | grep -c '^OBJ_FD_' || true)

if [ "$cased_count" -eq 0 ]; then
	fail "found 0 case OBJ_FD_* labels in fd_from_object() (parser broke?)"
fi

# Members in the enum but never cased -- the dangerous direction.
missing=$(comm -23 \
	<(printf '%s\n' "$enum_members") \
	<(printf '%s\n' "$cased_members"))

# Cases that name an enum member that no longer exists -- stale code.
stale=$(comm -13 \
	<(printf '%s\n' "$enum_members") \
	<(printf '%s\n' "$cased_members"))

if [ -n "$missing" ] || [ -n "$stale" ]; then
	detail=()
	if [ -n "$missing" ]; then
		while IFS= read -r name; do
			[ -z "$name" ] && continue
			detail+=("missing case in fd_from_object(): $name")
		done <<< "$missing"
	fi
	if [ -n "$stale" ]; then
		while IFS= read -r name; do
			[ -z "$name" ] && continue
			detail+=("stale case in fd_from_object() (not in enum): $name")
		done <<< "$stale"
	fi
	fail "fd_from_object() switch out of sync with enum objecttype" \
		"${detail[@]}" \
		"see objects.c fd_from_object() and include/object-types.h"
fi

echo "PASS: $NAME (enum=$enum_count, cased=$cased_count)"
exit 0
