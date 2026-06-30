#!/bin/bash
#
# ioctl-struct-memset: every get_writable_struct() that hands the
# kernel a struct pointer must be followed by memset(var, 0, ...) on
# the same variable before any field stores.
#
# Background.  get_writable_struct() returns a chunk of trinity's own
# writable_region pool.  That pool is recycled across syscalls and
# starts each life full of whatever residue the previous user left
# behind.  An ioctl sanitiser that allocates a struct and then sets
# only a SUBSET of fields hands the kernel a struct whose unmentioned
# fields are arbitrary pool bytes -- the kernel reads them as input
# (or copies them back through copy_to_user, leaking the residue back
# to userspace).  Either case is a real fuzz-time defect masquerading
# as kernel signal.
#
# The fix pattern is unambiguous and already in use throughout
# ioctls/ (see ioctls/nvme.c, ioctls/firewire.c::sanitise_fw_get_info,
# ioctls/seccomp.c): right after the NULL-check on the allocation,
# memset the whole struct to zero, THEN stamp the fields the
# sanitiser cares about.
#
# This check is a regex tripwire.  It walks ioctls/*.c looking for
# get_writable_struct(sizeof(*<var>)) calls whose declaration line
# contains the token `struct ` (so anonymous-type allocations like
# `int *p = get_writable_struct(sizeof(int));` are skipped -- those
# are primitives that get fully written by `*p = ...`), then
# requires a memset(<var>, 0, ...) within the next dozen source
# lines.  Lookahead stops at the first <var>->field store, so a
# sanitiser that writes a field before zeroing is flagged even if a
# stray memset appears later.
#
# Add a new ioctl sanitiser?  Memset the struct.  Need a real
# exception (e.g. the struct is wholly written field-by-field with no
# padding, and you have proof)?  Add it to the IGNORE list below
# with a short justification.

set -u

NAME="ioctl-struct-memset"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# Files exempt from the check (none currently; reserved for future
# justified exceptions).
IGNORE=""

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

for srcfile in ioctls/*.c; do
	case " $IGNORE " in
		*" $srcfile "*) continue ;;
	esac
	awk '
	{
		line[NR] = $0
		total = NR
	}
	END {
		for (i = 1; i <= total; i++) {
			ln = line[i]
			# Match: ... <var> = ... get_writable_struct( sizeof( *<var> ) ...);
			if (match(ln, /[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(\([^)]+\)[ \t]*)?get_writable_struct[ \t]*\([ \t]*sizeof[ \t]*\([ \t]*\*[A-Za-z_][A-Za-z0-9_]*[ \t]*\)/) == 0)
				continue

			# Skip non-struct primitive pointer allocations:
			# those are fully written by `*var = ...` and have
			# no leakable tail.
			if (ln !~ /struct[ \t]/)
				continue

			# Extract the var name (token to the left of `=`).
			head = ln
			sub(/[ \t]*=.*/, "", head)
			n = split(head, parts, /[ \t*()]+/)
			var = parts[n]
			if (var == "")
				continue

			# Look ahead up to 12 source lines for a
			# memset(var, 0, ...) on the same variable.  A
			# couple of sanitisers do a second alloc + null-
			# check between the get_writable_struct and the
			# memset (for sibling data buffers), and one
			# carries a three-line comment before the memset;
			# 12 lines covers both shapes.  Stop early if we
			# hit a var->field store -- once a field is
			# written we can no longer safely zero the rest.
			found = 0
			for (j = i + 1; j <= i + 12 && j <= total; j++) {
				pat = "memset[ \t]*\\([ \t]*" var "[ \t]*,[ \t]*0[ \t]*,"
				if (match(line[j], pat) != 0) {
					found = 1
					break
				}
				stop_pat = var "[ \t]*->"
				if (match(line[j], stop_pat) != 0)
					break
			}
			if (!found)
				printf("%s:%d: %s\n", FILENAME, i, ln)
		}
	}
	' "$srcfile" >> "$hits_tmp"
done

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: get_writable_struct allocation(s) with no memset:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: add 'memset(<var>, 0, sizeof(*<var>));' immediately"
		echo "       after the NULL check on the allocation, before any"
		echo "       <var>->field stores.  See ioctls/nvme.c or"
		echo "       ioctls/firewire.c::sanitise_fw_get_info for the"
		echo "       canonical pattern."
	} >&2
	echo "FAIL: $NAME: $n unguarded get_writable_struct allocation(s)"
	exit 1
fi

echo "PASS: $NAME: 0 unguarded get_writable_struct allocations"
exit 0
