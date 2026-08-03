#!/bin/bash
#
# rettype-multiplexer-conflict: an op-multiplexed syscall must not
# also carry a static entry->rettype initializer.
#
# include/syscall.h documents that op-multiplexed entries (fcntl,
# futex, bpf, seccomp) leave entry->rettype unset (RET_NONE) and
# publish rec->rettype per-cmd from their .sanitise hook.
# effective_rettype() short-circuits on any non-RET_NONE
# entry->rettype:
#
#     if (entry->rettype != RET_NONE)
#         return entry->rettype;
#     ...
#     return rec->rettype;
#
# If such an entry is also stamped with a static .rettype = RET_XXX,
# the fall-through to rec->rettype is dead and the per-cmd contract
# published by .sanitise is silently ignored -- every downstream
# consumer that keys off effective_rettype() (fd-group live_fds
# tracking, retfd corruption guard, RZS blanket gate,
# validate_ret_bound()) sees the static answer instead of the
# per-cmd one.
#
# The check flags any syscalls/*.c source file that contains BOTH
# a `rec->rettype =` assignment (the multiplexer signature) AND a
# top-level `struct syscallentry` `.rettype =` designated initializer
# (the static-annotation signature).  Files that carry the
# .rettype_publish_hint escape hatch are exempt -- that field lets a
# static walker still recognise the entry as a potential dynamic
# RET_FD source without stamping a real rettype.

set -u

NAME="rettype-multiplexer-conflict"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

mapfile -t SRCFILES < <(find syscalls \( -name '*.c' \) -type f \
		-not -path '*/.git/*' -print | sort)

if [ "${#SRCFILES[@]}" -eq 0 ]; then
	echo "FAIL: $NAME: no source files found under syscalls/"
	exit 1
fi

for f in "${SRCFILES[@]}"; do
	# Multiplexer signature: any `rec->rettype = ...` assignment.
	# This is what a .sanitise hook writes to publish the per-cmd
	# rettype at dispatch time.
	grep -q '\brec->rettype[[:space:]]*=' "$f" || continue

	# Static-annotation signature: a designated initializer
	# `.rettype = ...` inside a struct syscallentry initializer.
	# Grep the raw form -- if any line matches, this file carries
	# a static rettype that will short-circuit effective_rettype().
	grep -qE '^[[:space:]]*\.rettype[[:space:]]*=' "$f" || continue

	# Escape hatch: rettype_publish_hint lets a file declare it
	# publishes rettype dynamically without stamping a real value.
	if grep -q 'rettype_publish_hint' "$f"; then
		continue
	fi

	echo "$f" >> "$hits_tmp"
done

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: file(s) that both publish rec->rettype and stamp .rettype:"
		while read -r file; do
			echo "    $file"
		done < "$hits_tmp"
		echo "  fix: op-multiplexed syscalls must leave entry->rettype unset"
		echo "       (RET_NONE) so effective_rettype() falls through to the"
		echo "       per-cmd rec->rettype published by .sanitise.  Remove the"
		echo "       static .rettype = initializer, or add .rettype_publish_hint"
		echo "       if a static walker still needs the classification."
	} >&2
	echo "FAIL: $NAME: $n file(s) short-circuit per-cmd rettype"
	exit 1
fi

echo "PASS: $NAME: 0 files short-circuit op-multiplexed rettype"
exit 0
