#!/bin/bash
#
# kcov-canonicalise-pcs: every PC hashed into kcov_shm->bucket_seen[]
# must first be canonicalised against the runtime KASLR base by
# kcov_canon_pc, so the bucket index for an instruction is invariant
# across reboots of the same kernel build.
#
# Without canonicalisation the bucket index for a given instruction
# shifts on every KASLR reroll, silently aliasing the cached bitmap
# across reboots that the kallsyms fingerprint (deliberately KASLR-
# invariant) already considers identical.  See the kcov_canon_pc /
# pc_to_edge / KCOV_BITMAP_FILE_VERSION comments in kcov.c for the
# design.
#
# The only PC -> edge-index hash today is pc_to_edge() in kcov.c, and
# it canonicalises by calling kcov_canon_pc() on its argument before
# the Murmur3 finalizer.  This check enforces that invariant so a
# future commit cannot accidentally drop the call or add a parallel
# hash path that bypasses canonicalisation.

set -u

NAME="kcov-canonicalise-pcs"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

if [ ! -f kcov.c ]; then
	echo "FAIL: $NAME: kcov.c not found at $ROOT"
	exit 1
fi

# Extract the pc_to_edge function body and confirm it routes its
# argument through kcov_canon_pc before any hash mixing.
body="$(awk '
	/^static unsigned int pc_to_edge\(/ { in_body = 1 }
	in_body { print }
	in_body && /^}/ { exit }
' kcov.c)"

if [ -z "$body" ]; then
	echo "FAIL: $NAME: pc_to_edge() definition not found in kcov.c"
	exit 1
fi

if ! grep -q 'kcov_canon_pc' <<< "$body"; then
	{
		echo "  $NAME: pc_to_edge() does not invoke kcov_canon_pc:"
		echo "$body" | sed 's/^/    /'
		echo "  fix: pc_to_edge() must call kcov_canon_pc(pc) before"
		echo "       the Murmur3 finalizer so bucket_seen[] indices are"
		echo "       KASLR-invariant."
	} >&2
	echo "FAIL: $NAME: pc_to_edge() missing kcov_canon_pc call"
	exit 1
fi

# kcov_canon_pc itself must subtract the runtime KASLR base.  Without
# this the helper degrades to identity and the canonicalisation claim
# is silently false.
canon_body="$(awk '
	/^static inline unsigned long kcov_canon_pc\(/ { in_body = 1 }
	in_body { print }
	in_body && /^}/ { exit }
' kcov.c)"

if [ -z "$canon_body" ]; then
	echo "FAIL: $NAME: kcov_canon_pc() definition not found in kcov.c"
	exit 1
fi

if ! grep -q 'kcov_kaslr_base' <<< "$canon_body"; then
	{
		echo "  $NAME: kcov_canon_pc() does not reference kcov_kaslr_base:"
		echo "$canon_body" | sed 's/^/    /'
		echo "  fix: kcov_canon_pc() must subtract kcov_kaslr_base from"
		echo "       its argument; without that the bucket index is the"
		echo "       raw PC again and cross-reboot warm-start aliases."
	} >&2
	echo "FAIL: $NAME: kcov_canon_pc() missing kcov_kaslr_base subtraction"
	exit 1
fi

echo "PASS: $NAME: pc_to_edge canonicalises PCs via kcov_canon_pc"
exit 0
