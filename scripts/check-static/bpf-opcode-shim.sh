#!/bin/bash
#
# bpf-opcode-shim: every BPF_* symbol used in net/bpf/*.c must have a
# definition that does NOT depend on the build host's <linux/bpf.h>
# vintage -- either a trinity #define (a uapi-gap #ifndef fallback or a
# derived convenience macro in include/bpf.h / net/bpf/internal.h), or an
# entry in bpf-opcode-shim.baseline (symbols we deliberately take from the
# base UAPI, present on every supported build host).
#
# Why this exists: the eBPF generators encode instructions with raw ISA
# opcode values (BPF_LOAD_ACQ, BPF_MEMSX, ...).  A newly-used opcode that
# has no #ifndef fallback still compiles on a modern devserver header, so
# the gap is invisible there -- then the build breaks on the older fuzz-box
# header with "BPF_FOO undeclared here (not in a function)".  We must NOT
# trust the local header (that is exactly what hides the bug), hence the
# shim-or-baseline rule.  Add a new opcode -> add its #ifndef shim; add a
# base-UAPI/API symbol -> add a baseline line.  Either way it is a
# conscious, reviewable decision instead of a fuzz-host surprise.

set -u

NAME="bpf-opcode-shim"
ROOT="${REPO_ROOT:-$(pwd)}"
SRC_DIR="$ROOT/net/bpf"
BASELINE="$ROOT/scripts/check-static/bpf-opcode-shim.baseline"

[ -d "$SRC_DIR" ] || { echo "PASS: $NAME (no net/bpf/ directory)"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "WARN: $NAME: perl unavailable, skipping"; exit 0; }

# BPF_ tokens used in code (strip C comments so a token named only in a
# comment does not count as a use).
used=$(perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' "$SRC_DIR"/*.c 2>/dev/null \
	| grep -oE '\bBPF_[A-Z0-9_]+\b' | sort -u)

# BPF_ tokens trinity #defines in its shim headers (host-independent:
# either an #ifndef uapi fallback or a derived macro).
defined=$(grep -hoE '#[[:space:]]*define[[:space:]]+BPF_[A-Z0-9_]+' \
	"$ROOT/include/bpf.h" "$SRC_DIR/internal.h" 2>/dev/null \
	| awk '{print $NF}' | sort -u)

# Baseline allowlist (strip comments/blank lines).
base=$(sed -E 's/#.*//' "$BASELINE" 2>/dev/null | grep -oE '\bBPF_[A-Z0-9_]+\b' | sort -u)

known=$(printf '%s\n%s\n' "$defined" "$base" | sort -u)
missing=$(comm -23 <(printf '%s\n' "$used") <(printf '%s\n' "$known"))

if [ -n "$missing" ]; then
	echo "FAIL: $NAME: BPF_ symbol(s) used in net/bpf/ with no host-independent definition:" >&2
	printf '%s\n' "$missing" | sed 's/^/    /' >&2
	echo "  Fix: if it is an ISA opcode a pre-6.x <linux/bpf.h> may lack, add an" >&2
	echo "  #ifndef fallback to include/bpf.h; if it is a base-UAPI symbol present" >&2
	echo "  on every supported build host, add it to" >&2
	echo "  scripts/check-static/bpf-opcode-shim.baseline." >&2
	n=$(printf '%s\n' "$missing" | grep -c .)
	echo "FAIL: $NAME: $n unshimmed/unbaselined BPF_ symbol(s)"
	exit 1
fi

uc=$(printf '%s\n' "$used" | grep -c .)
bc=$(printf '%s\n' "$base" | grep -c .)
echo "PASS: $NAME ($uc BPF_ symbol(s) used, all shimmed or baselined; baseline=$bc)"
exit 0
