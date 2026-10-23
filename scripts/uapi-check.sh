#!/bin/bash
#
# uapi-check.sh: compile every trinity and test-binary object against the
# uapi headers of an older kernel tag, and summarise what fails by symbol.
# Run through `make uapi-check`, which passes MAKE, CC and the settings
# below; Documentation/HACKING.txt describes the target.
#
#   KERNEL_SRC       kernel git tree, only read (default
#                    $HOME/src/kernel/git-trees/linux)
#   UAPI_TAG         kernel tag whose headers are used (default v6.12)
#   UAPI_SYSROOT     sysroot cache (default
#                    ${XDG_CACHE_HOME:-$HOME/.cache}/trinity-uapi/$UAPI_TAG)
#   UAPI_JOBS        -j flag for the sub-makes, empty under a jobserver
#   UAPI_CHECK_TOP   symbols listed in the failure summary (default 20)

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_SRC="${KERNEL_SRC:-$HOME/src/kernel/git-trees/linux}"
UAPI_TAG="${UAPI_TAG:-v6.12}"
UAPI_SYSROOT="${UAPI_SYSROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/trinity-uapi/$UAPI_TAG}"
UAPI_JOBS="${UAPI_JOBS-}"
TOP="${UAPI_CHECK_TOP:-20}"
MAKE="${MAKE:-make}"
BUILD="$ROOT/build-uapi/$UAPI_TAG"
LOG="$BUILD/build.log"

if [ ! -d "$KERNEL_SRC" ]; then
	echo "uapi-check: no kernel git tree at $KERNEL_SRC; pass KERNEL_SRC=<tree>" >&2
	exit 1
fi

# A CFLAGS taken from the environment comes back from make fully
# expanded, naming the tree's own config.h, so nothing below inherits it.
unset CFLAGS
# ASCII quotes around symbols in the diagnostics, for the summary.
export LC_ALL=C

CC="${CC:-cc}" "$ROOT/scripts/uapi-sysroot.sh" "$KERNEL_SRC" "$UAPI_TAG" "$UAPI_SYSROOT" || exit 1

mkdir -p "$BUILD"
if ! (cd "$BUILD" && SYSROOT="$UAPI_SYSROOT" "$ROOT/configure" > configure.log 2>&1); then
	echo "uapi-check: configure failed, see $BUILD/configure.log" >&2
	exit 1
fi

# -k so one run reports every failing file, not just the first.
# $UAPI_JOBS is a make flag or nothing, so it stays unquoted.
# shellcheck disable=SC2086
{
	"$MAKE" -k --no-print-directory -C "$ROOT" $UAPI_JOBS OBJDIR="$BUILD/" \
		CONFIG_H="$BUILD/config.h" SYSROOT="$UAPI_SYSROOT" uapi-objs
	rc1=$?
	"$MAKE" -k -s --no-print-directory -C "$ROOT/tests" $UAPI_JOBS BUILDDIR="$BUILD/tests" \
		CONFIG_H="$BUILD/config.h" SYSROOT="$UAPI_SYSROOT" objs
	rc2=$?
} > "$LOG" 2>&1

if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ]; then
	echo "uapi-check: trinity and test objects compile against $UAPI_TAG uapi headers"
	exit 0
fi

# One row per diagnostic: symbol, file, file:line, message, with paths
# from the tests/ sub-make made relative to the root.  The symbol is the
# first quoted name in the message, or the missing header for a fatal
# "No such file" error; a message naming neither is its own group.
grep -E '^[^ :]+:[0-9]+:[0-9]+: (fatal )?error: ' "$LOG" |
	awk '{
		loc = $0; sub(/: (fatal )?error: .*/, "", loc); sub(/:[0-9]+$/, "", loc)
		sub(/^\.\.\//, "", loc)
		msg = $0; sub(/^[^ ]*: (fatal )?error: /, "", msg)
		sym = msg
		if (match(msg, /^[^ :]+\.h: No such file/))
			sym = substr(msg, 1, index(msg, ":") - 1)
		else if (match(msg, /\047[^\047]+\047 has no member named \047[^\047]+\047/)) {
			n = split(substr(msg, RSTART, RLENGTH), q, "\047")
			sym = q[2] "." q[4]
		} else if (match(msg, /incomplete type \047[^\047]+\047/))
			sym = substr(msg, RSTART + 17, RLENGTH - 18)
		else if (match(msg, /\047[^\047]+\047/))
			sym = substr(msg, RSTART + 1, RLENGTH - 2)
		file = loc; sub(/:[0-9]+$/, "", file)
		printf "%s\t%s\t%s\t%s\n", sym, file, loc, msg
	}' | sort -u > "$BUILD/errors.tsv"

nfiles=$(cut -f2 "$BUILD/errors.tsv" | sort -u | wc -l)
nsyms=$(cut -f1 "$BUILD/errors.tsv" | sort -u | wc -l)
if [ "$nfiles" -eq 0 ]; then
	echo "uapi-check: the build failed with no compiler error to group; see $LOG" >&2
	exit 1
fi

echo "uapi-check: against $UAPI_TAG uapi headers, $nfiles file(s) fail to compile on $nsyms symbol(s)" >&2
echo "uapi-check: files per symbol, first $TOP, with one example each:" >&2
# Per symbol: distinct files, then the first diagnostic in sort order.
awk -F'\t' '
	!seen[$1 FS $2]++ { files[$1]++ }
	!($1 in ex) { ex[$1] = $3 ": " $4 }
	END { for (s in files) printf "%d\t%s\t%s\n", files[s], s, ex[s] }
' "$BUILD/errors.tsv" | sort -t"$(printf '\t')" -k1,1nr -k2,2 | head -n "$TOP" |
	awk -F'\t' '{ printf "  %4d  %s\n        %s\n", $1, $2, $3 }' >&2
echo "uapi-check: full log $LOG, every error in $BUILD/errors.tsv" >&2
exit 1
