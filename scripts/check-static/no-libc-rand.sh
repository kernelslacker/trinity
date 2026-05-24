#!/bin/bash
#
# no-libc-rand: reject libc PRNG callsites outside the wrapper layer.
#
# Trinity migrated off libc rand()/random()/srand() and the *rand48
# family in favour of the inline, mutex-free rnd_u32() / rnd_u64() /
# rnd_modulo_u32() helpers declared in include/rnd.h.  libc rand() is
# an out-of-line LFSR with a pthread mutex that showed up >5% in perf
# top on hot fuzz paths; the trinity wrappers are inline and route
# through trinity's own seeded RNG.
#
# Two locations are allowed to mention the libc names:
#
#   rand/           - the wrapper bridge layer that owns the libc seed
#   include/rnd.h   - the header that declares the trinity wrappers
#
# Everywhere else, libc PRNG calls are forbidden.  This check is a
# regex tripwire: it grep-matches the token list followed by `(` on
# word boundaries (so getrandom, random_address, random.h, rnd_*,
# RAND_RANGE etc. do not trigger) and then filters out comment lines
# (a single-line `/* ... rand() ... */`, a `//` comment, or a block
# comment continuation `^\s*\*`).  Anything that survives those
# filters fails the check.

set -u

NAME="no-libc-rand"
ROOT="${REPO_ROOT:-$(pwd)}"

# Token list: every libc PRNG entry point trinity must not call.
PATTERN='\b(rand|random|srand|srandom|drand48|erand48|lrand48|nrand48|mrand48|jrand48|srand48|seed48|lcong48)[[:space:]]*\('

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

# Walk every .c / .h file outside the allow-list and grep for the
# pattern.  The allow-list is "anything under rand/" plus the single
# header include/rnd.h.
while IFS= read -r srcfile; do
	case "$srcfile" in
		./rand/*|rand/*) continue ;;
		./include/rnd.h|include/rnd.h) continue ;;
	esac

	# grep -E -n -H for "path:line:content" output.
	grep -E -H -n "$PATTERN" "$srcfile" 2>/dev/null
done < <(find . \( -name '*.c' -o -name '*.h' \) -type f \
		-not -path './.git/*' -print | sort) | \
while IFS= read -r match; do
	# match is "path:line:content".  Split the first two colons off
	# manually so a colon inside the source line does not corrupt
	# the content field.
	path="${match%%:*}"
	rest="${match#*:}"
	lineno="${rest%%:*}"
	content="${rest#*:}"

	# Trim leading whitespace.
	trimmed="${content#"${content%%[![:space:]]*}"}"

	# Skip block-comment continuation, a banner that opens with
	# `/*`, or a `//` line comment.  These are the only false
	# positives the current tree produces; if a future commit
	# manages to put a real call on a line that *also* contains
	# `/*` we will rediscover that the hard way.
	case "$trimmed" in
		\**)    continue ;;
		/\**)   continue ;;
		//*)    continue ;;
	esac

	echo "${path#./}:$lineno: $trimmed"
done > "$hits_tmp"

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: libc PRNG callsite(s) outside rand/ and include/rnd.h:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: replace with rnd_u32() / rnd_u64() / rnd_modulo_u32()"
		echo "       from include/rnd.h.  See rand/ for the wrapper layer."
	} >&2
	echo "FAIL: $NAME: $n libc-PRNG callsite(s) outside rand/"
	exit 1
fi

echo "PASS: $NAME: 0 libc-PRNG callsites outside rand/"
exit 0
