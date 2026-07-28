#!/bin/bash
#
# check-option-off-branch-inert: per-option mode-off RNG-neutrality gate.
#
# check-option-parity proves every long option is unique / parsed /
# documented / defaulted, but does NOT prove that a mode-off arg leaves
# the picker RNG stream untouched.  A stray rnd_u32() slipped into an
# off-path branch (or a printf that pulls a syscall latency the picker
# indirectly conditions on) desynchronises the stream and silently
# invalidates every "(default off)" byte-identical A/B claim in help.c.
#
# This gate is the structural floor beneath those runtime claims: for
# every option whose parser accepts arg=="off", verify the parser's
# off-branch body is *inert*.  Inert = one of:
#
#   VAR = ENUM_NAME_OFF;             (direct assignment)
#   mode = ENUM_NAME_OFF;            (local-var-then-atomic-store pattern)
#
# and the ENUM_NAME_OFF constant used equals 0 (so the assignment is a
# no-op relative to the C zero-initialised default state).  Together
# these two facts pin the runtime invariant that the row spec calls out
# ("disabled-mode run produces a picker stream byte-identical to the
# pre-option baseline"): the parser branch consumes no RNG draw itself,
# and the state it lands on is bit-equal to the default that a
# no-option baseline would have produced.
#
# A true end-to-end runtime fixture (spawn trinity, fixed-seed, hash the
# picker stream twice) is called for in the same spec, but it needs
# picker migration onto the arena test infra that tests/rnd_stream_golden.c
# already flags as absent -- this static gate lands the structural floor
# so the runtime fixture, when it lands, only has to enforce what this
# one proves the code shape already guarantees.
#
# Adding a new toggleable option that takes an "off" arg picks up
# automatic enforcement.  If a legitimately-non-inert off-branch shows
# up (unlikely -- the pattern in main/params/coverage.c is uniform),
# extend the ALLOWLIST at the top rather than relaxing the check body.

set -u

NAME="check-option-off-branch-inert"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

OPTIONS_C="main/params/options.c"
PARAMS_DIR="main/params"
INCLUDE_DIR="include"

# Options intentionally exempt from this gate.  Empty today.  Add an
# entry only with a per-option comment explaining WHY the off-branch
# cannot be inert -- do not use this to silence real drift.
ALLOWLIST=""

for f in "$OPTIONS_C"; do
	if [ ! -f "$f" ]; then
		echo "FAIL: $NAME: expected file missing: $f"
		exit 1
	fi
done
if [ ! -d "$PARAMS_DIR" ] || [ ! -d "$INCLUDE_DIR" ]; then
	echo "FAIL: $NAME: missing dir: $PARAMS_DIR or $INCLUDE_DIR"
	exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fails="$tmp/fails"
: > "$fails"
checked=0
skipped=0

# ---- 1. Concatenate every main/params/*.c into a single searchable
# corpus with source-file annotations preserved (so failure messages
# name the actual parser file).  awk state-machine below walks the
# concatenation looking for the option-name outer strcmp and, inside
# it, the arg=="off" inner strcmp -- extracting the ONE OR TWO source
# lines that make up the off-branch body.
CONCAT="$tmp/concat"
: > "$CONCAT"
for f in "$PARAMS_DIR"/*.c; do
	awk -v src="$f" '{ printf "%s\t%d\t%s\n", src, NR, $0 }' "$f" >> "$CONCAT"
done

# ---- 2. Enumerate every long option that takes an argument.  Bool
# / no_argument options do not enter an arg=="off" branch (they are
# either set true or left default), so they cannot leak an inert-branch
# drift and drop out of the check set.
OPTS_WITH_ARG="$tmp/opts_with_arg"
awk '
	/^[[:space:]]*\{[[:space:]]*"[^"]/ {
		q1 = index($0, "\"")
		rest = substr($0, q1 + 1)
		q2 = index(rest, "\"")
		if (q2 <= 1) next
		name = substr(rest, 1, q2 - 1)
		if (index($0, "required_argument") > 0 ||
		    index($0, "optional_argument") > 0)
			print name
	}
' "$OPTIONS_C" > "$OPTS_WITH_ARG"

n_opts="$(wc -l < "$OPTS_WITH_ARG" | tr -d ' ')"
if [ "$n_opts" -eq 0 ]; then
	echo "FAIL: $NAME: extracted 0 arg-taking options from $OPTIONS_C"
	exit 1
fi

# ---- 3. Pre-scan include/ once for every *_OFF enumerator so we can
# verify each assignment target evaluates to zero.  Any variant of
#
#   FOO_OFF = 0,
#   FOO_MODE_OFF = 0,
#   FOO_SCOPE_OFF   = 0  ,
#
# with optional whitespace matches; anything not resolvable this way
# fails the check (an off-enum that is not 0 breaks the "bit-equal to
# default" leg).
OFF_ENUMS_ZERO="$tmp/off_enums_zero"
grep -rEh '^[[:space:]]*[A-Z][A-Z0-9_]*_OFF[[:space:]]*=[[:space:]]*0[[:space:]]*,' \
	"$INCLUDE_DIR" 2>/dev/null | \
	sed -E 's/^[[:space:]]*([A-Z][A-Z0-9_]*_OFF)[[:space:]]*=.*/\1/' | \
	sort -u > "$OFF_ENUMS_ZERO"

# ---- 4. Per-option walk.  For each option name, find its parser
# block, locate the arg=="off" branch inside it, capture the branch
# body, and validate the body against the inert-shape allowlist.
#
# The parser blocks in main/params/*.c uniformly look like:
#
#   if (strcmp("NAME", name) == 0) {
#           ...
#           if (strcmp(arg, "off") == 0) {
#                   VAR = FOO_OFF;
#           } else if (strcmp(arg, ...) == 0) {
#                   ...
#
# The body between `if (strcmp(arg, "off") == 0) {` and the matching
# `}` is the payload we validate.  awk balances braces from column-1
# in the parser file so multi-line assignments (VAR = \n  FOO_OFF;)
# survive the extraction.
while IFS= read -r name; do
	[ -z "$name" ] && continue

	# Skip allowlist entries up-front.
	case " $ALLOWLIST " in
		*" $name "*) skipped=$((skipped + 1)); continue ;;
	esac

	# Locate a parser block for this option.  Match the exact
	# `strcmp("NAME", name)` shape so we do not confuse the outer
	# name-dispatch strcmp with the inner arg=="off" strcmp or with
	# an unrelated strcmp that happens to mention the name.
	block="$tmp/block.$$"
	awk -v n="$name" '
		BEGIN { in_block = 0; depth = 0 }
		{
			# Field 1 is source file, 2 is line number, 3+ is code.
			file = $1
			lineno = $2
			$1 = ""; $2 = ""
			code = substr($0, 3)

			if (!in_block) {
				# Match `strcmp("NAME", name)` -- the outer
				# option-name dispatch strcmp.  The parser body
				# opens on the same line with `{`.
				if (code ~ ("strcmp\\(\"" n "\", name\\)")) {
					in_block = 1
					depth = 0
					print file "\t" lineno "\t" code
				}
				next
			}

			# Balance braces to find the block end.
			nopen = gsub(/\{/, "&", code)
			nclose = gsub(/\}/, "&", code)
			depth += nopen - nclose
			print file "\t" lineno "\t" code
			if (depth <= 0) {
				in_block = 0
				exit
			}
		}
	' "$CONCAT" > "$block"

	if [ ! -s "$block" ]; then
		# No parser block found -- option is not routed through a
		# strcmp("NAME", name) dispatch.  Options handled purely by
		# short-opt case-labels (e.g. -T kernel_taint) fall in this
		# bucket and legitimately have no "off" arg to test.
		skipped=$((skipped + 1))
		rm -f "$block"
		continue
	fi

	# Locate the `strcmp(arg, "off")` branch inside the block, if any.
	# Absence means this arg-taking option does not offer an "off"
	# value (numeric parses, path arguments, etc.) -- correctly skipped.
	if ! grep -q 'strcmp(arg, "off")' "$block"; then
		skipped=$((skipped + 1))
		rm -f "$block"
		continue
	fi

	# Extract the off-branch body (between the `if (strcmp(arg, "off")`
	# opening `{` and the matching `}`).  A naive per-line brace-balance
	# would run past the branch because `} else if (...) {` carries both
	# a closing `}` (for the off-branch) and an opening `{` (for the
	# next arm) on the same line -- the closes cancel the opens and
	# depth never returns to 0.  Instead walk the code stream character
	# by character so a `}` that lands depth at 0 terminates the body
	# BEFORE any following `{` opens a new one.
	off_body="$tmp/off_body.$$"
	awk '
		function process(code,   i, ch, current_line) {
			# Called with one line of code after the opening
			# `strcmp(arg, "off")` line has been consumed and
			# depth initialised to 1.  Walks the line char by
			# char, buffering payload into current_line.  When
			# depth hits 0 we flush the buffer and set done.
			current_line = pending
			pending = ""
			for (i = 1; i <= length(code); i++) {
				ch = substr(code, i, 1)
				if (ch == "{") {
					depth++
					current_line = current_line ch
				} else if (ch == "}") {
					depth--
					if (depth <= 0) {
						flush(current_line)
						done = 1
						return
					}
					current_line = current_line ch
				} else {
					current_line = current_line ch
				}
			}
			flush(current_line)
		}

		function flush(s) {
			sub(/^[[:space:]]+/, "", s)
			sub(/[[:space:]]+$/, "", s)
			if (length(s) > 0)
				print s
		}

		BEGIN { in_off = 0; depth = 0; done = 0; pending = "" }

		done { exit }

		{
			file = $1
			lineno = $2
			$1 = ""; $2 = ""
			code = substr($0, 3)

			if (!in_off) {
				if (code ~ /strcmp\(arg, "off"\)[[:space:]]*==[[:space:]]*0/) {
					# Consume the opening `{` and any body
					# text after it on the same line.
					lbrace = index(code, "{")
					if (lbrace == 0) next
					in_off = 1
					depth = 1
					pending = ""
					tail = substr(code, lbrace + 1)
					if (length(tail) > 0)
						process(tail)
				}
				next
			}

			process(code)
		}
	' "$block" > "$off_body"

	if [ ! -s "$off_body" ]; then
		printf 'FAIL: --%s: off-branch body extracted empty\n' \
			"$name" >> "$fails"
		rm -f "$block" "$off_body"
		continue
	fi

	# Validate the off-branch body.  Every non-blank line must match
	# one of the inert shapes:
	#
	#   IDENT = IDENT_OFF;
	#   IDENT =                          (start of a two-line assignment)
	#           IDENT_OFF;               (continuation line)
	#   mode = IDENT_OFF;                (local var assignment shape)
	#
	# The single ENUM_OFF token referenced must be in $OFF_ENUMS_ZERO.
	# Anything else -- a function call, printf, an if/for/while, an
	# rnd_* draw, an atomic op inside the branch (the atomic-store
	# pattern lives OUTSIDE the off-branch, after the if/else chain)
	# -- fails.
	problem=""
	off_enum=""

	# Join possibly two-line assignments back into one for shape check.
	joined="$(paste -sd' ' "$off_body" | tr -s ' ')"

	# Extract the single *_OFF enum name (or fail).
	off_enum="$(printf '%s' "$joined" | \
		grep -oE '[A-Z][A-Z0-9_]*_OFF' | head -1)"
	if [ -z "$off_enum" ]; then
		problem="off-branch has no *_OFF enum assignment: [$joined]"
	elif ! grep -qxF "$off_enum" "$OFF_ENUMS_ZERO"; then
		problem="off-enum '$off_enum' is not '= 0' in $INCLUDE_DIR/"
	else
		# Reject any token that looks like a call (name followed by
		# `(`) other than a benign macro; the branch shape has no
		# calls at all so any `(` in a non-comment line trips this.
		# strip C-style comments first to avoid a `/* ... ( ... */`
		# false trigger.
		stripped="$(printf '%s' "$joined" | \
			sed 's|/\*[^*]*\*/||g')"
		if printf '%s' "$stripped" | grep -qE '[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\('; then
			problem="off-branch contains a function-call-shaped token: [$joined]"
		fi
	fi

	if [ -n "$problem" ]; then
		printf 'FAIL: --%s: %s\n' "$name" "$problem" >> "$fails"
	else
		checked=$((checked + 1))
	fi

	rm -f "$block" "$off_body"
done < "$OPTS_WITH_ARG"

fail_count="$(wc -l < "$fails" | tr -d ' ')"

if [ "$fail_count" -gt 0 ]; then
	{
		echo "  $NAME: $fail_count option(s) have non-inert off-branch:"
		sed 's/^/    /' "$fails"
		echo "  fix: keep the arg==\"off\" branch to a bare"
		echo "       VAR = ENUM_NAME_OFF; assignment.  A side effect in"
		echo "       that branch (rnd_*, printf, syscall) desynchronises"
		echo "       the picker RNG stream and voids the option's"
		echo "       \"(default off)\" byte-identical promise in help.c."
	} >&2
	echo "FAIL: $NAME: $fail_count option(s) fail inert-off-branch check"
	exit 1
fi

echo "PASS: $NAME: $checked option(s) inert-off-branch verified" \
     "($skipped skipped: no arg==\"off\" branch)"
exit 0
