#!/bin/bash
#
# check-option-parity: every long option in main/params/options.c must be
# unique in the table, reached by a parser case, documented, and have a
# backing default.
#
# The five files that carry each option are edited independently:
#
#   main/params/options.c    -- getopt_long() longopts[] metadata
#   main/params/parse.c      -- getopt loop + short-opt cases
#   main/params/*.c          -- parse_*_options() family helpers that
#                               claim options via case labels or by
#                               matching the name with strcmp()
#   main/params/help.c       -- option_descs[] --help table
#   Documentation/*.md       -- prose docs (some options are described
#                               there instead of, or in addition to,
#                               help.c)
#   main/params/state.c      -- initial values for the option-backed
#                               globals
#   main/params/defaults.c   -- clamp_default_*() post-parse fillers
#
# Drift between them shows up on-host as either "option accepted but
# does nothing" (parser gap) or "internal error: unhandled long option
# --NAME" (parse.c fatal for opt==0 with no claimer).  This gate is a
# structural tripwire that catches the drift before a fuzz host does.
#
# Per-option checks:
#
#   (a) uniqueness -- NAME appears exactly once in longopts[].
#   (b) parsed     -- if NAME has a short-opt char C then some
#                     main/params/*.c has `case 'C':` OR `opt == 'C'`;
#                     otherwise (val==0 long-only) some main/params/*.c
#                     has strcmp("NAME".
#   (c) documented -- NAME appears as an option_descs[] entry in help.c
#                     OR --NAME appears in some Documentation/*.md file.
#   (d) defaulted  -- identifier form of NAME (dashes -> underscores)
#                     appears as a substring in state.c or defaults.c;
#                     failing that, in any other tree .c file (many
#                     subsystems own their own default -- e.g.
#                     blob_mutator_mode lives in args/pools/blob_mutator.c,
#                     cmsg_richness_mode in lib/cmsg_build.c);
#                     failing that, a dash-split token of length >=4
#                     (optionally with a trailing 's' stripped) does.
#                     A short allow-list covers info-dump commands and
#                     composite flags that legitimately hold no direct
#                     state of their own (--help / --bdev exit inside
#                     the parser, --hermetic drives other --no-*-warm-start
#                     flags, --enable-fds / --disable-fds mutate the fd
#                     registry via process_fds_param()).
#
# The (d) heuristic accepts substring hits because option identifiers
# often expand into qualified globals (e.g. --canary-window ->
# canary_window_iters, --childop-kcov-attribution -> childop_kcov_attr_mode).
# The intent is mechanical drift detection, not name-mirroring enforcement:
# a NEW option with zero token overlap in the tree is the signal, and
# that is what this check surfaces.

set -u

NAME="check-option-parity"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

OPTIONS_C="main/params/options.c"
HELP_C="main/params/help.c"
DEFAULTS_C="main/params/defaults.c"
STATE_C="main/params/state.c"
PARAMS_DIR="main/params"
DOCS_DIR="Documentation"

# Options that legitimately have no backing state variable:
# info-dump commands that call a printer and exit(EXIT_SUCCESS)
# straight out of the parser helper.  Adding a new entry here is a
# deliberate act -- consider whether the option really is state-free
# before doing so.
NO_STATE_OPTS=" help bdev hermetic enable_fds disable_fds "

for f in "$OPTIONS_C" "$HELP_C" "$DEFAULTS_C" "$STATE_C"; do
	if [ ! -f "$f" ]; then
		echo "FAIL: $NAME: expected file missing: $f"
		exit 1
	fi
done
if [ ! -d "$PARAMS_DIR" ]; then
	echo "FAIL: $NAME: missing dir: $PARAMS_DIR"
	exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- 1. Extract (name, short-char) for every longopts[] entry.
# A row looks like: { "NAME", required_argument, NULL, VAL },
# where VAL is either a char literal (like 'a') or the integer 0.
# The { NULL, 0, NULL, 0 } terminator lacks a quoted first field so
# it drops out.  awk regex uses \047 for the single quote so the
# whole program stays inside a single-quoted shell string.
awk '
	/^[[:space:]]*\{[[:space:]]*"[^"]/ {
		q1 = index($0, "\"")
		rest = substr($0, q1 + 1)
		q2 = index(rest, "\"")
		if (q2 <= 1) next
		name = substr(rest, 1, q2 - 1)

		tail = substr(rest, q2 + 1)
		short = ""
		if (match(tail, /\047.\047/) > 0) {
			short = substr(tail, RSTART + 1, 1)
		}
		printf "%s\t%s\n", name, short
	}
' "$OPTIONS_C" > "$tmp/opts"

n_opts="$(wc -l < "$tmp/opts" | tr -d ' ')"
if [ "$n_opts" -eq 0 ]; then
	echo "FAIL: $NAME: extracted 0 long options from $OPTIONS_C"
	exit 1
fi

# ---- 2. Pre-collect the corpora we grep against.
find "$PARAMS_DIR" -maxdepth 1 -type f -name '*.c' > "$tmp/params_srcs"

if [ -d "$DOCS_DIR" ]; then
	find "$DOCS_DIR" -type f -name '*.md' > "$tmp/docs" 2>/dev/null || : > "$tmp/docs"
else
	: > "$tmp/docs"
fi

# Concatenate state.c + defaults.c into one buffer for the primary
# (d) check.  Build a second, whole-tree corpus (all .c files outside
# .git / tests / scripts / vendor) for the fallback pass -- some
# option-backed defaults live in the subsystem module that owns the
# flag (blob_mutator_mode in args/pools/blob_mutator.c, etc.) rather
# than in the central state.c.
cat "$STATE_C" "$DEFAULTS_C" > "$tmp/defaults_corpus"
find . \( -path ./.git -o -path ./tests -o -path ./scripts \) -prune -o \
	-type f -name '*.c' -print > "$tmp/tree_csrcs"

# Count each name once (uniqueness).
cut -f1 "$tmp/opts" | sort | uniq -c > "$tmp/name_counts"

# ---- 3. Per-option checks.
fails="$tmp/fails"
: > "$fails"
pass_count=0

# Returns 0 if $1 (a haystack file) contains $2 as a substring.
contains_substring() {
	grep -q -F -- "$2" "$1"
}

while IFS=$'\t' read -r name short; do
	[ -z "$name" ] && continue
	problems=""

	# (a) uniqueness in longopts[]
	count="$(awk -v n="$name" '$2 == n { print $1 }' "$tmp/name_counts")"
	if [ -z "$count" ] || [ "$count" != "1" ]; then
		problems="${problems}duplicate-in-options.c(x${count:-0}); "
	fi

	# (b) parsed
	if [ -n "$short" ]; then
		# Accept either the switch-form `case 'X':` or the equality
		# form `opt == 'X'` -- both are used by parser helpers.
		if ! xargs grep -l -F -- "case '${short}':" < "$tmp/params_srcs" >/dev/null 2>&1 && \
		   ! xargs grep -l -F -- "opt == '${short}'" < "$tmp/params_srcs" >/dev/null 2>&1; then
			problems="${problems}no-case-or-opt=='${short}'-in-main/params/*.c; "
		fi
	else
		# Long-only opt: some helper must strcmp("name",...) it.
		if ! xargs grep -l -F -- "strcmp(\"${name}\"" < "$tmp/params_srcs" >/dev/null 2>&1; then
			problems="${problems}no-strcmp(\"${name}\")-in-main/params/*.c; "
		fi
	fi

	# (c) documented
	doc_ok=0
	if contains_substring "$HELP_C" "\"${name}\""; then
		doc_ok=1
	elif [ -s "$tmp/docs" ] && xargs grep -l -F -- "--${name}" < "$tmp/docs" >/dev/null 2>&1; then
		doc_ok=1
	fi
	if [ "$doc_ok" -eq 0 ]; then
		problems="${problems}not-in-help.c-or-Documentation/; "
	fi

	# (d) defaulted.  Allow-list first, then substring, then per-token
	# substring (with an optional trailing-'s' strip so plural option
	# names like --ioctls / --victims still match the singular
	# state-variable roots like show_ioctl_list / victim_paths).
	ident="$(printf '%s' "$name" | tr '-' '_')"
	default_ok=0
	case "$NO_STATE_OPTS" in
		*" $ident "*) default_ok=1 ;;
	esac
	if [ "$default_ok" -eq 0 ] && contains_substring "$tmp/defaults_corpus" "$ident"; then
		default_ok=1
	fi
	# Whole-tree fallback: many subsystems own their own default.
	if [ "$default_ok" -eq 0 ] && \
	   xargs grep -l -F -- "$ident" < "$tmp/tree_csrcs" >/dev/null 2>&1; then
		default_ok=1
	fi
	if [ "$default_ok" -eq 0 ]; then
		# Split identifier on underscores and try tokens of length >=4.
		IFS='_' read -ra tokens <<<"$ident"
		for tok in "${tokens[@]}"; do
			if [ "${#tok}" -ge 4 ] && contains_substring "$tmp/defaults_corpus" "$tok"; then
				default_ok=1
				break
			fi
			# Strip a trailing 's' (plural -> singular) and re-check.
			case "$tok" in
				*s)
					sing="${tok%s}"
					if [ "${#sing}" -ge 4 ] && contains_substring "$tmp/defaults_corpus" "$sing"; then
						default_ok=1
						break
					fi
					;;
			esac
			if [ "$default_ok" -eq 1 ]; then break; fi
		done
	fi
	if [ "$default_ok" -eq 0 ]; then
		problems="${problems}no-default-for-'${ident}'-in-state.c/defaults.c; "
	fi

	if [ -n "$problems" ]; then
		printf 'FAIL: --%s: %s\n' "$name" "${problems% }" >> "$fails"
	else
		pass_count=$((pass_count + 1))
	fi
done < "$tmp/opts"

fail_count="$(wc -l < "$fails" | tr -d ' ')"

if [ "$fail_count" -gt 0 ]; then
	{
		echo "  $NAME: $fail_count option(s) failed parity:"
		sed 's/^/    /' "$fails"
		echo "  fix: reconcile main/params/options.c against"
		echo "       main/params/{parse,help,defaults,state}.c and Documentation/"
	} >&2
	echo "FAIL: $NAME: $fail_count/$n_opts long option(s) fail parity"
	exit 1
fi

echo "PASS: $NAME: $pass_count/$n_opts long option(s) unique+parsed+documented+defaulted"
exit 0
