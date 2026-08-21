#!/bin/bash
#
# getppid-one-literal: flag source lines that compare getppid() against the
# literal constant 1 to detect orphaning.
#
# Background
# ----------
# `if (getppid() == 1)` is only correct when the system's reaper for
# orphaned processes is PID 1 (init).  If any ancestor process has called
# prctl(PR_SET_CHILD_SUBREAPER, 1) -- systemd --user, a container init,
# or a libfuzzer/AFL harness -- orphaned children reparent to that ancestor
# instead of init.  The == 1 test then silently becomes dead code and the
# orphan-containment guarantee evaporates.
#
# The correct idiom captures the parent PID before arming PDEATHSIG:
#
#   pid_t saved_ppid = getppid();          /* before fork or as first child act */
#   (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
#   if (getppid() != saved_ppid)           /* subreaper-safe orphan check */
#       _exit(0);
#
# This check scans .c files under the source tree for the getppid()==1
# literal pattern (both libc and raw-syscall forms) on non-comment lines,
# and reports any hit not pinned in the baseline as FAIL.
#
# Two scan passes are performed:
#
#   Pass 1 (same-line): catches getppid() compared directly against a
#   literal sentinel on the same source line.  Flagged forms:
#     getppid() == 1        (exact init check)
#     getppid() != 1        (inverse sentinel — still subreaper-unsafe)
#     getppid() <= 1        (close-zero — equivalent to == 1 for PIDs)
#     getppid() <  2        (close-zero — equivalent to <= 1 for PIDs)
#     1 == getppid()        (yoda form of exact init check)
#     1 != getppid()        (yoda form of inverse sentinel)
#     getppid() == mainpid  (mainpid sentinel — unsafe at depth > 1)
#     getppid() != mainpid  (inverse mainpid sentinel — unsafe at depth > 1)
#     getppid() <= mainpid  (mainpid sentinel variant)
#     getppid() <  mainpid  (mainpid sentinel variant)
#     mainpid == getppid()  (yoda mainpid sentinel)
#     mainpid != getppid()  (yoda inverse mainpid sentinel)
#     mainpid >= getppid()  (yoda mainpid: equiv to getppid() <= mainpid)
#     mainpid >  getppid()  (yoda mainpid: equiv to getppid() < mainpid)
#     mainpid <= getppid()  (yoda mainpid: equiv to getppid() >= mainpid)
#   All forms are caught for both the libc getppid() and raw-syscall variants.
#
#   Pass 2 (hoisted): catches the common refactoring where the call is
#   separated from the comparison:
#     pid_t p = getppid();   /* hoisted assignment */
#     ...
#     if (p == 1)            /* flagged here */
#     if (1 == p)            /* yoda form — also flagged */
#   The pass finds all local variables assigned from getppid() in each .c
#   file, then checks whether those variables appear in a sentinel comparison
#   (==, !=, <=, <) against literal 1 or 2 anywhere in the same file.
#   NOTE: Pass 2 is file-scoped; it may false-positive if two different
#   functions in the same file both use a same-named local variable but only
#   one function assigns it from getppid().  Pin such sites in the baseline.
#
# 551c2d57bf5e ("userns-bootstrap: add getppid()==1 re-check after
# PR_SET_PDEATHSIG") introduced the last site converted in the batch that
# added this gate; those sites are now all fixed.  Any new occurrence must
# fail this check rather than being silently accepted.
#
# False-positive-friendly: sites that cannot be converted (e.g., because
# they genuinely test for PID 1 as a process identity, not as an orphan
# sentinel) can be pinned in getppid-one-literal.baseline with a reason.

set -u

NAME="getppid-one-literal"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/getppid-one-literal.baseline"

# ---------------------------------------------------------------------------
# Shared operator sets and sentinel comparands — single source of truth.
# Deriving all four patterns from these variables prevents the operator axis
# from diverging between passes and between yoda/non-yoda forms.
#
#   OPS      — operators for non-yoda form: expr OP sentinel
#   OPS_YODA — operators for yoda form:     sentinel OP expr
#              Includes ==|!= (self-mirroring), >= (mirror of <=),
#              > (mirror of <), and <= (to catch mainpid <= getppid()
#              which is equivalent to getppid() >= mainpid — still suspect).
#   SENTINELS — named sentinel comparands (literal 1 handled separately
#              because it also has the < 2 close-zero form).
# ---------------------------------------------------------------------------
OPS='==|!=|<=|<'
OPS_YODA='==|!=|>=|>|<='
SENTINELS='1|mainpid'

# ---------------------------------------------------------------------------
# Pass 1 pattern: getppid() (or raw-syscall equivalents) compared on the
# same line against a literal or named sentinel.
#
# Operators and literals caught:
#   == 1  != 1  <= 1  < 1   (literal 1 via OPS)
#   < 2                     (literal 2 with strict-less — equivalent to <= 1)
#   == mainpid  != mainpid  (mainpid named sentinel — unsafe at fork depth > 1)
#   <= mainpid  < mainpid   (mainpid named sentinel variants)
#   mainpid OP getppid()    (all yoda forms via OPS_YODA)
# ---------------------------------------------------------------------------
CALLEXPR='(getppid[[:space:]]*\(\)|trinity_raw_syscall\([^)]*__NR_getppid[^)]*\)|syscall\([^)]*__NR_getppid[^)]*\))'
PATTERN="${CALLEXPR}[[:space:]]*(($OPS)[[:space:]]*1([^0-9]|$)|<[[:space:]]*2([^0-9]|$))"
# Yoda form: 1 == getppid() / 1 != getppid() — only == and != are meaningful
# on the literal-left side (1 <= getppid() / 1 < getppid() have different
# semantics and are not subreaper-sentinel patterns).
YODA_PATTERN="(^|[^0-9])1[[:space:]]*(==|!=)[[:space:]]*${CALLEXPR}"
# mainpid sentinel: getppid() compared against the mainpid global.  This is
# unsafe at fork depth > 1 — at that depth mainpid != getppid() on every call
# so the guard fires unconditionally.  Only the direct child of main() (where
# the parent IS mainpid) may use this comparison; pin that site in the baseline.
PATTERN_MAINPID="${CALLEXPR}[[:space:]]*($OPS)[[:space:]]*mainpid([^a-z_A-Z0-9]|$)"
# Yoda mainpid form: all forms where mainpid appears on the left.
# Uses OPS_YODA so that >=, >, and <= are caught in addition to == and !=.
YODA_MAINPID_PATTERN="(^|[^a-z_A-Z0-9])mainpid[[:space:]]*($OPS_YODA)[[:space:]]*${CALLEXPR}"

# ---------------------------------------------------------------------------
# Pass 2: hoisted assignment — variable assigned from getppid(), then
# compared against a literal in the same file.
#
# Step A: grep for assignment of getppid() to a local variable name.
# Step B: for each variable found, grep for comparisons against 1 or 2.
# ---------------------------------------------------------------------------
ASSIGN_PATTERN='[a-z_][a-z_0-9]*[[:space:]]*=[[:space:]]*getppid[[:space:]]*\(\)'

# Load baselined file:lineno keys.
# Format: `path/to/file.c:lineno  reason text`
declare -A BASELINED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		entry="${entry#"${entry%%[![:space:]]*}"}"
		key="${entry%%[[:space:]]*}"
		[ -z "$key" ] && continue
		if [[ -v BASELINED["$key"] ]]; then
			echo "FAIL: $NAME: duplicate baseline entry: $key" >&2
			exit 1
		fi
		BASELINED["$key"]=1
	done < "$BASELINE"
fi

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

flagged=0
total=0

# Collect the list of .c files once; both passes iterate over the same set.
mapfile -t srcfiles < <(find "$ROOT" -name '*.c' -type f \
	! -path '*/scripts/*' \
	| sort)

# ---------------------------------------------------------------------------
# Pass 1: same-line getppid() sentinel comparison.
# ---------------------------------------------------------------------------
for srcfile in "${srcfiles[@]}"; do
	while IFS=: read -r lineno content; do
		[ -z "$lineno" ] && continue

		# Skip lines that are comments (leading *, //, or /*).
		trimmed="${content#"${content%%[![:space:]]*}"}"
		case "$trimmed" in
			\**|/\**|//*) continue ;;
		esac

		total=$((total + 1))
		relpath="${srcfile#"$ROOT"/}"
		key="$relpath:$lineno"

		if [ -n "${BASELINED[$key]+x}" ]; then
			BASELINED["$key"]=2
			continue
		fi

		echo "$key: getppid() literal sentinel (==1 / !=1 / <=1 / <2) — use saved-ppid idiom for subreaper safety" >> "$hits_tmp"
		flagged=$((flagged + 1))
	done < <(grep -nE "${PATTERN}|${YODA_PATTERN}|${PATTERN_MAINPID}|${YODA_MAINPID_PATTERN}" "$srcfile" 2>/dev/null)
done

# ---------------------------------------------------------------------------
# Pass 2: hoisted getppid() — variable assigned then compared against literal.
# ---------------------------------------------------------------------------
# Track keys already flagged or baselined in pass 1 to avoid double-counting.
declare -A SEEN_P2=()

for srcfile in "${srcfiles[@]}"; do
	# Step A: collect all variable names assigned from getppid() in this file.
	mapfile -t varnames < <(
		grep -oE "$ASSIGN_PATTERN" "$srcfile" 2>/dev/null \
		| grep -oE '^[a-z_][a-z_0-9]*'
	)
	[ "${#varnames[@]}" -eq 0 ] && continue

	# Deduplicate variable names (a file may assign getppid() to the same
	# variable in multiple branches).
	declare -A seen_vars=()
	unique_vars=()
	for v in "${varnames[@]}"; do
		if [ -z "${seen_vars[$v]+x}" ]; then
			seen_vars["$v"]=1
			unique_vars+=("$v")
		fi
	done
	unset seen_vars

	relpath="${srcfile#"$ROOT"/}"

	for varname in "${unique_vars[@]}"; do
		# Step B: look for this variable compared against literal 1 or 2,
		# including the yoda form (1 == varname / 1 != varname).
		# Require a word boundary before the variable name so we don't
		# match longer identifiers that happen to end with the same suffix.
		# Use the shared OPS/OPS_YODA sets so operators stay in sync with
		# the Pass 1 patterns above.
		cmp_pattern="(^|[^a-z_A-Z0-9])${varname}[[:space:]]*(($OPS)[[:space:]]*(1|mainpid)([^a-z_A-Z0-9]|$)|<[[:space:]]*2([^0-9]|$))"
		cmp_pattern_yoda="(^|[^0-9])1[[:space:]]*(==|!=)[[:space:]]*${varname}([^a-z_A-Z0-9]|$)|(^|[^a-z_A-Z0-9])mainpid[[:space:]]*($OPS_YODA)[[:space:]]*${varname}([^a-z_A-Z0-9]|$)"

		while IFS=: read -r lineno content; do
			[ -z "$lineno" ] && continue

			# Skip comment lines.
			trimmed="${content#"${content%%[![:space:]]*}"}"
			case "$trimmed" in
				\**|/\**|//*) continue ;;
			esac

			key="$relpath:$lineno"

			# Skip if already processed (pass 1 hit, baselined, or
			# a prior variable in this file already flagged this line).
			if [ -n "${BASELINED[$key]+x}" ]; then
				BASELINED["$key"]=2
				continue
			fi
			[ -n "${SEEN_P2[$key]+x}" ] && continue
			SEEN_P2["$key"]=1

			total=$((total + 1))

			echo "$key: hoisted getppid() via '$varname' compared against literal sentinel — use saved-ppid idiom for subreaper safety" >> "$hits_tmp"
			flagged=$((flagged + 1))
		done < <(grep -nE "${cmp_pattern}|${cmp_pattern_yoda}" "$srcfile" 2>/dev/null)
	done
done

# Report stale baseline entries (advisory, non-fatal).
stale=()
for key in "${!BASELINED[@]}"; do
	if [ "${BASELINED[$key]}" = "1" ]; then
		stale+=("$key")
	fi
done

if [ "$flagged" -gt 0 ]; then
	{
		echo "  $NAME: $flagged getppid() literal sentinel(s) found on non-comment lines:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: capture expected_ppid = getpid() in the forking parent"
		echo "       immediately before fork(), pass it to the child (struct field"
		echo "       or function parameter), and compare getppid() != expected_ppid."
		echo "       Do NOT use saved_ppid = getppid() inside the child -- that idiom"
		echo "       is logically inverted.  Do NOT compare against mainpid either:"
		echo "       it is the top-level orchestrator pid, so at depth > 1 (forked by"
		echo "       a worker, not by main) the comparison is unequal on every call"
		echo "       and the guard fires unconditionally."
		echo "       If the site genuinely tests for init as a process identity (not an"
		echo "       orphan sentinel), pin it in scripts/check-static/getppid-one-literal.baseline."
	} >&2
fi

if [ "${#stale[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale[@]} baseline entry/entries no longer match (consider pruning):"
		for e in "${stale[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "$flagged" -gt 0 ]; then
	echo "FAIL: $NAME: $flagged getppid() literal sentinel(s) not in baseline"
	exit 1
fi

baseline_size=${#BASELINED[@]}
echo "PASS: $NAME (hits=$total, baselined=$baseline_size)"
exit 0
