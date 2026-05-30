#!/bin/bash
#
# activate-syscall-active-flag: enforce the ACTIVE-flag / activate
# pairing for every direct activate_syscall*() callsite.
#
# The active_syscalls[] (and active_syscalls32[] / active_syscalls64[])
# arrays store calln+1 for activated entries, with active_number used
# as the back-index.  Decoders downstream assume that every slot
# carrying the +1 shift corresponds to a syscall entry whose ACTIVE
# flag was set at activation time; that flag gates init_syscalls(),
# dump_syscall_tables(), display_enabled_syscalls() and the various
# picker eligibility checks.  A callsite that invokes
# activate_syscall*() *without* first setting the ACTIVE flag leaves
# the entry registered in the active table but invisible to the
# flag-driven consumers -- a uniarch setup path regressed exactly
# this way and had to be patched.
#
# Canonical pairing in this tree is:
#
#     entry->flags |= ACTIVE;
#     activate_syscall(i);          /* or _32 / _64 */
#
# This check scans every .c file outside include/ and rand/ for
# direct activate_syscall*() calls, skipping function definitions
# (lines that match the prototype shape and do not terminate with
# `;`) and comment lines, and FAILs any call whose preceding source
# lines do not set the ACTIVE flag and whose enclosing function is
# not on the canonical toggle-helper allow-list.

set -u

NAME="activate-syscall-active-flag"
ROOT="${REPO_ROOT:-$(pwd)}"

# Lookback window (in source lines) examined before each call for an
# ACTIVE flag set.  Three lines covers the canonical two-liner with
# room for one intervening blank or comment.
LOOKBACK=3

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

# include/ holds the header declarations (those end in `;` and would
# never match the pairing rule); rand/ has no syscall-table code.
find . -name '*.c' -type f \
		-not -path './.git/*' \
		-not -path './include/*' \
		-not -path './rand/*' \
		-print | sort | \
while IFS= read -r srcfile; do
	awk -v LOOKBACK="$LOOKBACK" -v FILE="${srcfile#./}" '
	BEGIN {
		# Allow-listed toggle helpers.  These functions own the
		# ACTIVE/activate pairing for their callers; if a future
		# refactor relocates the flag set further than LOOKBACK
		# lines from the call inside one of these helpers we do
		# not want to false-positive.  Keep this list tight -- a
		# new entry should only be added with reviewer sign-off.
		helper["toggle_syscall_n"] = 1
		helper["toggle_syscall_biarch_n"] = 1
		helper["setup_syscall_group_uniarch"] = 1
		helper["setup_syscall_group_biarch"] = 1
		helper["mark_all_syscalls_active_uniarch"] = 1
		helper["mark_all_syscalls_active_biarch"] = 1

		# Direct-call pattern.  The leading (^|[^A-Za-z0-9_])
		# alternation acts as a portable word boundary so the
		# pattern does not fire inside deactivate_syscall* or
		# activate_syscall_in_table.  The optional suffix group
		# enumerates every direct-callable variant.
		call_re = "(^|[^A-Za-z0-9_])activate_syscall(32|64|_uniarch|_biarch)?[ \t]*\\("

		# ACTIVE flag set: either an `entry->flags |= ACTIVE`
		# style assignment or a hypothetical set_active() helper.
		active_re = "flags[ \t]*[|&^]?=[^;]*ACTIVE|set_active[ \t]*\\("

		# Function-definition shape: column-0 identifier prefix,
		# the activate_syscall token, an opening paren, and the
		# line must not end with `;` (that would be a prototype,
		# but include/ is already excluded).  We classify with the
		# call_re hit + a no-semicolon trailing check below.
		cur_fn = ""
	}
	{
		line = $0

		trimmed = line
		sub(/^[ \t]+/, "", trimmed)

		rstripped = line
		sub(/[ \t]+$/, "", rstripped)

		# Track the enclosing top-level function name.  Trinity
		# style: signatures begin at column 0 with the return
		# type and qualifiers, and the function name is the last
		# whitespace/asterisk-delimited token before the opening
		# paren.  Extract it whenever we see a column-0 line that
		# looks like a signature.
		if (line ~ /^[A-Za-z_].*\(/) {
			tmp = line
			sub(/\(.*/, "", tmp)
			sub(/[ \t\*]+$/, "", tmp)
			n2 = split(tmp, parts, /[ \t\*]+/)
			if (n2 > 0 && parts[n2] != "")
				cur_fn = parts[n2]
		}

		# A top-level `}` ends the current function.  We clear
		# cur_fn AFTER processing this lines match so a call on
		# the last line of a helper still attributes correctly.
		closes = (line ~ /^\}/)

		# Comment-line classification.  Mirrors no-libc-rand.sh.
		is_comment = 0
		if (trimmed ~ /^\*/)       is_comment = 1
		else if (trimmed ~ /^\/\*/) is_comment = 1
		else if (trimmed ~ /^\/\//) is_comment = 1

		# Save this line into the lookback ring BEFORE matching;
		# the lookback loop reads NR-1..NR-LOOKBACK, never NR.
		ring[NR % (LOOKBACK + 1)] = line

		if (!is_comment && line ~ call_re) {
			# Distinguish a definition (no terminating `;`)
			# from a call (terminates with `;` after the
			# close paren).  Trinity does not split calls
			# across lines, so this is reliable here.
			is_defn = (rstripped !~ /;$/)

			if (!is_defn) {
				found_active = 0
				for (k = 1; k <= LOOKBACK; k++) {
					if (NR - k < 1) break
					prev = ring[(NR - k) % (LOOKBACK + 1)]
					if (prev ~ active_re) {
						found_active = 1
						break
					}
				}
				if (!found_active && !(cur_fn in helper))
					printf "%s:%d: %s\n", FILE, NR, trimmed
			}
		}

		if (closes)
			cur_fn = ""
	}
	' "$srcfile"
done > "$hits_tmp"

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: activate_syscall*() callsite(s) missing ACTIVE flag pairing:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: precede the call with"
		echo "         entry->flags |= ACTIVE;"
		echo "       or move the call into a canonical toggle helper."
	} >&2
	echo "FAIL: $NAME: $n callsite(s) without preceding ACTIVE flag set"
	exit 1
fi

echo "PASS: $NAME"
exit 0
