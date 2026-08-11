#!/bin/bash
#
# signal-disposition-ownership: two checks that guard process-wide
# signal-table state from being silently mutated by childop or mm code.
#
# Check 1 — SIG_DFL + raise (beacon-drop pattern)
# ------------------------------------------------
# signal(sig, SIG_DFL) followed immediately by raise(sig) resets the
# per-signal disposition to the kernel default before delivering the
# signal.  In any code path outside health/ this silently prevents the
# trinity fault beacon from firing: the signal is delivered bare, the
# health fault handler is never entered, and the parent sees an
# unexplained WIFSIGNALED child rather than a beacon-instrumented crash.
# This pattern is inherently correct ONLY inside health/signals-policy.c
# where SIG_DFL is deliberately set before a controlled re-raise so that
# the kernel's default action (core, terminate) executes after the
# beacon has finished.  Everywhere else it is a bug.
#
# The check greps every .c file outside health/ and scripts/check-static/
# for signal(…SIG_DFL…) calls and, for each hit, tests whether raise(
# appears within 2 source lines.  Proximity of 2 lines catches the
# canonical one-liner form and the common "blank line between" variant.
# The 2-line window is a deliberate floor — cross-statement or
# cross-function reset-then-raise (e.g. signal() in a loop body, raise()
# in a separate function called later) is intentionally out of scope.
# Files that contain whole-table SIG_DFL resets in grandchild sanitizers
# with no raise() reachable within the window are inherently correct;
# pre-emptive exemptions for the known sites are documented in the
# allowlist.
#
# Check 1b — sigaction-expressed SIG_DFL + raise (beacon-drop via sa_handler)
# -----------------------------------------------------------------------------
# sa.sa_handler = SIG_DFL; sigaction(SIGX, &sa, NULL); raise(SIGX);
# has identical semantics to the signal() form above and is the form
# used by the prior 495-A defect sites.  The check scans for
# sa_handler = SIG_DFL paired with a sigaction(SIG install in the same
# file, then applies the same 2-line proximity test for raise(.
#
# Check 2 — sigaction disposition ownership (canonical-snapshot invariant)
# ------------------------------------------------------------------------
# Polices SIGSEGV and SIGBUS only.  SIGABRT and SIGILL installs from
# non-health/ code are currently unpoliced by this check.
#
# Any childop or mm translation unit that installs a new SIGSEGV or
# SIGBUS handler must first read the canonical disposition that health/
# established at startup.  The canonical read is:
#
#     sigaction(SIGSEGV, NULL, &saved_sa);   /* read, do not write */
#
# Without that snapshot the saved handler pointer is whatever was
# previously installed by an earlier (possibly leaked) uffd worker or
# other path — stale state that corrupts the restore-on-exit chain.
#
# The check flags any file outside health/ that:
#   - contains a sigaction(SIGSEGV, …) or sigaction(SIGBUS, …) call
#     where the second argument is non-NULL (i.e. it installs a handler), AND
#   - does NOT contain a canonical-read pattern in the same file:
#       sigaction(SIG(SEGV|BUS), NULL, &…)   (read-current-disposition call)
#
# Allowlist
# ---------
# Known-good or accepted-risk sites are listed in
# signal-disposition-ownership.allowlist (file:line:hash, same format as
# childop-lock-call.allowlist).  Dead allowlist entries (key never
# matched by the scanner) cause a FAIL so stale suppressions are caught.

set -u

NAME="signal-disposition-ownership"
ROOT="${REPO_ROOT:-$(pwd)}"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
ALLOWLIST_FILE="$SCRIPT_DIR/signal-disposition-ownership.allowlist"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

declare -A allowlist
declare -A allowlist_matched

if [ -f "$ALLOWLIST_FILE" ]; then
	while IFS= read -r entry; do
		[[ -z "$entry" || "$entry" == \#* ]] && continue
		_key="${entry%%[[:space:]]*}"
		allowlist["$_key"]=1
	done < "$ALLOWLIST_FILE"
fi

fail_count=0

# ---------------------------------------------------------------------------
# Check 1: signal(X, SIG_DFL) followed by raise() within 2 source lines.
# Exclude health/ (intentional) and scripts/check-static/ (test fixtures).
# ---------------------------------------------------------------------------
while IFS= read -r srcfile; do
	while IFS=: read -r lineno content; do
		trimmed=$(printf '%s' "$content" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

		# Skip comment-only lines.
		case "$trimmed" in
			\**) continue ;; /\**) continue ;; //*) continue ;;
		esac

		# Check if raise( appears within 2 lines of this signal call
		# (inclusive of the matched line itself — catches one-liner form).
		end_line=$((lineno + 2))
		has_raise=$(awk -v start="$lineno" -v end="$end_line" '
			NR >= start && NR <= end && /raise[[:space:]]*\(/ { print; exit }
		' "$srcfile")
		[ -z "$has_raise" ] && continue

		hash=$(printf '%s' "$trimmed" | sha256sum | cut -c1-8)
		key="${srcfile#./}:$lineno:$hash"

		if [ "${allowlist[$key]+set}" ]; then
			allowlist_matched[$key]=1
			continue
		fi

		echo "FAIL: $NAME: check1: $key: signal(SIG_DFL)+raise() drops fault beacon"
		fail_count=$((fail_count + 1))
	done < <(grep -En 'signal[[:space:]]*\([^)]*SIG_DFL' "$srcfile" 2>/dev/null)
done < <(find . -name '*.c' -type f \
	-not -path './health/*' \
	-not -path './scripts/check-static/*' \
	| sort)

# ---------------------------------------------------------------------------
# Check 1b: sa_handler = SIG_DFL paired with sigaction(SIG install + raise().
# Same beacon-drop hazard as check1, expressed via the sigaction(3) API.
# ---------------------------------------------------------------------------
while IFS= read -r srcfile; do
	# Skip files that don't combine sa_handler=SIG_DFL with a sigaction install.
	has_sadfl=$(grep -E 'sa_handler[[:space:]]*=[[:space:]]*SIG_DFL' "$srcfile" 2>/dev/null | head -1)
	[ -z "$has_sadfl" ] && continue
	has_sainstall=$(grep -E 'sigaction[[:space:]]*\(SIG' "$srcfile" 2>/dev/null | head -1)
	[ -z "$has_sainstall" ] && continue

	# For each sa_handler=SIG_DFL line test for raise() within 2 lines.
	while IFS=: read -r lineno content; do
		trimmed=$(printf '%s' "$content" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
		case "$trimmed" in
			\**) continue ;; /\**) continue ;; //*) continue ;;
		esac

		end_line=$((lineno + 2))
		has_raise=$(awk -v start="$lineno" -v end="$end_line" '
			NR >= start && NR <= end && /raise[[:space:]]*\(/ { print; exit }
		' "$srcfile")
		[ -z "$has_raise" ] && continue

		hash=$(printf '%s' "$trimmed" | sha256sum | cut -c1-8)
		key="${srcfile#./}:$lineno:$hash"

		if [ "${allowlist[$key]+set}" ]; then
			allowlist_matched[$key]=1
			continue
		fi

		echo "FAIL: $NAME: check1b: $key: sa_handler=SIG_DFL+sigaction+raise() drops fault beacon"
		fail_count=$((fail_count + 1))
	done < <(grep -En 'sa_handler[[:space:]]*=[[:space:]]*SIG_DFL' "$srcfile" 2>/dev/null)
done < <(find . -name '*.c' -type f \
	-not -path './health/*' \
	-not -path './scripts/check-static/*' \
	| sort)

# ---------------------------------------------------------------------------
# Check 2: sigaction(SIGSEGV/SIGBUS) install without canonical-capture proof.
# Exclude health/ (it owns the canonical disposition).
# ---------------------------------------------------------------------------
while IFS= read -r srcfile; do
	# Collect install lines: sigaction(SIGSEGV/SIGBUS, non-NULL-second-arg, …)
	# Match second arg starting with & or a lowercase identifier (not NULL).
	mapfile -t install_matches < <(
		grep -En 'sigaction[[:space:]]*\(SIG(SEGV|BUS)[[:space:]]*,[[:space:]]*(&|[a-z_])' \
			"$srcfile" 2>/dev/null
	)
	[ "${#install_matches[@]}" -eq 0 ] && continue

	# Does the file have a canonical-read call: sigaction(SIG(SEGV|BUS), NULL, &…)?
	# Proof is file-scoped — per-function scoping (ensuring the read precedes
	# the install in the same function) is a harder follow-up left for a
	# future audit pass.
	has_capture=$(grep -E \
		'sigaction[[:space:]]*\(SIG(SEGV|BUS)[[:space:]]*,[[:space:]]*NULL[[:space:]]*,' \
		"$srcfile" 2>/dev/null | head -1)

	# If proof is present the file satisfies the invariant.
	# Still walk the allowlist for this file so those entries get marked
	# matched — without this, a file that gains proof coverage would cause
	# every allowlist entry pointing into it to be reported as dead.
	if [ -n "$has_capture" ]; then
		for match in "${install_matches[@]}"; do
			lineno="${match%%:*}"
			content="${match#*:}"
			trimmed=$(printf '%s' "$content" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
			case "$trimmed" in
				\**) continue ;; /\**) continue ;; //*) continue ;;
			esac
			hash=$(printf '%s' "$trimmed" | sha256sum | cut -c1-8)
			key="${srcfile#./}:$lineno:$hash"
			if [ "${allowlist[$key]+set}" ]; then
				allowlist_matched[$key]=1
			fi
		done
		continue
	fi

	# Flag each install line individually (so allowlist entries are site-specific).
	for match in "${install_matches[@]}"; do
		lineno="${match%%:*}"
		content="${match#*:}"
		trimmed=$(printf '%s' "$content" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

		case "$trimmed" in
			\**) continue ;; /\**) continue ;; //*) continue ;;
		esac

		hash=$(printf '%s' "$trimmed" | sha256sum | cut -c1-8)
		key="${srcfile#./}:$lineno:$hash"

		if [ "${allowlist[$key]+set}" ]; then
			allowlist_matched[$key]=1
			continue
		fi

		echo "FAIL: $NAME: check2: $key: sigaction(SIGSEGV/SIGBUS) install without canonical-snapshot proof"
		fail_count=$((fail_count + 1))
	done
done < <(find . -name '*.c' -type f -not -path './health/*' | sort)

# ---------------------------------------------------------------------------
# Dead-allowlist check.
# ---------------------------------------------------------------------------
dead_count=0
for _k in "${!allowlist[@]}"; do
	if [ -z "${allowlist_matched[$_k]+x}" ]; then
		echo "DEAD ALLOWLIST ENTRY: $_k" >&2
		dead_count=$((dead_count + 1))
	fi
done
if [ "$dead_count" -gt 0 ]; then
	{
		echo "  $NAME: $dead_count dead allowlist entry/entries (never matched by scanner)"
		echo "  The file:line:hash key did not match: line number changed, site text"
		echo "  changed, or the site was removed; or the file now contains a"
		echo "  canonical-capture proof (sigaction(SIG(SEGV|BUS), NULL, &…))"
		echo "  making the suppression unnecessary.  If the"
		echo "  site is now compliant and no longer needs suppression, delete"
		echo "  the entry.  Otherwise re-derive the correct key or remove the"
		echo "  stale entry from:"
		echo "    scripts/check-static/signal-disposition-ownership.allowlist"
	} >&2
	echo "FAIL: $NAME: $dead_count dead allowlist entry/entries"
	exit 1
fi

if [ "$fail_count" -gt 0 ]; then
	{
		echo "  $NAME: check1/check1b flags signal/sigaction(SIG_DFL)+raise() outside health/:"
		echo "    that pattern resets disposition before delivery, silently"
		echo "    bypassing the fault beacon.  Restore the beacon protocol or"
		echo "    move the re-raise into health/.  Cross-function reset-then-raise"
		echo "    is out of scope (2-line window); see allowlist for pre-emptive"
		echo "    exemptions already reviewed."
		echo "  $NAME: check2 flags sigaction(SIGSEGV/SIGBUS) installs that lack"
		echo "    a canonical-read call (sigaction(SIG(SEGV|BUS), NULL, &saved))."
		echo "    Without the canonical snapshot the restore chain may chain to"
		echo "    stale state left behind by a leaked uffd worker.  Add the"
		echo "    snapshot or add the site to the allowlist with a rationale comment."
	} >&2
	exit 1
fi

echo "PASS: $NAME: 0 findings (check1/1b: SIG_DFL+raise beacon-drop; check2: sigaction ownership)"
exit 0
