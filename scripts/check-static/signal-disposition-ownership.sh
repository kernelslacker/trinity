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
#
# Check 2 — sigaction disposition ownership (canonical-snapshot invariant)
# ------------------------------------------------------------------------
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
#       sigaction(SIG…, NULL, &…)        (read-current-disposition call)
#     OR a saved-disposition variable name ending in _sa_bus or _sa_segv
#     (which implies the file participates in the canonical snapshot
#     protocol already reviewed during the initial audit).
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

		# Check if raise( appears within 2 lines following this signal call.
		end_line=$((lineno + 2))
		has_raise=$(awk -v start="$lineno" -v end="$end_line" '
			NR > start && NR <= end && /raise[[:space:]]*\(/ { print; exit }
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

	# Does the file have a canonical-read call: sigaction(SIG*, NULL, &…)?
	has_capture=$(grep -E \
		'sigaction[[:space:]]*\([A-Z_]+[[:space:]]*,[[:space:]]*NULL[[:space:]]*,' \
		"$srcfile" 2>/dev/null | head -1)

	# Does the file reference a saved-disposition variable (_sa_bus / _sa_segv)?
	has_saved_var=$(grep -E '(_sa_bus\b|_sa_segv\b)' "$srcfile" 2>/dev/null | head -1)

	# If either proof is present the file satisfies the invariant.
	if [ -n "$has_capture" ] || [ -n "$has_saved_var" ]; then continue; fi

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
		echo "  changed, or the site was removed.  Re-derive the correct key or"
		echo "  remove the stale entry from:"
		echo "    scripts/check-static/signal-disposition-ownership.allowlist"
	} >&2
	echo "FAIL: $NAME: $dead_count dead allowlist entry/entries"
	exit 1
fi

if [ "$fail_count" -gt 0 ]; then
	{
		echo "  $NAME: check1 flags signal(SIG_DFL)+raise() outside health/:"
		echo "    that pattern resets disposition before delivery, silently"
		echo "    bypassing the fault beacon.  Restore the beacon protocol or"
		echo "    move the re-raise into health/."
		echo "  $NAME: check2 flags sigaction(SIGSEGV/SIGBUS) installs that lack"
		echo "    a canonical-read call (sigaction(SIG, NULL, &saved)) or a"
		echo "    saved-disposition variable (_sa_bus / _sa_segv).  Without the"
		echo "    canonical snapshot the restore chain may chain to stale state"
		echo "    left behind by a leaked uffd worker.  Add the snapshot or"
		echo "    add the site to the allowlist with a rationale comment."
	} >&2
	exit 1
fi

echo "PASS: $NAME: 0 findings (check1: SIG_DFL+raise beacon-drop; check2: sigaction ownership)"
exit 0
