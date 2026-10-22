#!/bin/bash
#
# check-reexec-coverage: every struct syscallentry in syscalls/ that has a
# .sanitise must record what the CMP RedQueen re-exec step does with it.
#
# redqueen_reexec_step() skips a sanitise-bearing entry unless it opts back
# in, and counts the skip in reexec_skipped_destructive without a reason.
# A new sanitiser therefore drops out of re-exec by default and nothing
# says anyone decided that.  Each sanitise-bearing entry must carry one of
#   (a) REEXEC_SANITISE_OK in its flags: every arm is safe to replay;
#   (b) a "Not REEXEC_SANITISE_OK: <reason>" comment inside the entry;
#   (c) AVOID_REEXEC in its flags: never replay it;
#   (d) a line in check-reexec-coverage.baseline: the sanitiser opts in per
#       call with rec->flags |= REEXEC_OK, for the arms that qualify.
# (a) and (c) have to be code; naming a flag in a comment does not count.
# (b) needs its reason on the same line.  The baseline lists <file>:<entry>
# pairs, each followed by why it is dynamic, and must only shrink: a line
# fails once its entry gains (a), (b) or (c) or its file stops publishing
# REEXEC_OK.
#
# The scan is textual: an entry starts at a column-0 "struct syscallentry
# <name> =" and ends at the next column-0 "};".  It fails closed if it
# loses sync (an entry that never ends, a .sanitise outside any entry) or
# finds too few entries to be reading the tree.

set -u

NAME="check-reexec-coverage"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BASELINE_REL="scripts/check-static/check-reexec-coverage.baseline"

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

# Far below the real count (~330) so ordinary churn never trips it: fewer
# entries than this means the scan is not reading the tree.
MIN_ENTRIES=250

# scan_tree DIR
#
# Print "E <file> <entry> <class>" for each entry under DIR/syscalls that has
# a .sanitise, with class flag, avoid, rejected or none (first match wins).
# Print "O <file>:<line>" for a .sanitise outside any entry and
# "U <file> <entry>" for an entry whose end was never found.
scan_tree() {
	local root="$1"

	# shellcheck disable=SC2016
	find "$root/syscalls" -name '*.c' -print | LC_ALL=C sort | \
	xargs -r awk -v root="$root/" '
	# One line without its comments.  in_block carries a /* */ across
	# lines; a quoted string is copied through whole, so a "/*" inside
	# one opens nothing.  The fast path keeps the 66k-line scan cheap.
	function code_of(s,    out, i, n, c, two, q) {
		if (!in_block && index(s, "/") == 0)
			return s
		out = ""
		n = length(s)
		i = 1
		while (i <= n) {
			c = substr(s, i, 1)
			two = substr(s, i, 2)
			if (in_block) {
				if (two == "*/") { in_block = 0; i += 2 } else i++
			} else if (two == "/*") {
				in_block = 1; i += 2
			} else if (two == "//") {
				break
			} else if (c == "\"" || c == "\047") {
				q = c
				out = out c; i++
				while (i <= n) {
					c = substr(s, i, 1)
					out = out c; i++
					if (c == "\\") { out = out substr(s, i, 1); i++ }
					else if (c == q) break
				}
			} else {
				out = out c; i++
			}
		}
		return out
	}
	function unterminated() {
		if (in_struct)
			print "U", file, name
		in_struct = 0
	}
	FNR == 1 {
		unterminated()
		in_block = 0
		file = substr(FILENAME, length(root) + 1)
	}
	{
		raw = $0
		code = code_of(raw)
	}
	code ~ /^struct syscallentry [A-Za-z0-9_]+[[:space:]]*=/ {
		unterminated()
		name = code
		sub(/^struct syscallentry /, "", name)
		sub(/[[:space:]]*=.*$/, "", name)
		in_struct = 1
		sanitise = flag = avoid = rejected = 0
		next
	}
	in_struct {
		if (code ~ /\.sanitise[[:space:]]*=/)
			sanitise = 1
		if (code ~ /(^|[^A-Za-z0-9_])REEXEC_SANITISE_OK([^A-Za-z0-9_]|$)/)
			flag = 1
		if (code ~ /(^|[^A-Za-z0-9_])AVOID_REEXEC([^A-Za-z0-9_]|$)/)
			avoid = 1
		if (raw ~ /Not REEXEC_SANITISE_OK(:| because)[[:space:]]*[^[:space:]*\/]/ &&
		    code !~ /Not REEXEC_SANITISE_OK/)
			rejected = 1
		if (code ~ /^};/) {
			if (sanitise)
				print "E", file, name,
				      (flag ? "flag" : avoid ? "avoid" : rejected ? "rejected" : "none")
			in_struct = 0
		}
		next
	}
	code ~ /\.sanitise[[:space:]]*=/ {
		print "O", file ":" FNR
	}
	END {
		unterminated()
	}
	'
}

# verdict ROOT SCAN BASELINE
#
# Check SCAN (scan_tree output for ROOT) against the baseline file BASELINE.
# Print each failure on stderr and count it in n_sync, n_gap or n_base;
# succeed only if there are none.
verdict() {
	local root="$1" scan="$2" baseline="$3"
	local kind file entry cls key
	local -A listed=() gap=() class=()

	n_sync=0 n_gap=0 n_base=0

	if [ -r "$baseline" ]; then
		while IFS= read -r key; do
			listed["$key"]=1
		done < <(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' -e '/^$/d' "$baseline")
	fi

	while read -r kind file entry cls; do
		[ "$kind" = E ] || continue
		class["$file:$entry"]="$cls"
		[ "$cls" = none ] && gap["$file:$entry"]=1
	done <<< "$scan"

	if grep -q '^[OU] ' <<< "$scan"; then
		{
			echo "  the scan lost sync with the source:"
			grep '^[OU] ' <<< "$scan" | sed \
				-e 's/^O /    .sanitise outside any struct syscallentry: /' \
				-e 's/^U /    struct syscallentry never closed by a column-0 "};": /'
		} >&2
		n_sync=1
	fi

	while IFS= read -r key; do
		[ -z "$key" ] || [ -n "${listed[$key]+x}" ] && continue
		[ "$n_gap" = 0 ] && echo "  sanitise-bearing entries with no re-exec annotation:" >&2
		echo "    $key" >&2
		n_gap=$((n_gap + 1))
	done < <(printf '%s\n' "${!gap[@]}" | LC_ALL=C sort)
	if [ "$n_gap" -gt 0 ]; then
		cat >&2 <<-'EOF'
		  Say what the re-exec step does with each one.  Choose one:
		    (a) add REEXEC_SANITISE_OK to .flags if every arm of the sanitiser is
		        safe to replay (see the contract above REEXEC_SANITISE_OK in
		        include/syscall.h);
		    (b) add "/* Not REEXEC_SANITISE_OK: <reason> */" inside the entry;
		    (c) add AVOID_REEXEC to .flags if it must never be replayed;
		    (d) if the sanitiser sets rec->flags |= REEXEC_OK on the arms that
		        qualify, list the entry in
		        scripts/check-static/check-reexec-coverage.baseline with the reason.
		EOF
	fi

	# A baseline line must still be true: the entry is bare and its file
	# sets REEXEC_OK on a flags word in code, not just in a comment.
	while IFS= read -r key; do
		[ -n "$key" ] || continue
		file="${key%%:*}"
		if [ -z "${class[$key]+x}" ]; then
			echo "  baseline names $key, which is not a sanitise-bearing entry: drop the line" >&2
			n_base=$((n_base + 1))
		elif [ "${class[$key]}" != none ]; then
			echo "  baseline names $key, which now carries its own annotation (${class[$key]}): drop the line" >&2
			n_base=$((n_base + 1))
		elif ! strip_c_comments "$root/$file" |
		     grep -qE 'flags[[:space:]]*\|=[[:space:]]*REEXEC_OK([^A-Za-z0-9_]|$)'; then
			echo "  baseline names $key, but $file never sets REEXEC_OK on a flags word: annotate the entry or drop the line" >&2
			n_base=$((n_base + 1))
		fi
	done < <(printf '%s\n' "${!listed[@]}" | LC_ALL=C sort)

	[ $((n_sync + n_gap + n_base)) = 0 ]
}

# ---------------------------------------------------------------------------
# Self-test: both directions, on scratch trees.
#
# Every bad entry below must be reported and every good one must not.  The
# near misses are the cases a looser scan gets wrong: a flag named only in a
# comment, a rejection note with no reason, a .sanitise mentioned only in a
# comment, one entry's annotation leaking into the next, a flag split over
# two lines, and a "name= {" with no space.
# ---------------------------------------------------------------------------
selftest_dir="$(mktemp -d)" || { echo "FAIL: $NAME: mktemp failed"; exit 1; }
trap 'rm -rf "$selftest_dir"' EXIT

# plant NAME: write stdin to a scratch tree's syscalls/c.c, print its root.
plant() {
	mkdir -p "$selftest_dir/$1/syscalls"
	cat > "$selftest_dir/$1/syscalls/c.c"
	echo "$selftest_dir/$1"
}

scan_root="$(plant scan <<'EOF'
/*
 * .sanitise = is described here and is not an assignment.
 */
struct syscallentry syscall_flagged = {
	.flags = NEED_ALARM |
		 REEXEC_SANITISE_OK,
	.sanitise = sanitise_x,
};

struct syscallentry syscall_avoid = {
	.sanitise = sanitise_x,
	.flags = AVOID_REEXEC,
};

struct syscallentry syscall_rejected = {
	/* Not REEXEC_SANITISE_OK: a replay would open a second fd. */
	.sanitise = sanitise_x,
};

struct syscallentry syscall_bare = {
	.sanitise = sanitise_x,
};

struct syscallentry syscall_mention = {
	/* TODO: REEXEC_SANITISE_OK or AVOID_REEXEC once audited */
	.sanitise = sanitise_x,
};

struct syscallentry syscall_noreason = {
	/* Not REEXEC_SANITISE_OK: */
	.sanitise = sanitise_x,
};

struct syscallentry syscall_nosanitise = {
	/* .sanitise = would go here */
	.name = "nosanitise",
};

struct syscallentry syscall_spaced= {
	.sanitise = sanitise_x,
};

static struct syscallentry syscall_hidden = {
	.sanitise = sanitise_x,
};

struct syscallentry syscall_open = {
	.name = "open",
EOF
)"
expect="E syscalls/c.c syscall_flagged flag
E syscalls/c.c syscall_avoid avoid
E syscalls/c.c syscall_rejected rejected
E syscalls/c.c syscall_bare none
E syscalls/c.c syscall_mention none
E syscalls/c.c syscall_noreason none
E syscalls/c.c syscall_spaced none
O syscalls/c.c:44
U syscalls/c.c syscall_open"
got="$(scan_tree "$scan_root")"
if [ "$got" != "$expect" ]; then
	{
		echo "  $NAME: self-test FAILED -- the scan of the planted tree is wrong."
		echo "  a clean run of this check would be meaningless.  Expected:"
		printf '%s\n' "$expect" | sed 's/^/    /'
		echo "  Got:"
		printf '%s\n' "$got" | sed 's/^/    /'
	} >&2
	echo "FAIL: $NAME: self-test: planted tree scanned wrongly"
	exit 1
fi

# The baseline half.  A listed entry is accepted only while it is bare and
# its file really sets REEXEC_OK; a bare entry nobody listed is refused.
dyn_root="$(plant dyn <<'EOF'
struct syscallentry syscall_dynamic = {
	.sanitise = sanitise_x,
};
static void sanitise_x(struct syscallrecord *rec)
{
	rec->flags |= REEXEC_OK;
}
EOF
)"
dyn_scan="$(scan_tree "$dyn_root")"
flagged_root="$(plant flagged <<'EOF'
struct syscallentry syscall_dynamic = {
	.flags = REEXEC_SANITISE_OK,
	.sanitise = sanitise_x,
};
static void sanitise_x(struct syscallrecord *rec)
{
	rec->flags |= REEXEC_OK;
}
EOF
)"
flagged_scan="$(scan_tree "$flagged_root")"
silent_root="$(plant silent <<'EOF'
/* rec->flags |= REEXEC_OK would go here */
struct syscallentry syscall_dynamic = {
	.sanitise = sanitise_x,
};
EOF
)"
silent_scan="$(scan_tree "$silent_root")"

# accepts ROOT SCAN BASELINE-TEXT: succeed if the verdict is clean.
accepts() {
	printf '%s\n' "$3" > "$selftest_dir/baseline"
	verdict "$1" "$2" "$selftest_dir/baseline" 2> /dev/null
}
dyn_line="syscalls/c.c:syscall_dynamic  # sets REEXEC_OK on the qualifying arms"
if ! accepts "$dyn_root" "$dyn_scan" "$dyn_line" ||
   accepts "$dyn_root" "$dyn_scan" "" ||
   accepts "$dyn_root" "$dyn_scan" "$dyn_line
syscalls/c.c:syscall_gone" ||
   accepts "$flagged_root" "$flagged_scan" "$dyn_line" ||
   accepts "$silent_root" "$silent_scan" "$dyn_line"; then
	echo "FAIL: $NAME: self-test: baseline verdict wrong (took a bad baseline, or refused a good one)"
	exit 1
fi

# ---------------------------------------------------------------------------
# Real run.
# ---------------------------------------------------------------------------
scan="$(scan_tree "$ROOT")"

total="$(grep -c '^E ' <<< "$scan")"
if [ "$total" -lt "$MIN_ENTRIES" ]; then
	echo "  $NAME: only $total sanitise-bearing entries found, expected >= $MIN_ENTRIES." >&2
	echo "  the scan is not reading the tree." >&2
	echo "FAIL: $NAME: entry floor: $total < $MIN_ENTRIES"
	exit 1
fi

if ! verdict "$ROOT" "$scan" "$ROOT/$BASELINE_REL"; then
	echo "FAIL: $NAME: $n_gap entry/entries with no re-exec annotation, $n_base bad baseline line(s), scan out of sync: $n_sync"
	exit 1
fi

count() { grep -c "^E .* $1\$" <<< "$scan"; }
echo "PASS: $NAME: $total sanitise-bearing entries: $(count flag) flagged, $(count avoid) avoid, $(count rejected) rejected, $(count none) baselined dynamic"
exit 0
