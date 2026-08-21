#!/bin/bash
#
# childop-direct-syscall-uncounted: every childop translation unit that
# issues raw syscalls in its own body must call childop_direct_syscalls_add()
# so the direct-syscall telemetry counter stays accurate.
#
# Background: Trinity's per-child syscall accounting has two layers.
#   1. The random_syscall path (child.c) counts every dispatched syscall
#      via the shm->stats.childop.direct_syscalls[op] array, published by
#      child-altop-score.c at the end of each iteration.
#   2. Childops that issue raw syscalls in their own body (socket(),
#      sendmsg(), trinity_raw_syscall(), etc.) must additionally call
#      childop_direct_syscalls_add(op, n) so those calls appear in the
#      same accounting bucket.  The netlink transport (childops-netlink.h)
#      calls childop_direct_syscalls_add() internally at nl_close() for
#      the netlink path, but own-body calls outside the nl_* transport
#      still need a manual publish.
#
# -----------------------------------------------------------------------
# Bucket definition: what belongs in the direct-syscall tally
# -----------------------------------------------------------------------
#
# The direct-syscall bucket counts syscalls that:
#   (a) are issued directly in the childop body (or a local non-netlink
#       wrapper function called exclusively from that body), AND
#   (b) represent fuzz surface the childop is exercising as its primary
#       job -- i.e. the kernel interfaces being explored by the op.
#
# Three categories are explicitly OUT of the bucket:
#
#   1. Teardown / cleanup close() calls (and similar fd-release calls on
#      error paths).  Convention: the dispatch surface ends at the last
#      meaningful kernel interaction; resource teardown is infrastructure.
#      No childop in the tree counts cleanup close() calls.  The one
#      exception (sockmap-cork-race.c) counts close() only in a setup
#      helper where the socket pair creation is itself the fuzz surface;
#      both forms pass because the gate tests only for a non-negative gap,
#      not for an exact match.  The safe rule for new ops: do NOT count
#      close() on the error / cleanup path.
#
#   2. Harness-handshake syscalls (pipe/read/write used only to sequence
#      workers between the fork parent and child, or to synchronise
#      cooperating child threads before the actual work begins).  These
#      are synchronisation infrastructure, not kernel interfaces being
#      fuzzed.  They must not appear in the fuzz-surface tally.
#
#   3. Netlink-proxied syscalls routed through the nl_* transport
#      (nl_open / nl_send_recv / nl_close with a valid caller_op).
#      nl_close() calls childop_direct_syscalls_add() internally on
#      behalf of those calls; counting them again in the childop body
#      would double-count them in the telemetry.  If a childop uses
#      ONLY the nl_* path (no own-body socket/sendmsg/etc.), it needs
#      no manual publish -- but it should be grandfathered in the
#      baseline until confirmed; see the note on nl_*-routed files below.
#
# -----------------------------------------------------------------------
# Heuristic: for every childops/*.c (or subdirectory .c) file that does
# not contain a call to childop_direct_syscalls_add(), scan the
# comment-stripped code for raw-syscall invocations from the set:
#   trinity_raw_syscall, trinity_cmp_syscall,
#   socket, sendmsg, sendto, setsockopt, mmap, syscall
# Any such file is classified as an uncounted direct-syscall producer.
# Files in the baseline are grandfathered; anything not listed there
# fails the gate.
#
# Note on nl_*-routed files: childops that open a netlink context with a
# valid caller_op already have their netlink-path syscalls counted by
# nl_close() / childop_direct_syscalls_add().  However, many such files
# also carry own-body socket()/sendmsg()/etc. calls that are NOT proxied
# through the nl_* transport and therefore remain uncounted.  Rather than
# attempt to distinguish "netlink-proxied" from "own-body" calls
# statically (which would require call-graph analysis), this gate flags
# nl_*-routed files too.  Currently-existing nl_*-routed files that have
# not yet been separately wired are grandfathered in the baseline below;
# the baseline should shrink over time, never grow.  (Scoping decision
# for KC review: conservative inclusion — nl_*-routed files in baseline
# rather than nl_* exclusion in the predicate.)
#
# A baseline of grandfathered files lives alongside this script as
# childop-direct-syscall-uncounted.baseline (one relative path per line).
# The baseline should shrink over time, never grow.

set -u

NAME="childop-direct-syscall-uncounted"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/childop-direct-syscall-uncounted.baseline"
CHILDOPS_DIR="$ROOT/childops"

declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' "$BASELINE")
fi

RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE" 2>/dev/null' EXIT

# ---------------------------------------------------------------------------
# Self-test: drive the REAL scanner against fixture childops/ files laid out
# under a temporary REPO_ROOT.  Four fixtures exercise the pass-1 wrapper
# classifier; the live scanner is invoked for each assertion rather than a
# duplicate inline awk (which was testing a copy of the classifier, not the
# live code path -- divergence introduced by 6b635c147088 ("check-static:
# skip raw_* forward declarations in wrapper classifier"), anchoring
# fixed in the self-test copy by 6e04f6ea7550 ("check-static: anchor
# pass-1 wrapper self-count to atomic-arg member") but not the live block).
#
# Fixture A: raw_x prototype (static void raw_x(int);) must NOT register in
#   raw_wrapper_known.  A childop calling socket() must still be UNCOUNTED.
#
# Fixture B: raw_y definition with __atomic_add_fetch on ->member (anchored,
#   non-zero).  A childop calling only raw_y() must PASS (raw_y self=1
#   means fn_tally_count == fn_raw_sites for its callers).
#
# Fixture C: raw_z definition with __atomic_store_n storing 0 (a counter
#   reset, not an increment).  A childop calling only raw_z() must be
#   THREAD_UNCOUNTED -- the zero-store is rejected by the anchored pattern.
#
# Fixture D: raw_x prototype wrapped across two lines (raw_x(int a,\n    int b);)
#   must NOT register raw_x in raw_wrapper_known.  A worker thread calling
#   raw_x() must PASS (fn_raw_sites == 0, no spurious THREAD_UNCOUNTED).
# ---------------------------------------------------------------------------
# Recursion guard: skip the self-test when the script is called by its own
# sub-tests (which set REPO_ROOT to a temp dir for isolation).  Without this
# each sub-test invocation would re-enter the self-test, creating a cascade
# that fails when the recursive child tries to load the script from the
# temp dir's scripts/check-static/ (which does not exist there).
if [ -z "${_CSC_SELFTEST_RECURSE:-}" ]; then
# Resolve the script's real path before any REPO_ROOT manipulation so the
# sub-test invocations always find the correct file.
_st_self="$(readlink -f "$0")"
_st_root="$(mktemp -d /tmp/csc-selftest-root.XXXXXX)"
trap 'rm -f "$RESULTS_FILE" 2>/dev/null; [ -d "${_st_root:-}" ] && rm -rf "$_st_root" 2>/dev/null' EXIT
mkdir -p "$_st_root/childops" "$_st_root/scripts/check-static"
# Empty baseline; count ceiling large enough not to interfere with sub-tests.
> "$_st_root/scripts/check-static/$NAME.baseline"
echo "99" > "$_st_root/scripts/check-static/$NAME.count.baseline"
# .prev must match the ceiling so the ratchet guard does not misfire.
echo "99" > "$_st_root/scripts/check-static/$NAME.count.baseline.prev"

# Fixture A: prototype raw_x must not register as self-counting.
# A childop that calls socket() should still be flagged UNCOUNTED.
cat > "$_st_root/childops/st_raw_x_proto.c" <<'__FIXTURE_A__'
static void raw_x(int);

static int do_other(struct rs *rs)
{
	__atomic_add_fetch(&rs->direct_syscalls, 1, __ATOMIC_RELAXED);
	return 0;
}

bool st_childop_raw_x(struct childdata *child)
{
	socket(AF_INET, SOCK_STREAM, 0);
	return true;
}
__FIXTURE_A__

# Fixture B: raw_y with atomic add_fetch on ->member is self-counting.
# Calling raw_y() from a childop entry must satisfy fn_tally_count == fn_raw_sites.
cat > "$_st_root/childops/st_raw_y_def.c" <<'__FIXTURE_B__'
static void raw_y(int a)
{
	__atomic_add_fetch(&rs->direct_syscalls, 1, __ATOMIC_RELAXED);
}

bool st_childop_raw_y(struct childdata *child)
{
	raw_y(1);
	return true;
}
__FIXTURE_B__

# Fixture C: raw_z zero-store must NOT be classified as self-counting.
# Calling raw_z() from a childop entry must still produce THREAD_UNCOUNTED.
cat > "$_st_root/childops/st_raw_z_storen.c" <<'__FIXTURE_C__'
static void raw_z(struct rs *rs)
{
	__atomic_store_n(&rs->thread_tally, 0, __ATOMIC_RELEASE);
}

bool st_childop_raw_z(struct childdata *child)
{
	raw_z(NULL);
	return true;
}
__FIXTURE_C__

# Fixture D: wrapped raw_x prototype (split across two lines) must NOT
# register raw_x in raw_wrapper_known.  A worker thread calling raw_x()
# must PASS (fn_raw_sites == 0 because raw_x is absent from the wrapper
# map), not be THREAD_UNCOUNTED as the buggy single-line guard would
# cause by promoting raw_x via the following do_other body.
cat > "$_st_root/childops/st_raw_x_wrapped_proto.c" <<'__FIXTURE_D__'
static void raw_x(int a,
    int b);

static int do_other(void)
{
	return 0;
}

static void *proto_thread_worker(void *arg)
{
	raw_x(1, 2);
	return NULL;
}

bool st_childop_raw_x_wrapped(struct childdata *child)
{
	return true;
}
__FIXTURE_D__

# Baseline keys for fixture A findings (used to isolate sub-tests B, C, D).
_st_bl_a='UNCOUNTED:childops/st_raw_x_proto.c
THREAD_UNCOUNTED:childops/st_raw_x_proto.c#st_childop_raw_x'
# Baseline key for fixture C finding (used to isolate sub-tests B and D).
_st_bl_c='THREAD_UNCOUNTED:childops/st_raw_z_storen.c#st_childop_raw_z'

# Sub-test A: fixture_a must be UNCOUNTED (socket uncounted, raw_x not wired).
> "$_st_root/scripts/check-static/$NAME.baseline"
_st_out_a=$(REPO_ROOT="$_st_root" _CSC_SELFTEST_RECURSE=1 bash "$_st_self" 2>&1)
_st_rc_a=$?
if [ $_st_rc_a -eq 0 ]; then
	echo "FAIL: $NAME selftest A: expected UNCOUNTED for raw_x-proto childop (got PASS; output: $_st_out_a)" >&2
	exit 1
fi
if ! echo "$_st_out_a" | grep -q 'st_raw_x_proto'; then
	echo "FAIL: $NAME selftest A: st_raw_x_proto.c not flagged (output: $_st_out_a)" >&2
	exit 1
fi

# Sub-test B: fixture_b must PASS (raw_y self=1); baseline A and C findings.
printf '%s\n%s\n' "$_st_bl_a" "$_st_bl_c" \
	> "$_st_root/scripts/check-static/$NAME.baseline"
_st_out_b=$(REPO_ROOT="$_st_root" _CSC_SELFTEST_RECURSE=1 bash "$_st_self" 2>&1)
_st_rc_b=$?
if [ $_st_rc_b -ne 0 ]; then
	echo "FAIL: $NAME selftest B: raw_y should be self-counting (exit=$_st_rc_b; output: $_st_out_b)" >&2
	exit 1
fi
if echo "$_st_out_b" | grep -q 'st_raw_y'; then
	echo "FAIL: $NAME selftest B: raw_y childop wrongly flagged as uncounted (output: $_st_out_b)" >&2
	exit 1
fi

# Sub-test C: fixture_c must be THREAD_UNCOUNTED (zero-store rejected); baseline A only.
printf '%s\n' "$_st_bl_a" \
	> "$_st_root/scripts/check-static/$NAME.baseline"
_st_out_c=$(REPO_ROOT="$_st_root" _CSC_SELFTEST_RECURSE=1 bash "$_st_self" 2>&1)
_st_rc_c=$?
if [ $_st_rc_c -eq 0 ]; then
	echo "FAIL: $NAME selftest C: zero-store raw_z must be rejected (expected THREAD_UNCOUNTED, got PASS; output: $_st_out_c)" >&2
	exit 1
fi
if ! echo "$_st_out_c" | grep -q 'st_raw_z_storen'; then
	echo "FAIL: $NAME selftest C: st_raw_z_storen.c not flagged (output: $_st_out_c)" >&2
	exit 1
fi
# Sub-test D: fixture_d must PASS — wrapped raw_x prototype must not register
# in raw_wrapper_known, so raw_x_wrapped_worker calling raw_x() produces no
# THREAD_UNCOUNTED finding.  Baseline A and C findings to isolate D.
printf '%s\n%s\n' "$_st_bl_a" "$_st_bl_c" \
	> "$_st_root/scripts/check-static/$NAME.baseline"
_st_out_d=$(REPO_ROOT="$_st_root" _CSC_SELFTEST_RECURSE=1 bash "$_st_self" 2>&1)
_st_rc_d=$?
if [ $_st_rc_d -ne 0 ]; then
	echo "FAIL: $NAME selftest D: wrapped raw_x proto must not produce THREAD_UNCOUNTED (exit=$_st_rc_d; output: $_st_out_d)" >&2
	exit 1
fi
if echo "$_st_out_d" | grep -q 'st_raw_x_wrapped_proto'; then
	echo "FAIL: $NAME selftest D: st_raw_x_wrapped_proto.c wrongly flagged (output: $_st_out_d)" >&2
	exit 1
fi
> "$_st_root/scripts/check-static/$NAME.baseline"
fi # end _CSC_SELFTEST_RECURSE guard

# Walk every .c file under childops/.  For each file that has no
# childop_direct_syscalls_add() call in its own body (comment-stripped),
# scan for raw-syscall invocations.  A non-zero count means the file
# issues syscalls that are not reported into the direct-syscall telemetry
# bucket.
#
# Second pass: even for wired files, scan worker function bodies.
# Two worker shapes are detected:
#
#   Pthread workers (static void * return): reported as THREAD_UNCOUNTED.
#   Fork workers (static void return, or __attribute__((noreturn)) static void):
#     reported as FORK_UNCOUNTED.  The function is classified as a fork-child
#     body when ANY of the following terminators appears inside it (any one is
#     sufficient; _exit() alone is too narrow -- some workers use raw syscalls
#     or the POSIX _Exit() form):
#       _exit(              -- traditional POSIX
#       _Exit(              -- POSIX capital-E form (C99/C11)
#       syscall(__NR_exit   -- raw kernel exit via glibc syscall()
#       trinity_raw_syscall(__NR_exit  -- raw exit via trinity's wrapper
#       syscall(__NR_exit_group       -- exit_group raw form
#       trinity_raw_syscall(__NR_exit_group
#       __attribute__.*noreturn        -- function is noreturn (unconditional)
#     Concrete motivating case: af_unix_sibling_main() in
#     childops/net/af-unix-scm-rights-gc.c terminates via
#     syscall(__NR_exit, 0) with no bare _exit() token in the file.
#
# A worker is flagged only when it both (a) has raw-syscall sites and
# (b) does not accumulate those syscalls back via a struct member whose
# name contains "syscall", "tally", or "count" accessed through ->.
# The worker raw-syscall set is broader than the main-body set: it
# includes close, open, recv, send, read, and write in addition to
# the standard set.
#
# FORK_UNCOUNTED entries are buffered and emitted only for wired files
# (where the file-level UNCOUNTED check would otherwise pass silently);
# for unwired files the file-level UNCOUNTED entry covers fork workers.
while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"

	awk -v file="$rel" '
	# Reset block-comment state at each file boundary (two-pass mode).
	FNR == 1 { in_block = 0 }
	# -------------------------------------------------------------------
	# FIRST PASS: build a map of file-local raw_* wrapper functions and
	# classify each as self-counting (wrapper body bumps direct_calls tally
	# via childop_direct_syscalls_add or ->...count/tally/syscall) or not.
	# A per-function worker-body scan in the second pass uses this map to
	# credit fn_raw_sites for every call to a known raw_* wrapper, and
	# fn_tally_count only when that wrapper is itself self-counting.
	# -------------------------------------------------------------------
	FNR == NR {
		code = strip_comments($0)
		# Detect: static <type> raw_NAME(
		# A true word boundary before raw_ is enforced by requiring that the
		# character immediately preceding raw_ is not [a-zA-Z0-9_], matching
		# the same guard used by the call-site scanner at the second pass.
		# Prototype exclusion uses statement-level accumulation to handle
		# both single-line (static void raw_x(int);) and wrapped declarations
		# split across multiple lines (e.g. raw_x(int a,\n    int b);).
		# raw_fn_pending tracks paren depth across continuation lines; only
		# when { is reached at paren-depth 0 does in_raw_fn become 1.
		# The old single-line ); guard is replaced by this accumulation.

		# Handle continuation lines of a pending multi-line raw_* signature.
		if (raw_fn_pending) {
			if (match(code, /static[[:space:]]+[a-zA-Z_][a-zA-Z0-9_*[:space:]]*[^a-zA-Z0-9_]raw_[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(/)) {
				# New raw_* signature line — reset pending and fall through.
				raw_fn_pending = 0
			} else {
				_n = length(code); _done = 0
				for (_j = 1; _j <= _n && !_done; _j++) {
					_c = substr(code, _j, 1)
					if      (_c == "(") raw_fn_pending_depth++
					else if (_c == ")") raw_fn_pending_depth--
					else if (_c == ";" && raw_fn_pending_depth == 0) {
						# Statement ends with ; — prototype, discard.
						raw_fn_pending = 0; _done = 1
					} else if (_c == "{" && raw_fn_pending_depth == 0) {
						# Definition body begins — promote to in_raw_fn.
						cur_raw_fn_name = raw_fn_pending_name
						in_raw_fn = 1
						raw_fn_brace_depth = 0
						raw_fn_brace_opened = 0
						raw_fn_self_counting = 0
						raw_fn_pending = 0; _done = 1
					}
				}
				if (raw_fn_pending) next
			}
		}
		if (!in_raw_fn && !raw_fn_pending &&
		    match(code, /static[[:space:]]+[a-zA-Z_][a-zA-Z0-9_*[:space:]]*[^a-zA-Z0-9_]raw_[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(/)) {
			tmp = substr(code, RSTART)
			if (match(tmp, /raw_[a-zA-Z_][a-zA-Z0-9_]*/)) {
				_pname = substr(tmp, RSTART, RLENGTH)
				if (index(code, "{") > 0) {
					# Definition with { on same line.
					cur_raw_fn_name = _pname
					in_raw_fn = 1
					raw_fn_brace_depth = 0
					raw_fn_brace_opened = 0
					raw_fn_self_counting = 0
				} else if (code ~ /\);[[:space:]]*$/) {
					# Single-line prototype — skip, no state change.
				} else {
					# Multi-line signature — enter pending state and
					# accumulate continuation lines until ; or {.
					raw_fn_pending = 1
					raw_fn_pending_name = _pname
					# Compute paren depth from the match position
					# (tmp begins at the raw_* definition start).
					raw_fn_pending_depth = 0
					_n = length(tmp)
					for (_j = 1; _j <= _n; _j++) {
						_c = substr(tmp, _j, 1)
						if      (_c == "(") raw_fn_pending_depth++
						else if (_c == ")") raw_fn_pending_depth--
					}
				}
			}
		}
		if (in_raw_fn) {
			# Self-counting check.
			if (index(code, "childop_direct_syscalls_add") > 0)
				raw_fn_self_counting = 1
			if (!raw_fn_self_counting) {
				# Require an actual increment or publish form, anchored
				# so the member appears INSIDE the atomic call arguments.
				# Two independent match() calls (one for the atomic op,
				# one for the ->member) are insufficient: a zero-store
				# __atomic_store_n(&rs->thread_tally, 0, __ATOMIC_RELEASE)
				# satisfies both separately despite storing 0 (a counter
				# reset, not an increment).  Use single-match anchored
				# patterns: for add_fetch/fetch_add require the member
				# inside the first arg; for store_n require the stored
				# value (second arg) to be non-zero.  Mirrors the
				# self-test classifier; live block diverged from the
				# self-test copy anchored by 6e04f6ea7550 ("check-static: anchor
				# pass-1 wrapper self-count to atomic-arg member").
				if (match(code, /__atomic_(add_fetch|fetch_add)[[:space:]]*\([[:space:]]*&[^,]*->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*/) ||
				    match(code, /__atomic_store_n[[:space:]]*\([^,]*->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*[^,]*,[[:space:]]*[^0 \t,]/) ||
				    match(code, /->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*[ \t]*(\+\+|\+=)/) ||
				    match(code, /\+\+[ \t]*[a-zA-Z_][a-zA-Z0-9_]*->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*/)) 
					raw_fn_self_counting = 1
			}
			# Track brace depth to find function body end.
			n = length(code)
			for (j = 1; j <= n; j++) {
				c = substr(code, j, 1)
				if (c == "{") {
					raw_fn_brace_depth++
					raw_fn_brace_opened = 1
				} else if (c == "}") {
					raw_fn_brace_depth--
					if (raw_fn_brace_opened && raw_fn_brace_depth == 0) {
						raw_wrapper_known[cur_raw_fn_name] = 1
						raw_wrapper_self_counting[cur_raw_fn_name] = raw_fn_self_counting
						in_raw_fn = 0
						cur_raw_fn_name = ""
						raw_fn_brace_opened = 0
					}
				}
			}
		}
		next
	}
	function strip_comments(s,    idx, tail, cidx) {
		# Continuation of a block comment from a previous line.
		if (in_block) {
			idx = index(s, "*/")
			if (idx == 0) return ""
			s = substr(s, idx + 2)
			in_block = 0
		}
		# Inline block comments on this line.
		while ((idx = index(s, "/*")) > 0) {
			tail = substr(s, idx + 2)
			cidx = index(tail, "*/")
			if (cidx == 0) {
				in_block = 1
				s = substr(s, 1, idx - 1)
				break
			}
			s = substr(s, 1, idx - 1) " " substr(tail, cidx + 2)
		}
		sub(/\/\/.*$/, "", s)
		return s
	}
	BEGIN {
		in_block = 0
		raw_sites = 0
		wired = 0
		in_fn = 0
		is_fork_fn = 0
		fork_fn_exit_seen = 0
		fork_fn_has_fork = 0
		brace_depth = 0
		fn_raw_sites = 0
		fn_tally_count = 0
		fn_name = ""
		fork_uncounted_n = 0
	}
	{
		code = strip_comments($0)
		# Correctly-wired check: the file calls
		# childop_direct_syscalls_add() in non-comment code.
		if (!wired && index(code, "childop_direct_syscalls_add") > 0)
			wired = 1
		scan = code
		# Raw-syscall site predicate: call to any of the
		# substantive syscall-invoking functions used in the
		# childops tree.  The word-boundary guard ([^a-zA-Z0-9_]
		# or start-of-code) prevents matching e.g.
		# "setsockopt_helper" or "nl_socket".  The trailing
		# [[:space:]]*\( anchors to a call site rather than a
		# declaration reference.
		while (match(scan,
		    /trinity_raw_syscall[[:space:]]*\(|trinity_cmp_syscall[[:space:]]*\(|(^|[^a-zA-Z0-9_])(socket|sendmsg|sendto|setsockopt|mmap|syscall)[[:space:]]*\(/)) {
			raw_sites++
			scan = substr(scan, RSTART + RLENGTH - 1)
		}

		# --- Worker function scans ---
		#
		# Pthread workers: static void * return.
		if (!in_fn && match(code,
		    /static[[:space:]]+void[[:space:]]*\*[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(/)) {
			in_fn = 1
			is_fork_fn = 0
			fork_fn_exit_seen = 0
			brace_depth = 0
			fn_raw_sites = 0
			fn_tally_count = 0
			delete fn_acc_incr
			# Extract the function name.
			tmp = substr(code, RSTART)
			sub(/static[[:space:]]+void[[:space:]]*\*[[:space:]]*/, "", tmp)
			match(tmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)
			fn_name = substr(tmp, RSTART, RLENGTH)
		}
		# Fork workers: static void return (not void *).  Three header shapes
		# are matched:
		#   (a) plain:    static void foo(
		#   (b) noreturn before: __attribute__((noreturn)) static void foo(
		#   (c) noreturn after:  static __attribute__((noreturn)) void foo(
		# The void[[:space:]]+ guard (at least one space, then a letter) is
		# mutually exclusive with void[[:space:]]*\* above: a void* return
		# always has * before the name.  When __attribute__((noreturn)) appears
		# on its own line before the static void line, shape (a) catches it on
		# the following line.
		if (!in_fn && match(code,
		    /(__attribute__[[:space:]]*\(\([^)]*noreturn[^)]*\)\)[[:space:]]+static[[:space:]]+void|static[[:space:]]+(__attribute__[[:space:]]*\(\([^)]*noreturn[^)]*\)\)[[:space:]]+)?void)[[:space:]]+[a-zA-Z][a-zA-Z0-9_]*[[:space:]]*\(/)) {
			in_fn = 1
			is_fork_fn = 1
			fork_fn_exit_seen = 0
			fork_fn_has_fork = 0
			brace_depth = 0
			fn_raw_sites = 0
			fn_tally_count = 0
			delete fn_acc_incr
			tmp = substr(code, RSTART)
			# Strip any leading __attribute__ and/or static void prefix
			# before extracting the function name.
			sub(/.*void[[:space:]]+/, "", tmp)
			match(tmp, /^[a-zA-Z][a-zA-Z0-9_]*/)
			fn_name = substr(tmp, RSTART, RLENGTH)
		}
		# Childop entry functions: bool NAME(struct childdata *child).
		# These are the primary per-childop entry points; they run in the
		# child context and must account for every raw syscall they issue.
		# No fork/exit detection is needed -- they return normally.
		# Exclude "static bool" helpers: a static qualifier means the
		# function is an internal helper (e.g. a sub-combo or probe
		# predicate), not a top-level childop entry point.
		if (!in_fn && match(code,
		    /bool[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([[:space:]]*struct[[:space:]]+childdata[[:space:]]*\*/)) {
			if (!(substr(code, 1, RSTART - 1) ~ /static[[:space:]]*$/)) {
			in_fn = 1
			is_fork_fn = 0
			brace_depth = 0
			fn_raw_sites = 0
			fn_tally_count = 0
			delete fn_acc_incr
			tmp = substr(code, RSTART)
			sub(/bool[[:space:]]+/, "", tmp)
			match(tmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)
			fn_name = substr(tmp, RSTART, RLENGTH)
			}
		}
		# Clone body (_in_ns pattern): static int NAME(void *arg).
		# Used for clone(2) grandchild bodies that must return int.  The
		# int return type excluded them from the void/void* patterns above
		# by construction; they are treated as thread workers here.
		if (!in_fn && match(code,
		    /static[[:space:]]+int[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([[:space:]]*void[[:space:]]*\*[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\)/)) {
			in_fn = 1
			is_fork_fn = 0
			brace_depth = 0
			fn_raw_sites = 0
			fn_tally_count = 0
			delete fn_acc_incr
			tmp = substr(code, RSTART)
			sub(/static[[:space:]]+int[[:space:]]+/, "", tmp)
			match(tmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)
			fn_name = substr(tmp, RSTART, RLENGTH)
		}

		if (in_fn) {
			# Track brace depth to find function body bounds.
			n = length(code)
			for (j = 1; j <= n; j++) {
				c = substr(code, j, 1)
				if (c == "{") brace_depth++
				else if (c == "}") {
					brace_depth--
					if (brace_depth == 0) {
						if (is_fork_fn) {
							# Fork worker: only flag if _exit() was
							# seen (confirms fork-child body) AND the
							# function does not call fork() itself
							# (which would make it a parent wrapper
							# with an inline child branch, not a pure
							# fork-child body).  Buffer for END.
							if (fork_fn_exit_seen && !fork_fn_has_fork && fn_raw_sites > 0 && fn_tally_count < fn_raw_sites)
								fork_uncounted[fork_uncounted_n++] = \
									"FORK_UNCOUNTED " file " fn=" fn_name " raw_sites=" fn_raw_sites
							is_fork_fn = 0
						} else {
							if (fn_raw_sites > 0 && fn_tally_count < fn_raw_sites)
								print "THREAD_UNCOUNTED " file " fn=" fn_name " raw_sites=" fn_raw_sites
						}
						in_fn = 0
						fn_name = ""
						delete fn_acc_incr
					}
				}
			}
			# Broader raw-syscall set for worker bodies: includes
			# close, open, recv, send, read, write in addition to
			# the standard set used for the file-level check.
			# Exclude fork-child terminators: syscall(__NR_exit[...]) forms
			# are the termination mechanism, not fuzzed-work syscalls that
			# belong in the direct-call tally.  Replace the syscall( token
			# before scanning so the pattern below cannot match it.
			tscan = code
			gsub(/syscall[[:space:]]*\([[:space:]]*__NR_exit/, "SYSCALL_EXIT", tscan)
			while (match(tscan,
			    /trinity_raw_syscall[[:space:]]*\(|trinity_cmp_syscall[[:space:]]*\(|(^|[^a-zA-Z0-9_])(socket|sendmsg|sendto|setsockopt|mmap|syscall|close|open|recv|send|read|write)[[:space:]]*\(/)) {
				fn_raw_sites++
				tscan = substr(tscan, RSTART + RLENGTH - 1)
			}
			# Detect calls to file-local raw_* wrapper functions.
			# These wrappers delegate to trinity_raw_syscall (or similar)
			# but were invisible to the per-function scanner after the
			# direct raw_ alternation was removed at file scope.  The
			# first pass above classified each known wrapper; here we
			# credit fn_raw_sites for every call to a known wrapper, and
			# fn_tally_count only when that wrapper is itself self-counting
			# (i.e. the wrapper body bumps the tally on behalf of callers).
			{
				wscan = code
				while (match(wscan,
				    /(^|[^a-zA-Z0-9_])raw_[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(/)) {
					wm = substr(wscan, RSTART, RLENGTH)
					# Strip leading word-boundary guard char.
					if (substr(wm, 1, 1) !~ /[a-zA-Z_]/)
						wm = substr(wm, 2)
					# Strip trailing whitespace and open-paren.
					sub(/[[:space:]]*\(.*$/, "", wm)
					if (wm in raw_wrapper_known) {
						fn_raw_sites++
						if (raw_wrapper_self_counting[wm])
							fn_tally_count++
					}
					wscan = substr(wscan, RSTART + RLENGTH - 1)
				}
			}
			# Option-b accumulator-increment tracking: scan for <var>++ and
			# <var> += N on plain local scalars (not ->member accesses).
			# Strip pointer-member dereferences first so struct-field
			# increments are not mistaken for local accumulator bumps.
			# Also detect the out-param pointer-deref form (*var)++ and
			# (*var) += N used by sub-combo helpers that receive a
			# direct_calls pointer from the caller.
			{
				incr_scan = code
				gsub(/->[a-zA-Z_][a-zA-Z0-9_]*/, "_MEMBR_", incr_scan)
				tmp2 = incr_scan
				while (match(tmp2, /[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\+\+/)) {
					vn = substr(tmp2, RSTART, RLENGTH)
					sub(/[[:space:]]*\+\+/, "", vn)
					fn_acc_incr[vn] += 1
					tmp2 = substr(tmp2, RSTART + RLENGTH)
				}
				tmp2 = incr_scan
				while (match(tmp2, /[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\+=[[:space:]]*[0-9]+[UuLl]*/)) {
					vn = substr(tmp2, RSTART, RLENGTH)
					av = vn
					sub(/[[:space:]]*\+=.*$/, "", vn)
					sub(/^[^=]*=[[:space:]]*/, "", av)
					gsub(/[UuLl]/, "", av)
					fn_acc_incr[vn] += av + 0
					tmp2 = substr(tmp2, RSTART + RLENGTH)
				}
				# Out-param pointer-deref form: (*var)++ and (*var) += N.
				tmp2 = incr_scan
				while (match(tmp2, /\(\*[a-zA-Z_][a-zA-Z0-9_]*\)[[:space:]]*\+\+/)) {
					vn = substr(tmp2, RSTART, RLENGTH)
					sub(/\(\*/, "", vn)
					sub(/\)[[:space:]]*\+\+/, "", vn)
					fn_acc_incr[vn] += 1
					tmp2 = substr(tmp2, RSTART + RLENGTH)
				}
				tmp2 = incr_scan
				while (match(tmp2, /\(\*[a-zA-Z_][a-zA-Z0-9_]*\)[[:space:]]*\+=[[:space:]]*[0-9]+[UuLl]*/)) {
					vn = substr(tmp2, RSTART, RLENGTH)
					av = vn
					sub(/\(\*/, "", vn)
					sub(/\)[[:space:]]*\+=.*$/, "", vn)
					sub(/^[^=]*=[[:space:]]*/, "", av)
					gsub(/[UuLl]/, "", av)
					fn_acc_incr[vn] += av + 0
					tmp2 = substr(tmp2, RSTART + RLENGTH)
				}
			}
			# Fork-child body terminator detection.  ANY one of the following
			# is sufficient to mark this function as a fork-child body:
			#   _exit(              -- traditional POSIX
			#   _Exit(              -- POSIX C99/C11 capital-E form
			#                          (word-boundary: exclude _Exit_foo)
			#   syscall(__NR_exit   -- raw exit via glibc syscall()
			#   trinity_raw_syscall(__NR_exit  -- trinity raw wrapper
			#   syscall(__NR_exit_group       -- exit_group raw form
			#   trinity_raw_syscall(__NR_exit_group
			#   __attribute__.*noreturn -- noreturn annotation within body
			if (is_fork_fn && !fork_fn_exit_seen) {
				if (match(code, /(^|[^a-zA-Z0-9_])_exit[[:space:]]*\(/))
					fork_fn_exit_seen = 1
				else if (match(code, /(^|[^a-zA-Z0-9_])_Exit[[:space:]]*\(/) &&
				         !match(code, /(^|[^a-zA-Z0-9_])_Exit_/))
					fork_fn_exit_seen = 1
				else if (match(code, /syscall[[:space:]]*\([[:space:]]*__NR_exit/))
					fork_fn_exit_seen = 1
				else if (match(code, /trinity_raw_syscall[[:space:]]*\([[:space:]]*__NR_exit/))
					fork_fn_exit_seen = 1
				else if (match(code, /__attribute__[[:space:]]*\(\([^)]*noreturn/))
					fork_fn_exit_seen = 1
			}
			# fork() detection: a function that calls fork() internally is a
			# parent-side wrapper (fork-within-a-function), not a pure
			# fork-child body.  Exclude such functions from FORK_UNCOUNTED.
			if (is_fork_fn && !fork_fn_has_fork &&
			    match(code, /(^|[^a-zA-Z0-9_])fork[[:space:]]*\(/))
				fork_fn_has_fork = 1
			# Tally-accumulation heuristic (magnitude-aware): parse literal
			# addends where possible rather than counting +1 per tally line.
			#
			#   childop_direct_syscalls_add(op, N):
			#     N is a numeric literal (digits + optional UL/U/ULL suffix)
			#       -> add N to fn_tally_count
			#     N contains any identifier (runtime accumulator or a mixed
			#       expression such as 1UL + write_calls + 1UL)
			#       -> fully accounted (fn_tally_count = large sentinel):
			#          a runtime sum cannot be statically verified
			#     Second arg absent on this line (multi-line call)
			#       -> conservative +1 fallback
			#
			#   __atomic_fetch_add / __atomic_add_fetch on a ->...count/
			#   tally/syscall member with literal N -> add N to fn_tally_count;
			#   non-literal N -> conservative +1 (per-site increment).
			#
			#   Other ->...count/tally/syscall patterns: +1 (unchanged).
			if (index(code, "childop_direct_syscalls_add(") > 0) {
				tline = code
				sub(/.*childop_direct_syscalls_add\([^,]*,/, "", tline)
				if (index(tline, ")") > 0) {
					sub(/\).*$/, "", tline)
					sub(/^[ \t]+/, "", tline)
					sub(/[ \t]+$/, "", tline)
					if (tline ~ /^[0-9]+[UuLl]*$/) {
						fn_tally_count += tline + 0
					} else if (length(tline) > 0) {
						# Runtime accumulator (option b): parse the second
						# arg as a sum of literal addends and identifier
						# addends.  For each identifier look up its tracked
						# ++ / += increment count within this function body.
						# The old sentinel fn_tally_count = fn_raw_sites was
						# always equal, making the < test always false --
						# tail-publish functions whose accumulator did not
						# cover every raw-syscall site were invisible to the
						# gate.  Mixed expressions like "1UL + write_calls +
						# 1UL" parse as literal(1) + incr_count(write_calls)
						# + literal(1), correctly matching fn_raw_sites.
						{
							mixed_sum = 0
							etmp = tline
							while (length(etmp) > 0) {
								if (match(etmp, /^[0-9]+[UuLl]*/)) {
									mixed_sum += substr(etmp, RSTART, RLENGTH) + 0
									etmp = substr(etmp, RSTART + RLENGTH)
								} else if (match(etmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)) {
									vn = substr(etmp, RSTART, RLENGTH)
									if (vn in fn_acc_incr)
										mixed_sum += fn_acc_incr[vn]
									etmp = substr(etmp, RSTART + RLENGTH)
								} else {
									etmp = substr(etmp, 2)
								}
							}
							fn_tally_count += mixed_sum
						}
					} else {
						fn_tally_count++
					}
				} else {
					# Second arg on next line: conservative +1
					fn_tally_count++
				}
			} else if (match(code, /__atomic_(fetch_add|add_fetch)[[:space:]]*\(/) &&
			           match(code, /->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*/)) {
				tline = code
				sub(/.*__atomic_(fetch_add|add_fetch)[[:space:]]*\([^,]*,/, "", tline)
				sub(/,.*$/, "", tline)
				sub(/^[ \t]+/, "", tline)
				sub(/[ \t]+$/, "", tline)
				if (tline ~ /^[0-9]+[UuLl]*$/) {
					fn_tally_count += tline + 0
				} else {
					# Non-literal per-site increment: conservative +1
					fn_tally_count++
				}
			} else if (match(code, /__atomic_store_n[[:space:]]*\(/) &&
			           match(code, /->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*/)) {
				# Thread-publish form: __atomic_store_n(&ptr->tally, expr, order).
				# Used when a pthread worker accumulates into a local counter
				# and stores the total into a shared struct field for the parent
				# thread to read after pthread_join().  Parse the second arg
				# (the stored value) as a mixed literal/accumulator expression,
				# the same way childop_direct_syscalls_add() is parsed.
				{
					tline = code
					sub(/.*__atomic_store_n[[:space:]]*\([^,]*,/, "", tline)
					sub(/,[^,]*$/, "", tline)
					sub(/^[ \t]+/, "", tline)
					sub(/[ \t]+$/, "", tline)
					if (tline ~ /^[0-9]+[UuLl]*$/) {
						fn_tally_count += tline + 0
					} else if (length(tline) > 0) {
						mixed_sum = 0
						etmp = tline
						while (length(etmp) > 0) {
							if (match(etmp, /^[0-9]+[UuLl]*/)) {
								mixed_sum += substr(etmp, RSTART, RLENGTH) + 0
								etmp = substr(etmp, RSTART + RLENGTH)
							} else if (match(etmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)) {
								vn = substr(etmp, RSTART, RLENGTH)
								if (vn in fn_acc_incr)
									mixed_sum += fn_acc_incr[vn]
								etmp = substr(etmp, RSTART + RLENGTH)
							} else {
								etmp = substr(etmp, 2)
							}
						}
						fn_tally_count += mixed_sum
					} else {
						fn_tally_count++
					}
				}
			} else if (match(code, /->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*[ \t]*(\+\+|\+=|=[^=])/) ||
			           match(code, /\+\+[ \t]*[a-zA-Z_][a-zA-Z0-9_]*->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*/)) {
				# Increment/assignment form only: ->member++, ->member +=,
				# ->member = N (literal or tracked accumulator), or ++ptr->member.
				# Plain reads and comparisons (e.g. if (rs->count > 8)) do NOT
				# qualify and must not silently inflate the tally credit.
				# Assignment form ->member = N: parse the literal value
				# or look up a tracked accumulator (e.g. ncalls) rather
				# than always crediting just +1.  This covers patterns
				# such as slot->direct_count = 3 (literal) and
				# slot->direct_count = ncalls (tracked variable).
				{
					assign_scan = code
					if (match(assign_scan, \
					    /->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*[ \t]*=[ \t]*/)) {
						tline = substr(assign_scan, RSTART + RLENGTH)
						sub(/[;,)[:space:]].*$/, "", tline)
						if (tline ~ /^[0-9]+[UuLl]*$/) {
							fn_tally_count += tline + 0
						} else if (match(tline, /^[a-zA-Z_][a-zA-Z0-9_]*$/)) {
							vn = substr(tline, RSTART, RLENGTH)
							if (vn in fn_acc_incr)
								fn_tally_count += fn_acc_incr[vn]
							else
								fn_tally_count++
						} else {
							fn_tally_count++
						}
					} else {
						fn_tally_count++
					}
				}
			}
		}
	}
	END {
		if (!wired && raw_sites > 0)
			print "UNCOUNTED " file " raw_sites=" raw_sites
		# Fork-worker findings are only meaningful for wired files:
		# unwired files are already covered by the UNCOUNTED emit above.
		if (wired) {
			for (i = 0; i < fork_uncounted_n; i++)
				print fork_uncounted[i]
		}
	}
	' "$srcfile" "$srcfile"
done < <(find "$CHILDOPS_DIR" -name '*.c' | LC_ALL=C sort) > "$RESULTS_FILE"

new_unbaselined=()
declare -A SEEN_KEY=()

while IFS=' ' read -r kind key rest; do
	case "$kind" in
		UNCOUNTED)
			# Key is bare filename; baseline entry is UNCOUNTED:<file>.
			gf_key="UNCOUNTED:${key}"
			;;
		THREAD_UNCOUNTED)
			# Derive per-function key: file#fn_name so that multiple
			# workers in the same file each get their own baseline slot.
			fn_token="${rest%% *}"
			fn_name="${fn_token#fn=}"
			key="${key}#${fn_name}"
			gf_key="THREAD_UNCOUNTED:${key}"
			;;
		FORK_UNCOUNTED)
			# Same key structure as THREAD_UNCOUNTED: file#fn_name.
			fn_token="${rest%% *}"
			fn_name="${fn_token#fn=}"
			key="${key}#${fn_name}"
			gf_key="FORK_UNCOUNTED:${key}"
			;;
		*) continue ;;
	esac
	[ -n "${SEEN_KEY[$key]+x}" ] && continue
	SEEN_KEY["$key"]=1
	if [ -n "${GRANDFATHERED[$gf_key]+x}" ]; then
		:
	else
		new_unbaselined+=("[$kind] $key ($rest)")
	fi
done < "$RESULTS_FILE"

# Stale baseline entries: listed but no longer have uncounted syscall
# sites (wired up or removed).  Fatal: exits 1 to enforce baseline hygiene.
stale_baseline=()
for gf_entry in "${!GRANDFATHERED[@]}"; do
	case "$gf_entry" in
		UNCOUNTED:*)        bare_key="${gf_entry#UNCOUNTED:}" ;;
		THREAD_UNCOUNTED:*) bare_key="${gf_entry#THREAD_UNCOUNTED:}" ;;
		FORK_UNCOUNTED:*)   bare_key="${gf_entry#FORK_UNCOUNTED:}" ;;
		*)                  bare_key="$gf_entry" ;;
	esac
	if [ -z "${SEEN_KEY[$bare_key]+x}" ]; then
		stale_baseline+=("$gf_entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} childop file(s) issue raw syscalls"
		echo "  without calling childop_direct_syscalls_add():"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo "  fix: add a direct_calls counter, bump it at each raw-syscall"
		echo "       site in the file, and publish at the tail return:"
		echo "         if (valid_op && direct_calls > 0)"
		echo "             childop_direct_syscalls_add(op, direct_calls);"
		echo "       If the file issues syscalls only through the nl_*"
		echo "       transport (nl_open/nl_send_recv/nl_close with a valid"
		echo "       caller_op), nl_close() already calls"
		echo "       childop_direct_syscalls_add() and no additional call"
		echo "       is needed -- but add the file to"
		echo "       scripts/check-static/childop-direct-syscall-uncounted.baseline"
		echo "       so the gate knows it is intentionally netlink-only."
		echo "       The baseline should shrink over time, never grow."
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  ${#stale_baseline[@]} baseline entry/entries no longer"
		echo "  have uncounted raw-syscall sites (stale entries must be pruned):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
		echo "  fix: remove the listed entries from"
		echo "       scripts/check-static/childop-direct-syscall-uncounted.baseline"
	} >&2
	echo "FAIL: $NAME: ${#stale_baseline[@]} stale baseline entry/entries"
	exit 1
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} file(s) with uncounted direct syscalls"
	exit 1
fi

COUNT_BASELINE="$ROOT/scripts/check-static/childop-direct-syscall-uncounted.count.baseline"
frozen=$(cat "$COUNT_BASELINE" 2>/dev/null | tr -d '[:space:]')
if [ -z "$frozen" ] || ! [ "$frozen" -ge 0 ] 2>/dev/null; then
	echo "FAIL: $NAME: cannot read frozen ceiling from $COUNT_BASELINE" >&2
	exit 1
fi

# Anti-backslide ratchet: .prev is the highest value the ceiling is
# allowed to hold.  A missing, empty, or non-numeric .prev is a hard
# failure -- it means the guard file has been tampered with or was
# never properly seeded, and silently skipping would be fail-open.
PREV_BASELINE="${COUNT_BASELINE}.prev"
if [ ! -e "$PREV_BASELINE" ]; then
	{
		echo "FAIL: $NAME: ratchet guard $PREV_BASELINE is missing."
		echo "  Create it with the current ceiling value to initialise the ratchet."
	} >&2
	exit 1
fi
prev=$(cat "$PREV_BASELINE" 2>/dev/null | tr -d '[:space:]')
if [ -z "$prev" ] || ! [ "$prev" -ge 0 ] 2>/dev/null; then
	{
		echo "FAIL: $NAME: $PREV_BASELINE is empty or non-numeric (got: '$prev')."
		echo "  It must contain a non-negative integer matching the ceiling."
	} >&2
	exit 1
fi
if [ "$frozen" -gt "$prev" ]; then
	{
		echo "FAIL: $NAME: ceiling raised $prev→$frozen (ratchet must only shrink)."
		echo "  To lower the ceiling, decrease both count.baseline and"
		echo "  count.baseline.prev together.  Raising the ceiling requires"
		echo "  an explicit matching update of count.baseline.prev."
	} >&2
	exit 1
fi
# Pawl follow: when the ceiling is lowered, advance .prev to track it
# so the ratchet cannot silently re-raise back to a stale high-water mark.
if [ "$frozen" -lt "$prev" ]; then
	if ! printf '%s\n' "$frozen" > "$PREV_BASELINE" 2>/dev/null; then
		echo "WARN: $NAME: could not update $PREV_BASELINE; check file permissions." >&2
	fi
fi

total=${#SEEN_KEY[@]}

if [ "$total" -gt "$frozen" ]; then
	echo "FAIL: uncounted worker count regressed: $total > frozen ceiling $frozen"
	exit 1
fi

echo "PASS: $NAME (uncounted=$total, ceiling=$frozen)"
exit 0
