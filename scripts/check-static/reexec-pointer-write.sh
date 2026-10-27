#!/bin/bash
#
# reexec-pointer-write: a REEXEC_SANITISE_OK entry whose sanitiser stores a
# pointer into rec->aN is listed in the baseline.
#
# The CMP RedQueen re-exec step replays an opted-in sanitiser from a clean
# slate (include/syscall.h, above REEXEC_SANITISE_OK).  A pointer a
# sanitiser plants in an argument slot by hand, rather than through the
# generic ARG_* generators, is the part of that replay most likely to
# outlive its owner.  check-reexec-coverage proves every sanitise-bearing
# entry carries a decision; this gate flags the flagged ones whose
# sanitiser stores one of
#   rec->aN = ... <allocator>(...)        on one line, or
#   rec->aN = [(cast)] &x                 address-of, or
#   p = <allocator>(...); ... rec->aN = [(cast)] p
# where <allocator> is get_writable_*, get_address,
# get_non_null_address, zmalloc, malloc, calloc, alloc_shared* or mmap.  The sanitiser is found
# by name in the entry's own file; one defined elsewhere is not read.
#
# The baseline lists <file>:<entry> pairs and must only shrink: a line
# fails once its entry stops matching (cleaned up, or no longer flagged).
# The scan is textual and line-based: an assignment split over lines is
# missed.

set -u

NAME="reexec-pointer-write"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BASELINE="$ROOT/scripts/check-static/reexec-pointer-write.baseline"

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

# Far below the real count of flagged entries so churn never trips it.
MIN_FLAGGED=200

# scan_stream: stdin is comment-stripped source.  Print "F <entry>" per
# REEXEC_SANITISE_OK entry and "P <entry>" for each of those whose
# sanitiser writes a pointer into rec->aN.
scan_stream() {
	# shellcheck disable=SC2016
	awk '
	function alloc_call(s) {
		return s ~ /(get_writable_[A-Za-z0-9_]*|get_address|get_non_null_address|zmalloc|malloc|calloc|alloc_shared[A-Za-z0-9_]*|mmap)[[:space:]]*\(/
	}
	function writes_pointer(text,    n, lines, i, l, v, rhs, ptr) {
		n = split(text, lines, "\n")
		for (i = 1; i <= n; i++) {
			l = lines[i]
			if (l ~ /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[^=]/ && alloc_call(l)) {
				v = l
				sub(/^[[:space:]]*/, "", v)
				sub(/[[:space:]]*=.*$/, "", v)
				ptr[v] = 1
			}
		}
		for (i = 1; i <= n; i++) {
			l = lines[i]
			if (l !~ /rec->a[1-6][[:space:]]*=[^=]/)
				continue
			rhs = l
			sub(/^.*rec->a[1-6][[:space:]]*=[[:space:]]*/, "", rhs)
			if (alloc_call(rhs))
				return 1
			sub(/^\([^)]*\)[[:space:]]*/, "", rhs)
			if (rhs ~ /^&[A-Za-z_]/)
				return 1
			sub(/[^A-Za-z0-9_].*$/, "", rhs)
			if (rhs != "" && (rhs in ptr))
				return 1
		}
		return 0
	}
	/^struct syscallentry [A-Za-z0-9_]+[[:space:]]*=/ {
		ename = $3; sub(/=.*/, "", ename)
		in_entry = 1; flag = 0; san = ""
		next
	}
	in_entry {
		if ($0 ~ /(^|[^A-Za-z0-9_])REEXEC_SANITISE_OK([^A-Za-z0-9_]|$)/)
			flag = 1
		if ($0 ~ /\.sanitise[[:space:]]*=/) {
			san = $0
			sub(/^.*\.sanitise[[:space:]]*=[[:space:]]*/, "", san)
			sub(/[^A-Za-z0-9_].*$/, "", san)
		}
		if ($0 ~ /^};/) {
			in_entry = 0
			if (flag) { ne++; ent[ne] = ename; esan[ne] = san }
		}
		next
	}
	/^[A-Za-z_].*[A-Za-z0-9_][[:space:]]*\(/ && $0 !~ /;[[:space:]]*$/ {
		fname = $0
		sub(/[[:space:]]*\(.*$/, "", fname)
		sub(/^.*[^A-Za-z0-9_]/, "", fname)
		in_fn = 1; body[fname] = ""
		next
	}
	in_fn {
		if ($0 ~ /^}/) in_fn = 0
		else body[fname] = body[fname] $0 "\n"
		next
	}
	END {
		for (i = 1; i <= ne; i++) {
			print "F", ent[i]
			if (esan[i] != "" && (esan[i] in body) && writes_pointer(body[esan[i]]))
				print "P", ent[i]
		}
	}
	'
}

# scan_tree ROOT: print "F|P <file>:<entry>" for every .c under ROOT/syscalls.
scan_tree() {
	local root="$1" f out kind entry
	while IFS= read -r f; do
		out="$(strip_c_comments "$root/$f" | scan_stream)"
		[ -n "$out" ] || continue
		while read -r kind entry; do
			echo "$kind $f:$entry"
		done <<< "$out"
	done < <(cd "$root" && find syscalls -name '*.c' -print | LC_ALL=C sort)
}

# Self-test on a planted tree: each pattern must be found, and the near
# misses (scalar store, comment, unflagged entry, no sanitiser) must not.
selftest_dir="$(mktemp -d)" || { echo "FAIL: $NAME: mktemp failed"; exit 1; }
trap 'rm -rf "$selftest_dir"' EXIT
mkdir -p "$selftest_dir/syscalls"
cat > "$selftest_dir/syscalls/c.c" <<'EOT'
static void san_direct(struct syscallrecord *rec)
{
	rec->a2 = (unsigned long) get_writable_struct(8);
}
static void san_var(struct syscallrecord *rec)
{
	struct foo *p;

	p = get_writable_struct(8);
	rec->a3 = (unsigned long) p;
}
static void san_addr(struct syscallrecord *rec)
{
	rec->a1 = (unsigned long) &x;
}
static void san_scalar(struct syscallrecord *rec)
{
	struct foo *p = get_writable_struct(8);

	p->x = 1;
	rec->a1 = rnd_u32();
}
/* rec->a1 = (unsigned long) get_address(); in a comment */
static void san_comment(struct syscallrecord *rec)
{
	rec->a1 = 0;
}
struct syscallentry syscall_direct = {
	.flags = REEXEC_SANITISE_OK,
	.sanitise = san_direct,
};
struct syscallentry syscall_var = {
	.flags = REEXEC_SANITISE_OK,
	.sanitise = san_var,
};
struct syscallentry syscall_addr = {
	.flags = REEXEC_SANITISE_OK,
	.sanitise = san_addr,
};
struct syscallentry syscall_scalar = {
	.flags = REEXEC_SANITISE_OK,
	.sanitise = san_scalar,
};
struct syscallentry syscall_comment = {
	.flags = REEXEC_SANITISE_OK,
	.sanitise = san_comment,
};
struct syscallentry syscall_unflagged = {
	.sanitise = san_direct,
};
struct syscallentry syscall_nosan = {
	.flags = REEXEC_SANITISE_OK,
};
EOT
expect="F syscalls/c.c:syscall_direct
P syscalls/c.c:syscall_direct
F syscalls/c.c:syscall_var
P syscalls/c.c:syscall_var
F syscalls/c.c:syscall_addr
P syscalls/c.c:syscall_addr
F syscalls/c.c:syscall_scalar
F syscalls/c.c:syscall_comment
F syscalls/c.c:syscall_nosan"
got="$(scan_tree "$selftest_dir")"
if [ "$got" != "$expect" ]; then
	{
		echo "  $NAME: self-test FAILED -- the scan of the planted tree is wrong."
		echo "  Expected:"
		printf '%s\n' "$expect" | sed 's/^/    /'
		echo "  Got:"
		printf '%s\n' "$got" | sed 's/^/    /'
	} >&2
	echo "FAIL: $NAME: self-test: planted tree scanned wrongly"
	exit 1
fi

scan="$(scan_tree "$ROOT")"
flagged="$(grep -c '^F ' <<< "$scan")"
if [ "$flagged" -lt "$MIN_FLAGGED" ]; then
	echo "FAIL: $NAME: only $flagged flagged entries found, expected >= $MIN_FLAGGED: the scan is not reading the tree"
	exit 1
fi

declare -A hit=() listed=()
while read -r kind key; do
	[ "$kind" = P ] && hit["$key"]=1
done <<< "$scan"
if [ -r "$BASELINE" ]; then
	while IFS= read -r key; do
		[ -n "$key" ] && listed["$key"]=1
	done < <(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' -e '/^$/d' "$BASELINE")
fi

new=0
stale=0
while IFS= read -r key; do
	[ -n "$key" ] || continue
	[ -n "${listed[$key]+x}" ] && continue
	[ "$new" = 0 ] && echo "  REEXEC_SANITISE_OK entries whose sanitiser stores a pointer in rec->aN:" >&2
	echo "    $key" >&2
	new=$((new + 1))
done < <(printf '%s\n' "${!hit[@]}" | LC_ALL=C sort)
while IFS= read -r key; do
	[ -n "$key" ] || continue
	if [ -z "${hit[$key]+x}" ]; then
		echo "  baseline names $key, which no longer matches: drop the line" >&2
		stale=$((stale + 1))
	fi
done < <(printf '%s\n' "${!listed[@]}" | LC_ALL=C sort)

if [ $((new + stale)) -gt 0 ]; then
	echo "FAIL: $NAME: $new new pointer-writing entry/entries, $stale stale baseline line(s)"
	exit 1
fi
echo "PASS: $NAME: $flagged flagged entries, ${#hit[@]} pointer-writing (all baselined)"
exit 0
