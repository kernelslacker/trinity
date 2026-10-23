#!/bin/bash
#
# pidns-init-wiring: the idle init of a child's pid namespace has to be
# forked after the sandbox's credential drop, and a child whose init has
# died has to notice.
#
# init_child_setup_sandbox() unshares CLONE_NEWPID before drop_privs() and
# the capset() drop, but forks the init (start_pidns_init()) only after
# both.  The kernel checks the parent-death signal like a kill() from the
# dying child (check_kill_permission()), so an init forked any earlier
# would stay root and miss that signal from a child running as nobody.
# Nothing in a test sees that order, and moving the fork back next to the
# unshare would look like a tidy-up, so it is pinned here.  So is the
# pidns_init_lost() poll in child_process(): without it a child fuzzes on
# in a dead namespace, where every fork fails, and no test sees that loop.
#
# Comments are stripped first (strip_c_comments keeps the line numbers),
# so prose that names the calls does not count.

set -u

NAME="pidns-init-wiring"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
SANDBOX="child/child-init-sandbox.c"
LOOP="child/child.c"

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

fail() {
	echo "  $NAME: $1" >&2
	echo "FAIL: $NAME"
	exit 1
}

# first_code_line FILE ERE: line number of the first code line of FILE
# that matches ERE, or nothing.
first_code_line() {
	strip_c_comments "$1" | grep -n -m1 -E -e "$2" | cut -d: -f1
}

cd "$ROOT" || fail "cannot cd to $ROOT"
[ -r "$SANDBOX" ] || fail "cannot read $SANDBOX"

drop=$(first_code_line "$SANDBOX" '\bdrop_privs\(\);')
capset=$(first_code_line "$SANDBOX" '\b__NR_capset\b')
init=$(first_code_line "$SANDBOX" '\bstart_pidns_init\(\)')

[ -n "$drop" ] || fail "$SANDBOX: no drop_privs() call"
[ -n "$capset" ] || fail "$SANDBOX: no capset() syscall"
[ -n "$init" ] || fail "$SANDBOX: no start_pidns_init() call"
if [ "$init" -le "$drop" ] || [ "$init" -le "$capset" ]; then
	fail "$SANDBOX:$init: start_pidns_init() comes before drop_privs() (line $drop) or the capset() drop (line $capset)"
fi

[ -r "$LOOP" ] || fail "cannot read $LOOP"
[ -n "$(first_code_line "$LOOP" '\bpidns_init_lost\(\)')" ] ||
	fail "$LOOP: child_process() no longer polls pidns_init_lost()"

echo "PASS: $NAME"
