#!/bin/bash
#
# Stop every running trinity the invoker owns, or every one on the host
# when run as root.  A parent (comm trinity-main) exits cleanly once a
# trinity-stop file appears in its tmp dir: its cwd, or /tmp when it was
# started without a tmp/ dir.  That works whatever uid the run uses, so
# ask that way first and give the parents time to reap their children
# and write the warm-start saves.  Then fall back to SIGTERM, which a
# parent honours only from a uid its children cannot send as, and
# finally SIGKILL.

# A parent waits up to 30s for D-state children before parking them.
GRACE_SECS=60

# Anyone but root can only signal their own processes; leave other
# users' runs alone rather than wait out the grace period on them and
# collect EPERM.
match=(-x)
[ "$(id -u)" -eq 0 ] || match+=(-u "$(id -u)")

parents=$(pgrep "${match[@]}" trinity-main)
stopfiles=()

# Remove the stop files however we exit.  A root-owned one left in the
# sticky /tmp can't be unlinked by a later non-root run, which would
# still honour it and stop on its first tick.
trap 'rm -f "${stopfiles[@]}" 2>/dev/null' EXIT

if [ -n "$parents" ]; then
	for pid in $parents; do
		cwd=$(readlink "/proc/$pid/cwd") && stopfiles+=("$cwd/trinity-stop")
	done
	stopfiles+=(/tmp/trinity-stop)

	# Create by rename, so a symlink already sitting on the name is
	# replaced rather than written through.
	for f in "${stopfiles[@]}"; do
		t=$(mktemp "${f%/*}/.trinity-stop.XXXXXX" 2>/dev/null) || continue
		mv -fT "$t" "$f" 2>/dev/null || rm -f "$t"
	done

	for ((i = 0; i < GRACE_SECS; i++)); do
		pgrep "${match[@]}" trinity-main >/dev/null || break
		sleep 1
	done

	survivors=$(pgrep "${match[@]}" trinity-main)
	if [ -n "$survivors" ]; then
		for pid in $survivors; do
			kill "$pid"
		done
		sleep 2
	fi
fi

# trinity-subchil is the exec grandchild's "trinity-subchild", cut to
# the 15 characters a comm holds.  trinity-nsinit is the idle init of a
# child's pid namespace.
for pid in $(pgrep "${match[@]}" 'trinity(-main|-kmsg|-c[0-9]+|-subchil|-nsinit)?'); do
	kill -9 "$pid"
done
