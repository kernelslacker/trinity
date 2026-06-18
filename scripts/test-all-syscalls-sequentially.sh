#!/bin/bash
#
# This is a useful test to run occasionally, to see which syscalls are
# causing trinity to segfault.

set -uo pipefail

ulimit -v unlimited

CHILDREN=4

# Kernel version for the cache-stats -k key, without the local build suffix
KVER=$(uname -r); KVER=${KVER%%-*}

. scripts/paths.sh
. scripts/taint.sh

# Pre-flight: can we system-wide perf record?  If not (perf_event_paranoid > 1
# and not root), fall back to fuzzing WITHOUT perf rather than silently
# producing empty runs for the whole sweep.  PERF_PREFIX is the per-run perf wrapper
# (empty array = no perf).
PERF_PREFIX=()
if perf record -a -F 99 -o /tmp/.perftest.$$ -- true 2>/dev/null; then
	PERF_PREFIX=(perf record -a -F 99)
	rm -f /tmp/.perftest.$$
else
	echo "WARNING: 'perf record -a' unavailable (need perf_event_paranoid <= 1 or root)." >&2
	echo "         Continuing WITHOUT perf capture." >&2
fi

for syscall in $("$TRINITY_PATH/trinity" -L | sort -u)
do
	TIME=$(date +%Y%m%d-%H%M%S)
	echo $TIME
	echo $syscall

	if [ ! -f "$TRINITY_PATH/trinity" ]; then
		echo lost!
		pwd
		exit 1
	fi

	# Per-run kernel-log capture -> dmesg-$TIME.log (the find below files it into
	# $TIME-$syscall/).  --follow-new = THIS run only; head -c 1G caps the size;
	# killed right after the run so the follower can't leak (run-trinity.sh class).
	stdbuf -oL dmesg --follow-new --time-format=iso > >(head -c 1G > dmesg-$TIME.log) &
	DMESG_PID=$!

	# Wrap the run in system-wide perf record (when available -- see pre-flight).
	# trinity is almost entirely kernel-bound, so -a (all-CPU) is where the
	# signal is.  perf propagates trinity's exit code, so the 124/137 timeout
	# check below still works.  Flat profile (no -g): the per-syscall top-symbol
	# list is the mine; for a deep-dive on one syscall add `--call-graph dwarf`.
	# -a64 keeps us off the 32-bit (int 0x80) path that segfaults on this kernel.
	MALLOC_PERTURB_=$RANDOM MALLOC_CHECK_=3 \
		"${PERF_PREFIX[@]}" ${PERF_PREFIX:+-o perf-$TIME.data --} \
		timeout -k 30s 15m "$TRINITY_PATH/trinity" -c "$syscall" -N 50000 -C $CHILDREN -a64 -x execve -x execveat --stats --stats-log-file=stats.log >out.log 2>outerr.log
	rc=$?; { [ "$rc" = 124 ] || [ "$rc" = 137 ]; } && echo "$syscall" >> timeouts-$TIME.log

	kill "$DMESG_PID" 2>/dev/null; wait "$DMESG_PID" 2>/dev/null   # stop+reap the dmesg follower before moving logs

	# Distil perf.data into a compact, mineable text profile, then drop the raw
	# capture: a system-wide -a record is ~hundreds of MB/run, so keeping all
	# ~387 would be 100s of GB.  perf-report-$TIME.txt is the per-syscall version
	# of `perf top -a`.  To keep raw instead (flamegraphs/annotate): drop the rm,
	# add `-z`, lower -F, or use per-process (no -a) -- and expect the disk cost.
	if [ ${#PERF_PREFIX[@]} -gt 0 ] && [ -s perf-$TIME.data ]; then
		perf report --stdio -i perf-$TIME.data > perf-report-$TIME.txt 2>/dev/null
		rm -f perf-$TIME.data
	fi

	cp out.log out-$TIME.log
	cp outerr.log outerr-$TIME.log
	cp stats.log stats-$TIME.log

	echo > stats.log

	./logtar.sh
	mv bugs.tar.gz bugs-$TIME.tar.gz

	scripts/cache-stats.py stats ~/.cache/trinity/ -k "$KVER" > cache-stats-$TIME.log

	mkdir $TIME-$syscall
	find . -maxdepth 1 -type f -name "*$TIME*" -exec mv "{}" $TIME-$syscall/ \;

	# Group any core dumps in with this run's logs (most produce none).
	if compgen -G "tmp/core.*" > /dev/null; then
		mv tmp/core.* $TIME-$syscall/
	fi

	sudo rm -rf tmp ; mkdir tmp

	check_tainted
	echo
done
