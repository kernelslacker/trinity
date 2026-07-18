#pragma once

#include <stdbool.h>
#include <sys/types.h>

/*
 * Self-cgroup: at startup, place trinity into its own cgroup v2
 * sub-cgroup with a memory cap so a runaway allocation triggers a
 * scoped OOM kill of the worker pool instead of a host-wide global
 * OOM or an upstream group-OOM cascade.
 *
 * Design rationale, split-mode layout diagram, and failure fallback
 * ladder: Documentation/self-cgroup.md
 */
void self_cgroup_setup(void);
void self_cgroup_cleanup(void);
void self_cgroup_events_check(void);

/*
 * Close the parent's self-cgroup fds in a freshly forked child.  All
 * are opened IN_CLOEXEC, but CLOEXEC only fires on exec(); trinity's
 * children fork-and-fuzz without exec, so they inherit the parent's
 * open-file-descriptions.  Three fds need dropping:
 *
 *   - the memory.events file fd and its inotify watch fd.  A fuzzed
 *     fcntl(fd, F_SETFL, ...) in a child can clear O_NONBLOCK on the
 *     shared OFD, after which the parent's drain-read in
 *     self_cgroup_events_check() blocks forever -- main loop hangs,
 *     no fuzz children get reaped, zombie pileup.
 *
 *   - cg_workload_fd, the O_DIRECTORY fd on children/ that the parent
 *     hands to clone3(CLONE_INTO_CGROUP) (and falls back to
 *     openat(fd, "cgroup.procs") for post-migrate placement).  A
 *     fuzzed dup2 onto this slot redirects subsequent spawns into the
 *     wrong cgroup -- children escape the memory.max cap and the
 *     oom.group=1 scoped kill, defeating the whole containment story.
 *     A fuzzed close() turns the next spawn into EBADF and stalls the
 *     fork loop.  The parent already used the fd for its own clone3
 *     before the child reaches this hook, so closing the child's
 *     inherited copy can't break the parent's spawn path.
 *
 * Drop them all in the child's fd-shedding path so none are reachable
 * for fuzzing.
 */
void self_cgroup_drop_fds_in_child(void);

/*
 * fork() replacement that places the new child in the children/ cgroup
 * via clone3(CLONE_INTO_CGROUP).  Same return semantics as fork(): pid in
 * parent, 0 in child, -1 on error.  Falls back to plain fork() (single-
 * cgroup mode or no cgroup at all) or to fork()+post-migrate (older
 * kernel with no clone3) when CLONE_INTO_CGROUP isn't available.  Called
 * by spawn_child() in main/loop.c as a drop-in replacement for fork().
 */
pid_t self_cgroup_fork_into_workload(void);

/*
 * Per-spawn fork delay applied by the parent before each fork().  Set
 * by self_cgroup_events_check() in response to memory.high bumps and
 * decayed back to 0 after a quiet streak.  Read once per spawn from
 * spawn_child(); 0 means no throttle (the common case).
 */
extern unsigned int fork_throttle_us;

/*
 * Syntactic validation of a --memory-max / --memory-high /
 * --memory-swap-max argument.  Called from parse_args() so a malformed
 * value is rejected at parse time, before self_cgroup_setup() or any
 * fork/fuzz work runs -- the historical validator lived inside
 * self_cgroup_setup(), so this hook catches a bad value during
 * argument handling instead of only when setup first parses it.
 * Accepts "max", "<n>%" with 1 <= n <= 100, and
 * "<n>[KMG]" decimal byte counts; rejects leading signs, empty input,
 * unknown suffixes, percentage out-of-range, and overflow.  Emits a
 * "--flag: invalid memory-size ..." diagnostic on rejection.
 */
bool validate_cgroup_size_arg(const char *flag_name, const char *arg);
