#ifndef _TRINITY_STATS_SUBSYS_USERNS_BOOTSTRAP_H
#define _TRINITY_STATS_SUBSYS_USERNS_BOOTSTRAP_H

struct userns_bootstrap_stats {
	/* SHADOW per-outcome telemetry for the shared userns_run_in_ns()
	 * bootstrap helper (lib/userns-bootstrap.c).  The helper return
	 * value collapses every non-EPERM failure into -EAGAIN, so the
	 * caller-side accounting in the ~20+ net-ns childops that use this
	 * helper cannot distinguish a fork() failure from a setgroups write
	 * failure from a secondary unshare() rejection from a signalled
	 * grandchild.  These counters surface the breakdown without
	 * changing the return contract.
	 *
	 * Bumped from the parent path in userns_run_in_ns() ONLY -- the
	 * grandchild body cannot reach shared stats because every exit path
	 * runs through _exit().  Each counter is keyed off the grandchild's
	 * WEXITSTATUS code (or WIFSIGNALED for the signalled slot, or the
	 * fork()-failure return for the fork_fail slot).  Distinct from the
	 * pre-existing userns_runs / userns_inner_crashed / userns_unsupported
	 * counters above, which belong to the dedicated userns_fuzzer
	 * childop -- the bootstrap helper is a separate call site shared
	 * across the net-ns childops.
	 *
	 *  runs              total helper invocations that reached fork()
	 *                    (gate counter for the stats block)
	 *  ran               UBS_EXIT_RAN -- callback executed inside the
	 *                    namespace stack and returned cleanly
	 *  eperm             UBS_EXIT_USERNS_EPERM -- unshare(CLONE_NEWUSER)
	 *                    refused; matches the -EPERM caller return
	 *  userns_other      UBS_EXIT_USERNS_OTHER -- unshare(CLONE_NEWUSER)
	 *                    failed for a non-EPERM reason (also catches any
	 *                    unknown WEXITSTATUS via the switch default)
	 *  map_write_fail    Any UBS_EXIT_MAP_WRITE_FAIL_* -- uid_map /
	 *                    setgroups / gid_map write rejected by the
	 *                    kernel.  Rollup total; the three _eperm /
	 *                    _einval / _other slots below decompose it.
	 *  map_write_fail_eperm   write returned EPERM.  Post-geteuid this
	 *                    means the kernel still rejected the unprivi-
	 *                    leged single-line mapping (cred mismatch
	 *                    survived, capability profile lost, ...).
	 *  map_write_fail_einval  write returned EINVAL.  Line malformed
	 *                    or rule violated (e.g. multi-line write, range
	 *                    overlap), distinct from a permission failure.
	 *  map_write_fail_other   anything else -- open() ENOENT/EACCES,
	 *                    short write, EIO, ENOMEM, ...  Bucketed so
	 *                    novel errnos do not vanish into the EPERM
	 *                    slot.
	 *  target_unshare    UBS_EXIT_TARGET_UNSHARE -- secondary
	 *                    unshare(target_ns_flags) failed
	 *  fork_fail         fork() in the parent returned -1
	 *  signalled         grandchild died by signal (WIFEXITED false)
	 *
	 * RELAXED add-fetch -- diagnostic, not an event log. */
	unsigned long runs;
	unsigned long ran;
	unsigned long eperm;
	unsigned long userns_other;
	unsigned long map_write_fail;
	unsigned long map_write_fail_eperm;
	unsigned long map_write_fail_einval;
	unsigned long map_write_fail_other;
	unsigned long target_unshare;
	unsigned long fork_fail;
	unsigned long signalled;
};

#endif /* _TRINITY_STATS_SUBSYS_USERNS_BOOTSTRAP_H */
