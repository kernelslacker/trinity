#ifndef _TRINITY_STATS_SUBSYS_USERNS_FUZZER_H
#define _TRINITY_STATS_SUBSYS_USERNS_FUZZER_H

struct userns_fuzzer_stats {
	/* userns_fuzzer childop counters */
	unsigned long runs;			/* total userns_fuzzer invocations */
	unsigned long inner_crashed;		/* inner child died by signal */
	unsigned long unsupported;		/* CLONE_NEWUSER refused, noop path */

	/*
	 * userns_fuzzer's make_root_private() observed a failing
	 * mount("none", "/", MS_REC|MS_PRIVATE) before the per-op
	 * tmpfs mount.  The original shape called output(0, ...) so
	 * an operator watching the run could see that the inner mount
	 * ns wasn't isolated from the host's mount tree before the
	 * tmpfs attempt -- but make_root_private() runs from child
	 * context, where init_child has redirected stderr to /dev/null,
	 * so the diagnostic was lost.  Bump a shm counter on every
	 * failure (no one-shot: this fires per-iteration and the
	 * accumulating count is the survivor signal that mount-ns
	 * isolation is broken on the host).  A non-zero value across a
	 * run says the tmpfs mount path was being run unprotected.
	 */
	unsigned long root_private_failed;
};

#endif /* _TRINITY_STATS_SUBSYS_USERNS_FUZZER_H */
