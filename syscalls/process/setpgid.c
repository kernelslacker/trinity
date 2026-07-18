/*
 * SYSCALL_DEFINE2(setpgid, pid_t, pid, pid_t, pgid)
 */
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: setpgid(pid, pgid) on success has flipped the target task's
 * signal->pids[PIDTYPE_PGID] to point at the pid struct identified by
 * `pgid` (or, when pgid == 0, the target's own pid).  When the caller
 * targets itself (pid == 0) we can re-read the same kernel field via
 * getpgrp() and check it against the value we know the kernel must have
 * just written.  Both paths walk task_pgrp_vnr(current), but as
 * independent reads of signal_struct, so a divergence between the value
 * the syscall just committed and the subsequent getpgrp() is its own
 * corruption shape: a torn write to signal->pids[PIDTYPE_PGID], a
 * stale rcu pointer to signal_struct between the two reads, or a
 * mismatched pid_ns translation.
 *
 * Two-arg branch: setpgid(0, 0) folds the new pgid to the caller's own
 * pid, so the expected value comes from getpid().  setpgid(0, X != 0)
 * sets the pgid to X verbatim.  We can only validate the pid == 0
 * case — for pid != 0 we'd be reading our own pgrp while the kernel
 * mutated some other task's, which tells us nothing.
 *
 * Skip the failure path (retval == -1): no kernel state was changed,
 * so there is nothing to validate.  Sample one in a hundred successes
 * to stay in line with the rest of the oracle family.
 */
static void post_setpgid(struct syscallrecord *rec)
{
	unsigned long a1, a2;
	pid_t expected, got;

	if ((long) rec->retval == -1L)
		return;

	/*
	 * Read pid/pgid via the arg_shadow accessor: the oracle is gated
	 * on pid (a1) being 0 -- self-call -- and the expected getpgrp()
	 * value is selected per-case from pgid (a2: a2 == 0 folds to
	 * getpid(), otherwise the kernel set pgrp to a2 verbatim).
	 * Reading live rec->aN would let a sibling stomp between syscall
	 * return and this handler flip the gate or swing the per-case
	 * expected branch, mis-attributing the getpgrp() check against a
	 * value the kernel never wrote: a stomp of non-zero -> 0 on a1
	 * fires the oracle on a call where the kernel set some other
	 * task's pgid, and a stomp of a2 picks the wrong arm (either
	 * comparing getpgrp() against getpid() when the kernel committed
	 * a2, or against a fabricated a2 value when the kernel folded to
	 * getpid()) -- both produce a spurious oracle mismatch.
	 * arg_snapshot_mask on syscall_setpgid opts a1/a2 into the
	 * shadow; get_arg_snapshot() returns the dispatch-time value and
	 * bumps arg_shadow_stomp from inside the accessor on mismatch.
	 */
	a1 = get_arg_snapshot(rec, 1);
	a2 = get_arg_snapshot(rec, 2);

	if ((pid_t) a1 != 0)
		return;
	if (!ONE_IN(100))
		return;

	if ((pid_t) a2 == 0)
		expected = (pid_t) syscall(__NR_getpid);
	else
		expected = (pid_t) a2;

	got = getpgrp();
	if (got != expected) {
		output(0, "setpgid oracle: setpgid(0,%d) succeeded but "
		       "subsequent getpgrp()=%d (expected %d)\n",
		       (pid_t) a2, got, expected);
		__atomic_add_fetch(&shm->stats.oracle.setpgid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setpgid = {
	.name = "setpgid",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_PID },
	.argname = { [0] = "pid", [1] = "pgid" },
	.post = post_setpgid,
	.rettype = RET_ZERO_SUCCESS,
	/* a1/a2 (pid/pgid) both feed post_setpgid's oracle: a1 == 0 gates
	 * the oracle to self-calls, and a2 selects which expected pgid the
	 * getpgrp() result is compared against (getpid() when a2 == 0, a2
	 * verbatim otherwise).  Shadow both so a sibling stomp between
	 * dispatch and post cannot flip the gate or swing the per-case
	 * expected branch, mis-attributing the oracle against a value the
	 * kernel never wrote -- mismatch bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the oracle still compares against the
	 * (pid, pgid) the kernel actually executed against. */
	.arg_snapshot_mask = (1u << 0) | (1u << 1),
};
