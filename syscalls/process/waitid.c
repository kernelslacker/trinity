/*
 * SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
	infop, int, options, struct rusage __user *, ru)
 */
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include "objects.h"
#include "output-poison.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/wait.h"
static unsigned long waitid_options[] = {
	WNOHANG, WEXITED, WSTOPPED, WCONTINUED, WNOWAIT,
	__WALL, __WCLONE, __WNOTHREAD,
};

static unsigned long waitid_which[] = {
	P_ALL, P_PID, P_PGID, P_PIDFD,
};

/*
 * When which==P_PIDFD, upid (a2) must be a real pidfd, not a pid.
 * Re-resolve a live pidfd from the OBJ_FD_PIDFD pool (mirrors the
 * versioned slot-pick pattern in mq_timedsend / fds/pidfd.c) and plant
 * it into a2. Empty pool -> downgrade to P_ALL, which ignores a2, so
 * we never hand the kernel a random pid dressed up as a fd.
 */
static void arm_pidfd(struct syscallrecord *rec)
{
	struct object *obj;
	int i;

	for (i = 0; i < 16; i++) {
		obj = get_random_object(OBJ_FD_PIDFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_PIDFD))
			continue;
		if (obj->pidfdobj.fd < 0)
			continue;
		rec->a2 = (unsigned long) obj->pidfdobj.fd;
		return;
	}

	rec->a1 = P_ALL;
}

/*
 * Snapshot of the infop OUT-pointer arg captured at sanitise time and
 * consumed by post_waitid.  Lives in rec->post_state, a slot the
 * syscall ABI does not expose, so a sibling syscall scribbling rec->a3
 * between the syscall returning and the post handler running cannot
 * redirect the untouched-buffer check at a foreign user page.  A
 * poison_seed of 0 is the sanitise-refused-to-stamp signal (a3 == 0 --
 * ARG_ADDRESS is nullable) and the post handler must no-op the
 * untouched-buffer arm.  Only infop is poisoned: ru (a5, rusage) is
 * only filled when a child is actually reaped, so a survived poison
 * there after a WNOHANG-no-child success would false-positive.  infop
 * is different -- the kernel zeroes the siginfo on every retval==0
 * return, including WNOHANG with no matching child, so a survived
 * poison there after a zero return is an unambiguous skipped or
 * partial copy_to_user.
 */
#define WAITID_POST_STATE_MAGIC		0x57544944UL	/* "WTID" */
struct waitid_post_state {
	unsigned long magic;
	unsigned long infop;
	uint64_t poison_seed;
};

static void sanitise_waitid(struct syscallrecord *rec)
{
	struct waitid_post_state *snap;

	if (rec->a1 == P_PIDFD)
		arm_pidfd(rec);

	avoid_shared_buffer_out(&rec->a3, sizeof(siginfo_t));
	avoid_shared_buffer_out(&rec->a5, sizeof(struct rusage));

	/*
	 * Snapshot the infop OUT-pointer for the post oracle.  Without
	 * this the post handler reads rec->a3 at post-time, when a
	 * sibling syscall may have scribbled the slot -- the untouched-
	 * buffer memcmp would then run against a foreign allocation
	 * whose residual bytes happen to still carry the poison pattern.
	 * post_state is private to the post handler; post_state_install
	 * pairs the rec->post_state assign with the ownership-table
	 * register so the observable window between the two is closed,
	 * and post_waitid() gates through post_state_claim_owned() before
	 * touching any field.
	 *
	 * infop is ARG_ADDRESS: rec->a3 == 0 is a legitimate call that
	 * asks the kernel to skip the siginfo copy-out, and writing
	 * through NULL would SIGSEGV inside poison_output_struct.  Leave
	 * poison_seed at 0 in that case; the matching gate in the post
	 * handler suppresses the check.  Done after avoid_shared_buffer_
	 * out() so the poison lands on the final buffer the kernel will
	 * see (the relocation may have swapped rec->a3 for a fresh page).
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = WAITID_POST_STATE_MAGIC;
	snap->infop = rec->a3;
	if (rec->a3 != 0)
		snap->poison_seed =
			poison_output_struct((void *)(unsigned long) rec->a3,
					     sizeof(siginfo_t), 0);
	post_state_install(rec, snap);
}

/*
 * Kernel ABI: waitid() is RET_ZERO_SUCCESS -- it returns 0 on success
 * (with the reaped child's identity copied into *infop->si_pid, not the
 * retval) and -1 on failure.  Structurally distinct from waitpid/wait4,
 * which return the pid in retval.  Any retval other than 0 or -1 is a
 * kernel ABI regression.  Mirrors the strong-validator pattern from the
 * VAL11/VAL12 series.
 *
 * Second arm -- untouched-buffer oracle: sanitise stamps a per-call
 * poison pattern into the infop siginfo before the syscall runs.  On a
 * retval==0 return the kernel is contracted to copy a siginfo out --
 * it zeroes the struct even on WNOHANG with no matching child, so a
 * survived poison there is an unambiguous skipped or partial
 * copy_to_user (a torn write, a "return 0 before fill" early-exit, or
 * a mis-wired compat wrapper).  ru (a5) is deliberately NOT checked:
 * rusage is only filled when a child is actually reaped, so a survived
 * poison after a WNOHANG-no-child success is expected, not a bug.
 * Bumps the shared post_handler_untouched_out_buf counter; no re-issue,
 * no argument mutation.
 */
static void post_waitid(struct syscallrecord *rec)
{
	struct waitid_post_state *snap;
	long ret = (long) rec->retval;

	if (ret != 0 && ret != -1L) {
		output(0, "waitid oracle: retval %ld is invalid (must be 0 on success or -1 on failure)\n",
		       ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	snap = post_state_claim_owned(rec, WAITID_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (ret != 0)
		goto out_release;

	if (snap->poison_seed == 0)
		goto out_release;

	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->infop,
					     sizeof(siginfo_t),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_waitid = {
	.name = "waitid",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID, [2] = ARG_ADDRESS, [3] = ARG_LIST, [4] = ARG_ADDRESS },
	.argname = { [0] = "which", [1] = "upid", [2] = "infop", [3] = "options", [4] = "ru" },
	.arg_params[0].list = ARGLIST(waitid_which),
	.arg_params[3].list = ARGLIST(waitid_options),
	.sanitise = sanitise_waitid,
	.post = post_waitid,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
