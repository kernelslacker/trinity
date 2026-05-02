/*
 * SYSCALL_DEFINE3(get_robust_list, int, pid,
	struct robust_list_head __user * __user *, head_ptr,
	size_t __user *, len_ptr)
 */
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_get_robust_list(struct syscallrecord *rec)
{
	/*
	 * The kernel writes a robust_list_head pointer through head_ptr (a2)
	 * and a size_t through len_ptr (a3).  Both args are
	 * ARG_NON_NULL_ADDRESS, so generic_sanitise sources them from the
	 * random pool with no overlap check against the alloc_shared regions.
	 */
	avoid_shared_buffer(&rec->a2, sizeof(void *));
	avoid_shared_buffer(&rec->a3, sizeof(size_t));
}

/*
 * Oracle: get_robust_list(pid, &head, &len) returns a snapshot of
 * current->robust_list and sizeof(*current->robust_list) for the target
 * task.  Both fields are set once via set_robust_list (called by glibc
 * pthread setup) and stay stable across the lifetime of the task, so
 * re-issuing the same query for self gives a second read of the same
 * field through the same code path — the two copies must agree unless
 * something in between either (a) had copy_to_user write past or before
 * one of the two output slots, (b) the 32-bit-on-64-bit compat copy_to_user
 * truncated the head pointer from 8 bytes to 4, (c) struct-layout mismatch
 * on 32-on-64 emulation landed sizeof(*current->robust_list) (24 on 64-bit,
 * 12 on 32-bit) into the head_ptr slot or vice versa, or (d) a sibling
 * thread scribbled the user receive buffers between syscall return and the
 * post-hook.
 *
 * Restrict to self (pid == 0 or pid == gettid()): cross-target sampling
 * races set_robust_list on the target task and tells us nothing.  Snapshot
 * both user buffers into stack-local copies first to defeat TOCTOU on the
 * user side — once they're on our stack a sibling thread cannot scribble
 * them underneath the comparison.  If the re-call returns nonzero (the
 * original syscall succeeded but the re-call hit a transient failure),
 * give up rather than report a false divergence.  Compare head and len
 * individually with no early-return so a multi-field corruption shows up
 * in a single sample, but bump the anomaly counter only once per sample.
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.
 *
 * Known benign sources of divergence (acceptable at the 1/100 sample
 * rate): the calling task itself calling set_robust_list between the two
 * reads (Trinity children don't, but it's worth noting), and a
 * get_robust_list issued from a thread that has not yet set its own
 * robust_list returns (head, len) = (NULL, 0); a sibling thread calling
 * set_robust_list on the target between the two reads would race —
 * mitigated by the self-target gate.
 */
static void post_get_robust_list(struct syscallrecord *rec)
{
	struct robust_list_head *user_head, *kernel_head;
	size_t user_len, kernel_len;
	int rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a2 == 0 || rec->a3 == 0)
		return;

	if ((pid_t) rec->a1 != 0 && (pid_t) rec->a1 != gettid())
		return;

	memcpy(&user_head, (void *)(unsigned long) rec->a2, sizeof(user_head));
	memcpy(&user_len,  (void *)(unsigned long) rec->a3, sizeof(user_len));

	rc = syscall(SYS_get_robust_list, 0, &kernel_head, &kernel_len);
	if (rc != 0)
		return;

	if (user_head != kernel_head || user_len != kernel_len) {
		output(0,
		       "[oracle:get_robust_list] head %p vs %p len %zu vs %zu\n",
		       user_head, kernel_head, user_len, kernel_len);
		__atomic_add_fetch(&shm->stats.get_robust_list_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_get_robust_list = {
	.name = "get_robust_list",
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "head_ptr", [2] = "len_ptr" },
	.sanitise = sanitise_get_robust_list,
	.post = post_get_robust_list,
	.group = GROUP_PROCESS,
};
