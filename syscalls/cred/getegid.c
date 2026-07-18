/*
 * SYSCALL_DEFINE0(getegid)
 */
#include <sys/types.h>
#include "proc-status.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Oracle: getegid() and /proc/self/status's "Gid:" line (real, effective,
 * saved-set, fs) both derive from the same task cred but travel different
 * paths — getegid() is a thin syscall, procfs walks task_struct via
 * proc_pid_status() — so a divergence between the syscall return and the
 * procfs view of the same task is its own corruption shape.  Mirror of the
 * setgid procfs oracle, applied on the read side.
 */
static void post_getegid(struct syscallrecord *rec)
{
	unsigned long ids[4];
	gid_t got, proc_egid;
	unsigned long retval = rec->retval;

	/* Kernel ABI: getegid() is infallible — from_kgid_munged(current_user_ns(),
	 * current_egid()) cannot fail and the syscall return path has no error case.
	 * A retval of -1UL is a structural ABI violation (e.g. -errno leaking
	 * through the syscall return path), not a gid mismatch the procfs Gid:
	 * oracle would catch. */
	if (retval == -1UL) {
		output(0, "getegid oracle: returned gid -1UL is structurally invalid (infallible syscall)\n");
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	got = (gid_t) retval;

	if (!proc_status_read_id_quad("Gid", ids))
		return;
	proc_egid = (gid_t) ids[1];

	if (proc_egid != got) {
		output(0, "getegid oracle: getegid()=%u but "
		       "/proc/self/status Gid egid=%u\n",
		       got, proc_egid);
		__atomic_add_fetch(&shm->stats.oracle.getegid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getegid = {
	.name = "getegid",
	.num_args = 0,
	.rettype = RET_GID_T,
	.post = post_getegid,
	.group = GROUP_PROCESS,
};

/*
 * SYSCALL_DEFINE0(getegid16)
 */

struct syscallentry syscall_getegid16 = {
	.name = "getegid16",
	.num_args = 0,
	.rettype = RET_GID_T,
	.group = GROUP_PROCESS,
};
