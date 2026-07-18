/*
 * SYSCALL_DEFINE0(getgid)
 */
#include <sys/types.h>
#include "proc-status.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Oracle: getgid() returns the real gid (current_gid()), NOT the effective
 * gid — the kernel-side semantic is the FIRST field of /proc/self/status's
 * "Gid:" line (rgid egid sgid fsgid).  Both views derive from the same task
 * cred but travel different paths — getgid() is a thin syscall, procfs
 * walks task_struct via proc_pid_status() — so a divergence between the
 * syscall return and the procfs view of the same task is its own
 * corruption shape.  Mirror of the getuid procfs oracle, applied to the
 * real-gid side; comparing against egid here would false-positive on every
 * legitimate setresgid that diverges rgid from egid.
 */
static void post_getgid(struct syscallrecord *rec)
{
	unsigned long ids[4];
	gid_t got, proc_rgid;
	unsigned long retval = rec->retval;

	/* Kernel ABI: getgid() is infallible — from_kgid_munged(current_user_ns(),
	 * current_gid()) cannot fail and the syscall return path has no error case.
	 * A retval of -1UL is a structural ABI violation (e.g. -errno leaking
	 * through the syscall return path), not a gid mismatch the procfs Gid:
	 * oracle would catch. */
	if (retval == -1UL) {
		output(0, "getgid oracle: returned gid -1UL is structurally invalid (infallible syscall)\n");
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	got = (gid_t) retval;

	if (!proc_status_read_id_quad("Gid", ids))
		return;
	/* Gid: rgid egid sgid fsgid — getgid() returns rgid
	 * (real gid, first field), so compare against that. */
	proc_rgid = (gid_t) ids[0];

	if (proc_rgid != got) {
		output(0, "getgid oracle: getgid()=%u but "
		       "/proc/self/status Gid rgid=%u\n",
		       got, proc_rgid);
		__atomic_add_fetch(&shm->stats.oracle.getgid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getgid = {
	.name = "getgid",
	.num_args = 0,
	.rettype = RET_GID_T,
	.post = post_getgid,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE0(getgid)
 */

struct syscallentry syscall_getgid16 = {
	.name = "getgid16",
	.num_args = 0,
	.rettype = RET_GID_T,
	.group = GROUP_PROCESS,
};
