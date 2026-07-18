/*
 * SYSCALL_DEFINE1(setuid, uid_t, uid)
 */
#include <unistd.h>
#include <sys/types.h>
#include "proc-status.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: after a successful setuid(N), POSIX guarantees geteuid() == N
 * regardless of whether we had CAP_SETUID (root sets all three; non-root
 * sets only euid).  A divergence here would be a credential corruption
 * bug — exactly the silent privilege-escalation shape that doesn't crash.
 *
 * A second oracle re-reads the effective uid via /proc/self/status's
 * "Uid:" line (real, effective, saved-set, fs).  geteuid() and procfs
 * derive from the same task cred but travel different paths — geteuid()
 * is a thin syscall, procfs walks task_struct via the proc_pid_status()
 * formatter — so a divergence between the kernel's syscall return and
 * the procfs view of the same task is its own corruption shape.
 */
static void post_setuid(struct syscallrecord *rec)
{
	unsigned long ids[4];
	uid_t want, got;
	uid_t proc_euid;

	if ((long) rec->retval != 0)
		return;

	want = (uid_t) rec->a1;

	if (ONE_IN(20)) {
		got = geteuid();
		if (got != want) {
			output(0, "cred oracle: setuid(%u) succeeded but geteuid()=%u\n",
			       want, got);
			__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}

	if (!ONE_IN(100))
		return;

	if (!proc_status_read_id_quad("Uid", ids))
		return;
	proc_euid = (uid_t) ids[1];

	if (proc_euid != want) {
		output(0, "uid oracle: setuid(%u) succeeded but "
		       "/proc/self/status Uid euid=%u\n",
		       want, proc_euid);
		__atomic_add_fetch(&shm->stats.oracle.uid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setuid = {
	.name = "setuid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "uid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.post = post_setuid,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
};

/*
 * SYSCALL_DEFINE1(setuid16, old_uid_t, uid)
 */

struct syscallentry syscall_setuid16 = {
	.name = "setuid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "uid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
};
