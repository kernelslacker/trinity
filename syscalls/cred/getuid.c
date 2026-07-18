/*
 * SYSCALL_DEFINE0(getuid)
 */
#include <sys/types.h>
#include "proc-status.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Oracle: getuid() returns the real uid (current_uid()), NOT the effective
 * uid — the kernel-side semantic is the FIRST field of /proc/self/status's
 * "Uid:" line (ruid euid suid fsuid).  Both views derive from the same task
 * cred but travel different paths — getuid() is a thin syscall, procfs
 * walks task_struct via proc_pid_status() — so a divergence between the
 * syscall return and the procfs view of the same task is its own
 * corruption shape.  Mirror of the getegid procfs oracle, applied to the
 * real-uid side; comparing against euid here would false-positive on every
 * legitimate setresuid that diverges ruid from euid.
 */
static void post_getuid(struct syscallrecord *rec)
{
	char buf[2048];
	const char *value;
	unsigned long uids[4];
	uid_t got, proc_ruid;
	unsigned long retval = rec->retval;

	/* Kernel ABI: getuid() is infallible — from_kuid_munged(current_user_ns(),
	 * current_uid()) cannot fail and the syscall return path has no error case.
	 * A retval of -1UL is a structural ABI violation (e.g. -errno leaking
	 * through the syscall return path), not a uid mismatch the procfs Uid:
	 * oracle would catch. */
	if (retval == -1UL) {
		output(0, "getuid oracle: returned uid -1UL is structurally invalid (infallible syscall)\n");
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	got = (uid_t) retval;

	if (proc_status_read(buf, sizeof(buf)) < 0)
		return;
	value = proc_status_find_field(buf, "Uid");
	if (value == NULL)
		return;
	/* Uid: ruid euid suid fsuid — getuid() returns ruid (first field). */
	if (!proc_status_parse_uid_gid_quad(value, uids))
		return;
	proc_ruid = (uid_t)uids[0];

	if (proc_ruid != got) {
		output(0, "getuid oracle: getuid()=%u but "
		       "/proc/self/status Uid ruid=%u\n",
		       got, proc_ruid);
		__atomic_add_fetch(&shm->stats.oracle.getuid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getuid = {
	.name = "getuid",
	.num_args = 0,
	.rettype = RET_UID_T,
	.post = post_getuid,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE0(getuid16)
 */

struct syscallentry syscall_getuid16 = {
	.name = "getuid16",
	.num_args = 0,
	.rettype = RET_UID_T,
	.group = GROUP_PROCESS,
};
