/*
 * SYSCALL_DEFINE0(getuid)
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
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
	FILE *f;
	char line[128];
	uid_t got, proc_ruid = (uid_t)-1;
	unsigned int ruid, euid, suid, fsuid;

	/* Kernel ABI: getuid() is infallible — from_kuid_munged(current_user_ns(),
	 * current_uid()) cannot fail and the syscall return path has no error case.
	 * A retval of -1UL is a structural ABI violation (e.g. -errno leaking
	 * through the syscall return path), not a uid mismatch the procfs Uid:
	 * oracle would catch. */
	if (rec->retval == -1UL) {
		output(0, "getuid oracle: returned uid -1UL is structurally invalid (infallible syscall)\n");
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	got = (uid_t) rec->retval;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			/* Uid: ruid euid suid fsuid — getuid() returns ruid
			 * (first field), so compare against that. */
			if (sscanf(line + 4, "%u %u %u %u",
				   &ruid, &euid, &suid, &fsuid) == 4)
				proc_ruid = ruid;
			break;
		}
	}
	fclose(f);

	if (proc_ruid == (uid_t)-1)
		return;

	if (proc_ruid != got) {
		output(0, "getuid oracle: getuid()=%u but "
		       "/proc/self/status Uid ruid=%u\n",
		       got, proc_ruid);
		__atomic_add_fetch(&shm->stats.getuid_oracle_anomalies, 1,
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
