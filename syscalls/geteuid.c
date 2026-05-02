/*
 * SYSCALL_DEFINE0(geteuid)
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: geteuid() returns the effective uid (current_euid()), so the
 * kernel-side semantic to compare against is the SECOND field of
 * /proc/self/status's "Uid:" line (ruid euid suid fsuid).  Both views
 * derive from the same task cred but travel different paths — geteuid()
 * is a thin syscall, procfs walks task_struct via proc_pid_status() — so
 * a divergence between the syscall return and the procfs view of the
 * same task is its own corruption shape.  Mirror of the getuid procfs
 * oracle, applied to the effective-uid side; comparing against ruid here
 * would false-positive on every legitimate setresuid that diverges ruid
 * from euid.
 */
static void post_geteuid(struct syscallrecord *rec)
{
	FILE *f;
	char line[128];
	uid_t got, proc_euid = (uid_t)-1;
	unsigned int ruid, euid, suid, fsuid;

	if (!ONE_IN(100))
		return;

	got = (uid_t) rec->retval;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			/* Uid: ruid euid suid fsuid — geteuid() returns euid
			 * (second field), so compare against that. */
			if (sscanf(line + 4, "%u %u %u %u",
				   &ruid, &euid, &suid, &fsuid) == 4)
				proc_euid = euid;
			break;
		}
	}
	fclose(f);

	if (proc_euid == (uid_t)-1)
		return;

	if (proc_euid != got) {
		output(0, "geteuid oracle: geteuid()=%u but "
		       "/proc/self/status Uid euid=%u\n",
		       got, proc_euid);
		__atomic_add_fetch(&shm->stats.geteuid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_geteuid = {
	.name = "geteuid",
	.num_args = 0,
	.rettype = RET_UID_T,
	.post = post_geteuid,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE0(geteuid16)
 */

struct syscallentry syscall_geteuid16 = {
	.name = "geteuid16",
	.num_args = 0,
	.rettype = RET_UID_T,
	.group = GROUP_PROCESS,
};
