/*
 * SYSCALL_DEFINE0(getgid)
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
	FILE *f;
	char line[128];
	gid_t got, proc_rgid = (gid_t)-1;
	unsigned int rgid, egid, sgid, fsgid;

	if (!ONE_IN(100))
		return;

	got = (gid_t) rec->retval;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Gid:", 4) == 0) {
			/* Gid: rgid egid sgid fsgid — getgid() returns rgid
			 * (real gid, first field), so compare against that. */
			if (sscanf(line + 4, "%u %u %u %u",
				   &rgid, &egid, &sgid, &fsgid) == 4)
				proc_rgid = rgid;
			break;
		}
	}
	fclose(f);

	if (proc_rgid == (gid_t)-1)
		return;

	if (proc_rgid != got) {
		output(0, "getgid oracle: getgid()=%u but "
		       "/proc/self/status Gid rgid=%u\n",
		       got, proc_rgid);
		__atomic_add_fetch(&shm->stats.getgid_oracle_anomalies, 1,
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
