/*
 * SYSCALL_DEFINE1(setgid, gid_t, gid)
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
 * Oracle: a successful setgid(N) must leave getegid() == N.  Mirror of the
 * setuid oracle for the gid side; same silent-corruption rationale.
 *
 * A second oracle re-reads the effective gid via /proc/self/status's
 * "Gid:" line (real, effective, saved-set, fs).  getegid() and procfs
 * derive from the same task cred but travel different paths — getegid()
 * is a thin syscall, procfs walks task_struct via the proc_pid_status()
 * formatter — so a divergence between the kernel's syscall return and
 * the procfs view of the same task is its own corruption shape.
 */
static void post_setgid(struct syscallrecord *rec)
{
	FILE *f;
	char line[128];
	gid_t want, got;
	gid_t proc_egid = (gid_t)-1;
	unsigned int rgid, egid, sgid, fsgid;

	if ((long) rec->retval != 0)
		return;

	want = (gid_t) rec->a1;

	if (ONE_IN(20)) {
		got = getegid();
		if (got != want) {
			output(0, "cred oracle: setgid(%u) succeeded but getegid()=%u\n",
			       want, got);
			__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}

	if (!ONE_IN(100))
		return;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line + 4, "%u %u %u %u",
				   &rgid, &egid, &sgid, &fsgid) == 4)
				proc_egid = egid;
			break;
		}
	}
	fclose(f);

	if (proc_egid == (gid_t)-1)
		return;

	if (proc_egid != want) {
		output(0, "gid oracle: setgid(%u) succeeded but "
		       "/proc/self/status Gid egid=%u\n",
		       want, proc_egid);
		__atomic_add_fetch(&shm->stats.gid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setgid = {
	.name = "setgid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.post = post_setgid,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE1(setgid16, old_gid_t, gid)
 */

struct syscallentry syscall_setgid16 = {
	.name = "setgid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.group = GROUP_PROCESS,
};
