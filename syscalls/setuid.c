/*
 * SYSCALL_DEFINE1(setuid, uid_t, uid)
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
	FILE *f;
	char line[128];
	uid_t want, got;
	uid_t proc_euid = (uid_t)-1;
	unsigned int ruid, euid, suid, fsuid;

	if ((long) rec->retval != 0)
		return;

	want = (uid_t) rec->a1;

	if (ONE_IN(20)) {
		got = geteuid();
		if (got != want) {
			output(0, "cred oracle: setuid(%u) succeeded but geteuid()=%u\n",
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
		if (strncmp(line, "Uid:", 4) == 0) {
			if (sscanf(line + 4, "%u %u %u %u",
				   &ruid, &euid, &suid, &fsuid) == 4)
				proc_euid = euid;
			break;
		}
	}
	fclose(f);

	if (proc_euid == (uid_t)-1)
		return;

	if (proc_euid != want) {
		output(0, "uid oracle: setuid(%u) succeeded but "
		       "/proc/self/status Uid euid=%u\n",
		       want, proc_euid);
		__atomic_add_fetch(&shm->stats.uid_oracle_anomalies, 1,
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
};
