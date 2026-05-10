/*
 * SYSCALL_DEFINE0(getegid)
 */
#include <fcntl.h>
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
 * Oracle: getegid() and /proc/self/status's "Gid:" line (real, effective,
 * saved-set, fs) both derive from the same task cred but travel different
 * paths — getegid() is a thin syscall, procfs walks task_struct via
 * proc_pid_status() — so a divergence between the syscall return and the
 * procfs view of the same task is its own corruption shape.  Mirror of the
 * setgid procfs oracle, applied on the read side.
 */
static void post_getegid(struct syscallrecord *rec)
{
	char buf[2048];
	char *line;
	ssize_t n;
	int fd;
	gid_t got, proc_egid = (gid_t)-1;
	unsigned int rgid, egid, sgid, fsgid;

	/* Kernel ABI: getegid() is infallible — from_kgid_munged(current_user_ns(),
	 * current_egid()) cannot fail and the syscall return path has no error case.
	 * A retval of -1UL is a structural ABI violation (e.g. -errno leaking
	 * through the syscall return path), not a gid mismatch the procfs Gid:
	 * oracle would catch. */
	if (rec->retval == -1UL) {
		output(0, "getegid oracle: returned gid -1UL is structurally invalid (infallible syscall)\n");
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	got = (gid_t) rec->retval;

	/* Raw open/read instead of fopen/fgets/fclose: this post handler runs
	 * thousands of times per second under fuzz, and stdio's per-call malloc
	 * of FILE struct + IO buffer is heap traffic we don't need. */
	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';
	/* Anchor on a newline so a "Gid:" substring inside an earlier field
	 * (e.g. a process name) cannot mis-target the parse. */
	line = strstr(buf, "\nGid:");
	if (line != NULL) {
		if (sscanf(line + 5, "%u %u %u %u",
			   &rgid, &egid, &sgid, &fsgid) == 4)
			proc_egid = egid;
	}

	if (proc_egid == (gid_t)-1)
		return;

	if (proc_egid != got) {
		output(0, "getegid oracle: getegid()=%u but "
		       "/proc/self/status Gid egid=%u\n",
		       got, proc_egid);
		__atomic_add_fetch(&shm->stats.getegid_oracle_anomalies, 1,
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
