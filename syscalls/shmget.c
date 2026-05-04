/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */

#include <limits.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL,
};

static void post_shmget(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	/* Ordinary error return: -1 with errno set. */
	if (ret < 0)
		return;

	/*
	 * shmget() returns either -1 or a non-negative int in
	 * 0..INT_MAX. The current call passes the full unsigned long
	 * straight into shmctl(), but the kernel-side syscall takes
	 * an int and truncates anything wider. A sibling op that
	 * scribbles pointer-shaped junk over rec->retval, or a torn
	 * read of a concurrent update, can therefore drive IPC_RMID
	 * against whatever real sysv-shm segment on the host happens
	 * to share the low 31 bits of the garbage.
	 */
	if (ret > INT_MAX) {
		output(0, "shmget oracle: returned IPC id 0x%lx out of "
			  "range (must be 0..INT_MAX)\n",
			  (unsigned long) rec->retval);
		(void) looks_like_corrupted_ptr(rec,
						(const void *) rec->retval);
		return;
	}

	shmctl((int) ret, IPC_RMID, NULL);
}

struct syscallentry syscall_shmget = {
	.name = "shmget",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "key", [1] = "size", [2] = "shmflg" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[2].list = ARGLIST(ipc_flags),
	.post = post_shmget,
};
