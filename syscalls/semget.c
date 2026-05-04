/*
 * SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
 */
#include <limits.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL,
};

static void post_semget(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	/* Ordinary error return: -1 with errno set. */
	if (ret < 0)
		return;

	/*
	 * semget() returns either -1 or a non-negative int in
	 * 0..INT_MAX. A retval that decodes outside that range is the
	 * footprint of a wild write into the syscallrecord retval slot
	 * (or a torn read of a concurrent update). The (int) cast at
	 * the bottom of this function would silently truncate the
	 * garbage to a plausible 31-bit id and hand it to
	 * semctl(IPC_RMID), removing whatever unrelated sysv-sem
	 * object on the host happens to share that id.
	 */
	if (ret > INT_MAX) {
		output(0, "semget oracle: returned IPC id 0x%lx out of "
			  "range (must be 0..INT_MAX)\n",
			  (unsigned long) rec->retval);
		(void) looks_like_corrupted_ptr(rec,
						(const void *) rec->retval);
		return;
	}

	semctl((int) ret, 0, IPC_RMID);
}

struct syscallentry syscall_semget = {
	.name = "semget",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_LIST },
	.argname = { [0] = "key", [1] = "nsems", [2] = "semflg" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 250,
	.arg_params[2].list = ARGLIST(ipc_flags),
	.post = post_semget,
};
