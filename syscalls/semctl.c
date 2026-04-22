/*
 * SYSCALL_DEFINE(semctl)(int semid, int semnum, int cmd, union semun arg)
 */
#include <sys/ipc.h>
#include <sys/sem.h>
#include "arch.h"
#include "sanitise.h"

static unsigned long semctl_cmds[] = {
	IPC_RMID, IPC_SET, IPC_STAT, IPC_INFO,
	GETPID, GETVAL, GETALL, GETNCNT, GETZCNT,
	SETVAL, SETALL,
	SEM_STAT, SEM_INFO, SEM_STAT_ANY,
};

static void sanitise_semctl(struct syscallrecord *rec)
{
	/*
	 * arg (a4) is a union semun.  For the read-side commands the
	 * relevant field is a pointer the kernel writes into:
	 *   IPC_STAT / SEM_STAT / SEM_STAT_ANY -> struct semid_ds
	 *   IPC_INFO / SEM_INFO                -> struct seminfo
	 *   GETALL                             -> unsigned short array
	 * The ARG_ADDRESS slot drops a random-pool pointer in here for all
	 * commands; for the write-side ones the redirect is a no-op cost,
	 * for the read-side ones it stops a fuzzed pointer landing inside
	 * an alloc_shared region.  page_size is the conservative upper
	 * bound across all the variants.
	 */
	avoid_shared_buffer(&rec->a4, page_size);
}

struct syscallentry syscall_semctl = {
	.name = "semctl",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_OP, [3] = ARG_ADDRESS },
	.argname = { [0] = "semid", [1] = "semnum", [2] = "cmd", [3] = "arg" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 250,
	.arg_params[2].list = ARGLIST(semctl_cmds),
	.sanitise = sanitise_semctl,
};
