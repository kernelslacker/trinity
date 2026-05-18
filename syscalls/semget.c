/*
 * SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
 */
#include <limits.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "objects.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL,
};

/*
 * OBJ_SYSV_SEM pool: producer-side cache of live SysV semaphore set
 * ids returned by semget.  Consumed by semctl/semop/semtimedop
 * argument generation so subsequent fuzzed calls hit ids the kernel
 * actually has on hand instead of dead-on-arrival random integers.
 * Lives in the per-child OBJ_LOCAL pool; the pool destructor calls
 * real semctl(IPC_RMID) on shutdown so produced sem sets don't leak
 * past child lifetime.  Replaces a previous IPC_RMID-on-return shape
 * that prevented any pool-based tracking from being useful (sibling
 * consumers saw the id evaporate before they could touch it).
 */
static void sysv_sem_destructor(struct object *obj)
{
	semctl(obj->sysvsemobj.semid, 0, IPC_RMID);
}

static void init_sysv_sem_pool(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_SYSV_SEM);
	if (head == NULL)
		return;

	/* Wire the destructor on the OBJ_GLOBAL head; child OBJ_LOCAL
	 * pools inherit it from here at child fork time
	 * (init_object_lists() copies destroy/dump from the GLOBAL head). */
	head->destroy = &sysv_sem_destructor;
}

REG_GLOBAL_OBJ(sysv_sem, init_sysv_sem_pool);

void register_sysv_sem(int semid)
{
	struct object *obj;

	if (semid < 0)
		return;

	obj = alloc_object();
	obj->sysvsemobj.semid = semid;
	add_object(obj, OBJ_LOCAL, OBJ_SYSV_SEM);
}

int get_random_sysv_sem(void)
{
	struct object *obj;

	if (objects_empty(OBJ_SYSV_SEM) == true)
		return 0;

	obj = get_random_object(OBJ_SYSV_SEM, OBJ_LOCAL);
	if (obj == NULL)
		return 0;
	return obj->sysvsemobj.semid;
}

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
	 * (or a torn read of a concurrent update). The (int) cast below
	 * would silently truncate the garbage to a plausible 31-bit id
	 * and hand it to register_sysv_sem(), seeding the pool with a
	 * fabricated id that semctl(IPC_RMID) at child teardown would
	 * then issue against whatever unrelated sysv-sem object on the
	 * host happens to share that id.
	 */
	if (ret > INT_MAX) {
		output(0, "semget oracle: returned IPC id 0x%lx out of "
			  "range (must be 0..INT_MAX)\n",
			  (unsigned long) rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	register_sysv_sem((int) ret);
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
