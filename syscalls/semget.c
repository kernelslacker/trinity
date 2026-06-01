/*
 * SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
 */
#include <sys/ipc.h>
#include <sys/sem.h>
#include "ipc-common.h"
#include "objects.h"
#include "publish_resource.h"
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
	if (semid < 0)
		return;

	publish_resource(OBJ_SYSV_SEM, (unsigned long)semid, NULL);
}

int get_random_sysv_sem(void)
{
	struct object *obj;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_SYSV_SEM) == true)
		return 0;

	obj = get_random_object(OBJ_SYSV_SEM, OBJ_LOCAL);
	if (obj == NULL)
		return 0;
	return obj->sysvsemobj.semid;
}

static void post_semget(struct syscallrecord *rec)
{
	post_ipc_get(rec, register_sysv_sem, "semget");
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
