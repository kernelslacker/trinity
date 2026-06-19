/*
 * SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
 */
#include <limits.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "ipc-common.h"
#include "objects.h"
#include "prop_ring.h"
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

/*
 * Absolute ceiling for nsems.  newary() in the kernel allocates per
 * sem_undo / sem_array storage proportional to nsems before any other
 * gating, so a near-SEMMSL set (SEMMSL == 32000) reliably trips the
 * cgroup OOM-killer.  The .argtype = ARG_RANGE generator already biases
 * toward small values (range.hi = 250), but corpus replay and bit-level
 * mutation can hand us a value far above range.hi after the fact (an
 * OOM'd run was observed at nsems=0x75c0 = 30144).  Clamp at call time
 * so the cap holds for both the initial generator and any post-mutation
 * value handed to the syscall.  256 keeps the allocation path live for
 * coverage without ever approaching SEMMSL.  Values <= cap (including
 * 0 and negatives) are left intact so error-path returns still appear.
 */
#define SEMGET_NSEMS_CAP 256

static void sanitise_semget(struct syscallrecord *rec)
{
	if ((long) rec->a2 > SEMGET_NSEMS_CAP)
		rec->a2 = SEMGET_NSEMS_CAP;
}

static void post_semget(struct syscallrecord *rec)
{
	long semid;

	post_ipc_get(rec, register_sysv_sem, "semget");

	/* Mirror the semid into the per-child prop_ring so the typed
	 * consumer in gen_arg_sem_id can prefer recently-returned ids
	 * over raw randoms / stale pool draws.  Re-check the success
	 * window post_ipc_get accepted (>= 0, <= INT_MAX) as defence in
	 * depth -- mirrors the OBJ_KEY_SERIAL exemplar in syscall.c
	 * which also re-validates before prop_ring_push_scalar despite
	 * register_key_serial having just gated the same range.  The
	 * filters inside prop_ring_push_filtered still reject pointer-
	 * shaped and fd-aliased values. */
	semid = (long) rec->retval;
	if (semid < 0 || semid > INT_MAX)
		return;
	prop_ring_push_scalar(rec->nr, semid, SCALAR_SYSV_SEM);
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
	.sanitise = sanitise_semget,
	.post = post_semget,
};
