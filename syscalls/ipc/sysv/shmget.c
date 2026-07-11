/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */

#include <limits.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "ipc-common.h"
#include "objects.h"
#include "prop_ring.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL, SHM_NORESERVE,
};

/*
 * OBJ_SYSV_SHM producer-pool wireup: producer-side cache of live SysV
 * shared memory ids returned by shmget.  Consumed by shmat/shmctl
 * argument generation so subsequent fuzzed calls hit ids the kernel
 * actually has on hand instead of dead-on-arrival random integers.
 * Lives in the per-child OBJ_LOCAL pool; the pool destructor calls
 * real shmctl(IPC_RMID) on shutdown so produced segments don't leak
 * past child lifetime.  Replaces a previous IPC_RMID-on-return shape
 * that prevented any pool-based tracking from being useful (sibling
 * consumers saw the id evaporate before they could touch it).
 *
 * The OBJ_GLOBAL OBJ_SYSV_SHM pool predates this and is populated by
 * create_sysv_shms() at startup with pre-attached segments used by
 * random-address.c for ARG_ADDRESS slots.  Both scopes coexist on the
 * same enum -- separate objhead instances per scope keep them
 * independent.  Wiring head->destroy on the OBJ_GLOBAL head also lets
 * destroy_global_objects() reclaim those startup segments at trinity
 * exit (previously leaked) since the destructor only needs the id,
 * which both scopes store at obj->sysv_shm.id.
 */
static void sysv_shm_destructor(struct object *obj)
{
	shmctl(obj->sysv_shm.id, IPC_RMID, NULL);
}

static void init_sysv_shm_pool(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_SYSV_SHM);
	if (head == NULL)
		return;

	/* Wire the destructor on the OBJ_GLOBAL head; child OBJ_LOCAL
	 * pools inherit it from here at child fork time
	 * (init_object_lists() copies destroy/dump from the GLOBAL head). */
	head->destroy = &sysv_shm_destructor;
}

REG_GLOBAL_OBJ(sysv_shm_pool, init_sysv_shm_pool);

void register_sysv_shm(int shmid)
{
	struct object *obj;

	if (shmid < 0)
		return;

	obj = alloc_object();
	obj->sysv_shm.id = shmid;
	add_object(obj, OBJ_LOCAL, OBJ_SYSV_SHM);
}

int get_random_sysv_shm(void)
{
	struct object *obj;

	/*
	 * Prefer a segment this child actually produced via shmget
	 * (OBJ_LOCAL); fall back to the create_sysv_shms() startup
	 * segments (OBJ_GLOBAL) when the per-child pool is empty.
	 *
	 * The previous gate -- objects_empty(OBJ_SYSV_SHM) -- only
	 * checks OBJ_GLOBAL and so is effectively never true once the
	 * startup pool has been populated, yet the subsequent draw
	 * read OBJ_LOCAL.  In a fresh child whose LOCAL pool was still
	 * empty the gate passed but the draw returned NULL, so this
	 * helper handed 0 to shmat/shmctl argument generation and the
	 * resulting calls EINVAL'd out despite live global segments
	 * being available the whole time.
	 */
	if (!objects_pool_empty(OBJ_LOCAL, OBJ_SYSV_SHM))
		obj = get_random_object(OBJ_SYSV_SHM, OBJ_LOCAL);
	else
		obj = get_random_object(OBJ_SYSV_SHM, OBJ_GLOBAL);

	if (obj == NULL)
		return 0;
	return obj->sysv_shm.id;
}

static void post_shmget(struct syscallrecord *rec)
{
	long shmid;

	post_ipc_get(rec, register_sysv_shm, "shmget");

	/* Mirror the shmid into the per-child prop_ring so the typed
	 * consumer in gen_arg_sysv_shm can prefer recently-returned ids
	 * over raw randoms / stale pool draws.  Re-check the success
	 * window post_ipc_get accepted (>= 0, <= INT_MAX) as defence in
	 * depth -- mirrors the OBJ_KEY_SERIAL exemplar in syscall.c
	 * which also re-validates before prop_ring_push_scalar despite
	 * register_key_serial having just gated the same range.  The
	 * filters inside prop_ring_push_filtered still reject pointer-
	 * shaped and fd-aliased values. */
	shmid = (long) rec->retval;
	if (shmid < 0 || shmid > INT_MAX)
		return;
	prop_ring_push_scalar(rec->nr, shmid, SCALAR_SYSV_SHM);
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
