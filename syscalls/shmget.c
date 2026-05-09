/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */

#include <limits.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL,
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

	if (objects_empty(OBJ_SYSV_SHM) == true)
		return 0;

	obj = get_random_object(OBJ_SYSV_SHM, OBJ_LOCAL);
	if (obj == NULL)
		return 0;
	return obj->sysv_shm.id;
}

static void post_shmget(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	/* Ordinary error return: -1 with errno set. */
	if (ret < 0)
		return;

	/*
	 * shmget() returns either -1 or a non-negative int in
	 * 0..INT_MAX. A retval that decodes outside that range is the
	 * footprint of a wild write into the syscallrecord retval slot
	 * (or a torn read of a concurrent update). The (int) cast below
	 * would silently truncate the garbage to a plausible 31-bit id
	 * and hand it to register_sysv_shm(), seeding the pool with a
	 * fabricated id that shmctl(IPC_RMID) at child teardown would
	 * then issue against whatever real sysv-shm segment on the host
	 * happens to share that id.
	 */
	if (ret > INT_MAX) {
		output(0, "shmget oracle: returned IPC id 0x%lx out of "
			  "range (must be 0..INT_MAX)\n",
			  (unsigned long) rec->retval);
		(void) looks_like_corrupted_ptr(rec,
						(const void *) rec->retval);
		return;
	}

	register_sysv_shm((int) ret);
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
