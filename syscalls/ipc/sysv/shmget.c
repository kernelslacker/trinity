/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */

#include <limits.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "child.h"
#include "ipc-common.h"
#include "objects.h"
#include "prop_ring.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "sysv-shm.h"
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
	struct childdata *child;
	struct object *obj;
	unsigned int n;

	if (shmid < 0)
		return;

	obj = alloc_object();
	obj->sysv_shm.id = shmid;
	add_object(obj, OBJ_LOCAL, OBJ_SYSV_SHM);

	/* Mirror the id into the (shared) childdata ring so the parent can RMID
	 * it at reap even if this child is SIGKILL'd before the OBJ_LOCAL
	 * destructor runs.  Ring full -> RMID the oldest to bound the live leak. */
	child = this_child();
	if (child == NULL)
		return;
	n = child->fuzz_shm_count;
	if (n >= MAX_FUZZ_SHM_IDS) {
		shmctl(child->fuzz_shm_ids[0], IPC_RMID, NULL);
		memmove(&child->fuzz_shm_ids[0], &child->fuzz_shm_ids[1],
			(MAX_FUZZ_SHM_IDS - 1) * sizeof(child->fuzz_shm_ids[0]));
		n = MAX_FUZZ_SHM_IDS - 1;
	}
	child->fuzz_shm_ids[n] = shmid;
	/* Release-store the count last so the parent's acquire-load at reap sees
	 * the id write above. */
	__atomic_store_n(&child->fuzz_shm_count, n + 1, __ATOMIC_RELEASE);
}

void reap_child_sysv_shm(struct childdata *child)
{
	unsigned int n, i;

	if (child == NULL)
		return;

	n = __atomic_load_n(&child->fuzz_shm_count, __ATOMIC_ACQUIRE);
	if (n > MAX_FUZZ_SHM_IDS)	/* guard a torn/garbage count */
		n = MAX_FUZZ_SHM_IDS;
	for (i = 0; i < n; i++)
		(void) shmctl(child->fuzz_shm_ids[i], IPC_RMID, NULL);
	child->fuzz_shm_count = 0;
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

/*
 * Cap the fuzzed segment size.  A SysV shm segment created by a child
 * that then dies on an uncatchable signal (watchdog / OOM kill / SIGSEGV)
 * never runs its OBJ_LOCAL RMID destructor, so it orphans with its
 * committed pages held until reaped.  An unbounded size lets a single
 * orphan balloon the shmem accounting and OOM the box; shmget fixes the
 * segment's maximum size, so clamping it here bounds every orphan.  Keep
 * a bucketed spread so the small / multi-page / near-cap regimes stay warm.
 */
#define SHMGET_MAX_SIZE (4UL * 1024 * 1024)

static size_t pick_shmget_size(void)
{
	uint32_t pick = rnd_modulo_u32(100);

	if (pick < 10)
		return 0;					/* get-existing / EINVAL edge */
	if (pick < 45)
		return 1 + rnd_modulo_u32(4096);		/* sub-page / small */
	if (pick < 80)
		return (size_t)(1 + rnd_modulo_u32(512)) * 4096; /* 4 KiB .. 2 MiB, THP-eligible */
	return 1 + rnd_modulo_u32(SHMGET_MAX_SIZE);		/* up to the cap */
}

static void sanitise_shmget(struct syscallrecord *rec)
{
	rec->a2 = pick_shmget_size();

	/*
	 * Clear SHM_HUGETLB from the fuzzed shmflg.  ipc_flags[] does not
	 * offer it, but handle_arg_list()'s shift_flag_bit() mutation lands
	 * IPC_EXCL << 1 and SHM_NORESERVE >> 1 both on SHM_HUGETLB (0x800),
	 * so a few percent of fuzzed shmget calls request it.  On a host
	 * whose default hugepage size is 1G the kernel then rounds the
	 * size-capped request up to a full 1G hugepage per segment, and a
	 * handful of those OOM a small box despite the 4MB size cap.
	 * Deliberate hugetlb coverage lives in create_sysv_shms(); the
	 * fuzzed direct-shmget path never intends it.  Clearing SHM_HUGETLB
	 * alone disables the hugepage path -- the kernel ignores SHM_HUGE_*
	 * size bits when SHM_HUGETLB is unset.
	 */
	rec->a3 &= ~(unsigned long) SHM_HUGETLB;
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
	.sanitise = sanitise_shmget,
};
