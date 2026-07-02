/*
 * SYSCALL_DEFINE2(pkey_alloc, unsigned long, flags, unsigned long, init_val)
 */

#include <sys/syscall.h>
#include <unistd.h>

#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#define PKEY_DISABLE_ACCESS     0x1
#define PKEY_DISABLE_WRITE      0x2
#ifdef __aarch64__
#define PKEY_DISABLE_EXECUTE    0x4
#define PKEY_DISABLE_READ       0x8
#endif
/* PKEY_UNRESTRICTED added in Linux v6.15 (asm-generic/mman-common.h). */
#ifndef PKEY_UNRESTRICTED
#define PKEY_UNRESTRICTED       0x0
#endif

static unsigned long pkey_alloc_initvals[] = {
	PKEY_UNRESTRICTED,
	PKEY_DISABLE_ACCESS,
	PKEY_DISABLE_WRITE,
#ifdef __aarch64__
	PKEY_DISABLE_EXECUTE,
	PKEY_DISABLE_READ,
#endif
};

/*
 * OBJ_PKEY pool: producer-side cache of live pkey ids returned by
 * pkey_alloc().  Consumed by sanitise_mprotect()'s pkey_mprotect branch
 * via get_random_pkey_id() so the fourth argument lands on a key the
 * kernel actually has allocated for this mm instead of a random 4-bit
 * integer that the kernel's unknown-key reject path EINVALs ~94% of
 * the time.  Mirrors the OBJ_KEY_SERIAL pool shape (syscalls/keyctl.c)
 * — the destructor calls pkey_free() on teardown so produced keys
 * don't leak past child lifetime.
 */
static void pkey_destructor(struct object *obj)
{
	syscall(SYS_pkey_free, obj->pkey_obj.id);
}

static void init_pkey_pool(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_PKEY);
	if (head == NULL)
		return;

	/* Wire the destructor on the OBJ_GLOBAL head; child OBJ_LOCAL
	 * pools inherit it from here at child fork time
	 * (init_object_lists() copies destroy/dump from the GLOBAL head). */
	head->destroy = &pkey_destructor;
}

REG_GLOBAL_OBJ(pkey, init_pkey_pool);

void register_pkey_obj(int id)
{
	if (id < 0 || id > 15)
		return;

	publish_resource(OBJ_PKEY, (unsigned long)id, NULL);
}

int get_random_pkey_id(void)
{
	struct object *obj;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_PKEY) == true)
		return -1;

	obj = get_random_object(OBJ_PKEY, OBJ_LOCAL);
	if (obj == NULL)
		return -1;
	return obj->pkey_obj.id;
}

static void sanitise_pkey_alloc(struct syscallrecord *rec)
{
	/*
	 * pkey_alloc accepts a flags argument whose only currently-legal
	 * value is 0 (PKEY_UNRESTRICTED).  The PKEY_DISABLE_ACCESS /
	 * PKEY_DISABLE_WRITE bits are init_val (rec->a2) selectors, not
	 * flags — they live in a separate namespace despite the shared
	 * name prefix.  Force rec->a1 = 0 so the call exercises the
	 * success path; the ARG_LIST on init_val keeps a2 fuzzed across
	 * the unrestricted/disable-access/disable-write triplet.
	 */
	rec->a1 = 0;
}

/*
 * sys_pkey_alloc returns a pkey id allocated from the per-mm pkey
 * bitmap. On x86 the hardware PKRU register has 16 slots, so
 * arch_max_pkey() returns 16 and mm_pkey_alloc() can only hand back
 * an id in [0, 15]. Failure paths return negative errno (-EINVAL for
 * unsupported flags or init_val bits, -ENOSPC when the bitmap is
 * exhausted, -ENOTSUP under arch_set_user_pkey_access()), all of
 * which the syscall return path collapses to retval=-1UL with errno
 * set. A retval outside [0, 15] U {-1UL} is therefore a structural
 * ABI violation: a sign-extension at the syscall boundary, a
 * 32-on-64 compat tear, or a sibling thread scribbling the return
 * slot between syscall return and post-hook entry.
 *
 * On a successful return publish the id into the OBJ_PKEY pool so
 * sanitise_mprotect()'s pkey_mprotect branch can consume it.  The
 * pool destructor calls pkey_free() on teardown.
 */
static void post_pkey_alloc(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || ret > 15) {
		outputerr("post_pkey_alloc: rejected retval 0x%lx outside [0, 15] (and not -1)\n",
		          (unsigned long) ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	register_pkey_obj((int) ret);
}

struct syscallentry syscall_pkey_alloc = {
	.name = "pkey_alloc",
	.num_args = 2,
	.argtype = { [1] = ARG_LIST },
	.argname = { [0] = "flags", [1] = "init_val" },
	.arg_params[1].list = ARGLIST(pkey_alloc_initvals),
	.sanitise = sanitise_pkey_alloc,
	.post = post_pkey_alloc,
	.group = GROUP_VM,
	.rettype = RET_BORING,
};

/*
 * pkey_free's key argument is a pkey id previously returned by
 * pkey_alloc().  The ARG_RANGE fuzz over [0, 15] rarely names a live
 * key — the kernel's unknown-key reject path collapses the call to
 * EINVAL, so the actual free path stays under-exercised.  Pull from
 * the OBJ_PKEY pool (populated by post_pkey_alloc()) 60% of the time
 * when the pool is non-empty so the call lands on a live key.  The
 * remaining 40% (and the empty-pool fallback) stay in the ARG_RANGE
 * draw so the unknown-key reject path keeps getting coverage.
 * Mirrors the consume shape used by sanitise_mprotect()'s
 * pkey_mprotect branch.
 */
static void sanitise_pkey_free(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(100) < 60) {
		int id = get_random_pkey_id();

		if (id >= 0)
			rec->a1 = (unsigned long) id;
	}
}

struct syscallentry syscall_pkey_free = {
	.name = "pkey_free",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "key" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 15,
	.sanitise = sanitise_pkey_free,
	.group = GROUP_VM,
	.rettype = RET_ZERO_SUCCESS,
};
