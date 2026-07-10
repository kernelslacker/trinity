/*
 * SYSCALL_DEFINE1(io_destroy, aio_context_t, ctx)
 */
#include "objects.h"
#include "sanitise.h"

static void sanitise_io_destroy(struct syscallrecord *rec)
{
	unsigned long ctx;

	/*
	 * Precondition: ctx (a1) must be a live aio_context_t the kernel has
	 * on hand or io_destroy short-circuits with -EINVAL inside
	 * lookup_ioctx() before the kioctx teardown / free path runs.
	 * gen_arg_aio_ctx returns 0 (or 1/8 of the time a raw rand64) until
	 * a real io_setup has published into OBJ_AIO_CTX, so on the very
	 * first call in a child io_destroy never reaches the kernel's
	 * productive teardown path.
	 *
	 * io_destroy is seed-then-destroy: a successful call removes the
	 * ctx from the kernel's per-mm aio context table.  Seed ONLY when
	 * the pool is empty so we tear down a freshly minted ctx rather
	 * than draining a live ctx the gen_arg_aio_ctx rotation (and
	 * sibling io_submit / io_pgetevents / io_cancel calls) would still
	 * like to use.  When the pool is non-empty, leave rec->a1 to the
	 * generator -- it picks a real pool entry most of the time and
	 * still keeps the 1/8 raw rand64 path for -EINVAL coverage.
	 *
	 * The per-child OBJ_AIO_CTX destructor (aio_ctx_destructor in
	 * io_setup.c) calls real io_destroy(2) at child teardown and does
	 * not check the return value; a second io_destroy on an already-
	 * destroyed ctx returns -EINVAL from lookup_ioctx() with no
	 * double-free, so the freshly seeded-and-destroyed pool entry is
	 * safe to leave in place.
	 */
	if (objects_pool_empty(OBJ_LOCAL, OBJ_AIO_CTX) == false)
		return;

	ctx = seed_aio_ctx_if_empty();
	if (ctx != 0)
		rec->a1 = ctx;
}

struct syscallentry syscall_io_destroy = {
	.name = "io_destroy",
	.num_args = 1,
	.argtype = { [0] = ARG_AIO_CTX },
	.argname = { [0] = "ctx" },
	.group = GROUP_VFS,
	.sanitise = sanitise_io_destroy,
};
