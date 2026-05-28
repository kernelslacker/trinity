/*
 * SYSCALL_DEFINE4(lsm_set_self_attr, unsigned int, attr,
 *		struct lsm_ctx __user *, ctx, u32, size, u32, flags)
 */
#include <string.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"

#ifndef LSM_ATTR_CURRENT
#define LSM_ATTR_CURRENT	100
#define LSM_ATTR_EXEC		101
#define LSM_ATTR_FSCREATE	102
#define LSM_ATTR_KEYCREATE	103
#define LSM_ATTR_PREV		104
#define LSM_ATTR_SOCKCREATE	105
#endif

/* LSM IDs from linux/lsm.h; guard in case system headers provide them. */
#ifndef LSM_ID_SELINUX
#define LSM_ID_SELINUX		101
#define LSM_ID_SMACK		102
#define LSM_ID_APPARMOR		104
#endif

#ifndef LSM_ID_LANDLOCK
#define LSM_ID_LANDLOCK		110
#endif

static unsigned long lsm_attrs[] = {
	LSM_ATTR_CURRENT, LSM_ATTR_EXEC, LSM_ATTR_FSCREATE,
	LSM_ATTR_KEYCREATE, LSM_ATTR_PREV, LSM_ATTR_SOCKCREATE,
};

/*
 * Minimal layout of struct lsm_ctx (linux/lsm.h). The kernel validates id,
 * then dispatches to the named LSM's ->setselfattr hook.
 */
struct trinity_lsm_ctx {
	u64 id;
	u64 flags;
	u64 len;
	u64 ctx_len;
	/* no variable-length ctx[] — we leave it empty */
};

static unsigned long lsm_ids[] = {
	LSM_ID_SELINUX, LSM_ID_SMACK, LSM_ID_APPARMOR, LSM_ID_LANDLOCK,
};

static void sanitise_lsm_set_self_attr(struct syscallrecord *rec)
{
	struct trinity_lsm_ctx *ctx;
	size_t alloc_sz = page_size + 64;
	unsigned long size;

	/*
	 * Allocate at the largest bucket size up front so the kernel reads
	 * for any chosen rec->a3 (up to PAGE_SIZE + 1) stay inside the
	 * allocation.
	 */
	ctx = (struct trinity_lsm_ctx *) get_writable_struct(alloc_sz);
	if (!ctx)
		return;
	memset(ctx, 0, alloc_sz);
	ctx->id = lsm_ids[rnd_modulo_u32(ARRAY_SIZE(lsm_ids))];
	ctx->len = sizeof(*ctx);
	size = sizeof(*ctx);

	/*
	 * Exercise the kernel's security_setselfattr() size-validation
	 * buckets: zero / undersized (size < sizeof(*lctx) EINVAL),
	 * oversized (size > PAGE_SIZE E2BIG), the variable-length payload
	 * arm (size > sizeof(*lctx) with ctx_len consumed), and the
	 * current-ABI success path.  Bias heavily toward the current size
	 * so most iterations still reach the hook-dispatch logic.
	 */
	if (ONE_IN(16)) {
		size = 0;
		ctx->len = 0;
	} else if (ONE_IN(16)) {
		size = sizeof(*ctx) / 2;
	} else if (ONE_IN(16)) {
		size = page_size + 1;
	} else if (ONE_IN(16)) {
		u32 payload_len = rnd_modulo_u32(64) + 1;

		size = sizeof(*ctx) + payload_len;
		ctx->len = size;
		ctx->ctx_len = payload_len;
	}

	rec->a2 = (unsigned long) ctx;
	avoid_shared_buffer_inout(&rec->a2, size);
	rec->a3 = size;
	rec->a4 = 0;	/* flags must be zero */
}

struct syscallentry syscall_lsm_set_self_attr = {
	.name = "lsm_set_self_attr",
	.num_args = 4,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "attr", [1] = "ctx", [2] = "size", [3] = "flags" },
	.arg_params[0].list = ARGLIST(lsm_attrs),
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_set_self_attr,
	.group = GROUP_PROCESS,
};
