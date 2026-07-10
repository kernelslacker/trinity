/*
 *   SYSCALL_DEFINE2(io_uring_setup, u32, entries, struct io_uring_params __user *, params)
 */
#include <linux/types.h>
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifndef IORING_SETUP_IOPOLL
#define IORING_SETUP_IOPOLL		(1U << 0)
#define IORING_SETUP_SQPOLL		(1U << 1)
#define IORING_SETUP_SQ_AFF		(1U << 2)
#define IORING_SETUP_CQSIZE		(1U << 3)
#define IORING_SETUP_CLAMP		(1U << 4)
#define IORING_SETUP_ATTACH_WQ		(1U << 5)
#define IORING_SETUP_R_DISABLED		(1U << 6)
#endif
#ifndef IORING_SETUP_SUBMIT_ALL
#define IORING_SETUP_SUBMIT_ALL		(1U << 7)
#define IORING_SETUP_COOP_TASKRUN	(1U << 8)
#define IORING_SETUP_TASKRUN_FLAG	(1U << 9)
#define IORING_SETUP_SQE128		(1U << 10)
#define IORING_SETUP_CQE32		(1U << 11)
#endif
#ifndef IORING_SETUP_SINGLE_ISSUER
#define IORING_SETUP_SINGLE_ISSUER	(1U << 12)
#define IORING_SETUP_DEFER_TASKRUN	(1U << 13)
#endif
#ifndef IORING_SETUP_NO_MMAP
#define IORING_SETUP_NO_MMAP		(1U << 14)
#define IORING_SETUP_REGISTERED_FD_ONLY	(1U << 15)
#endif
#ifndef IORING_SETUP_NO_SQARRAY
#define IORING_SETUP_NO_SQARRAY		(1U << 16)
#endif
#ifndef IORING_SETUP_HYBRID_IOPOLL
#define IORING_SETUP_HYBRID_IOPOLL	(1U << 17)
#endif
#ifndef IORING_SETUP_CQE_MIXED
#define IORING_SETUP_CQE_MIXED		(1U << 18)
#endif
#ifndef IORING_SETUP_SQE_MIXED
#define IORING_SETUP_SQE_MIXED		(1U << 19)
#endif
#ifndef IORING_SETUP_SQ_REWIND
#define IORING_SETUP_SQ_REWIND		(1U << 20)
#endif

static unsigned long io_uring_setup_flags[] = {
	IORING_SETUP_IOPOLL, IORING_SETUP_SQPOLL,
	IORING_SETUP_SQ_AFF, IORING_SETUP_CQSIZE,
	IORING_SETUP_CLAMP, IORING_SETUP_ATTACH_WQ,
	IORING_SETUP_R_DISABLED, IORING_SETUP_SUBMIT_ALL,
	IORING_SETUP_COOP_TASKRUN, IORING_SETUP_TASKRUN_FLAG,
	IORING_SETUP_SQE128, IORING_SETUP_CQE32,
	IORING_SETUP_SINGLE_ISSUER, IORING_SETUP_DEFER_TASKRUN,
	IORING_SETUP_NO_MMAP, IORING_SETUP_REGISTERED_FD_ONLY,
	IORING_SETUP_NO_SQARRAY, IORING_SETUP_HYBRID_IOPOLL,
	IORING_SETUP_CQE_MIXED, IORING_SETUP_SQE_MIXED,
	IORING_SETUP_SQ_REWIND,
};

/*
 * Pre-curated kernel-accepted flag combinations.  Uniform-bitmask sampling
 * across io_uring_setup_flags[] (21 entries, 2^21 combos) almost always
 * trips a flag-dependency reject in io_uring_create / io_validate_ext_arg
 * before reaching io_allocate_scq_urings, the productive setup path:
 * SQ_AFF requires SQPOLL, DEFER_TASKRUN requires SINGLE_ISSUER, HYBRID_IOPOLL
 * requires IOPOLL, TASKRUN_FLAG conflicts with COOP_TASKRUN, NO_MMAP requires
 * user-supplied SQ/CQ ring addresses we don't pass, and REGISTERED_FD_ONLY
 * requires NO_MMAP.  Enumerate the combos the validator accepts so most
 * dispatches reach the ring-allocation path instead of -EINVAL'ing early.
 */
static const unsigned long io_uring_setup_valid_combos[] = {
	IORING_SETUP_CLAMP,
	IORING_SETUP_CQSIZE,
	IORING_SETUP_SUBMIT_ALL,
	IORING_SETUP_COOP_TASKRUN,
	IORING_SETUP_TASKRUN_FLAG,
	IORING_SETUP_SQE128,
	IORING_SETUP_CQE32,
	IORING_SETUP_SINGLE_ISSUER,
	IORING_SETUP_R_DISABLED,
	IORING_SETUP_NO_SQARRAY,
	IORING_SETUP_SQPOLL,
	IORING_SETUP_IOPOLL,
	IORING_SETUP_ATTACH_WQ,
	IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF,
	IORING_SETUP_IOPOLL | IORING_SETUP_HYBRID_IOPOLL,
	IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
	IORING_SETUP_CLAMP | IORING_SETUP_CQSIZE,
	IORING_SETUP_CLAMP | IORING_SETUP_SUBMIT_ALL,
	IORING_SETUP_SQE128 | IORING_SETUP_CQE32 | IORING_SETUP_SUBMIT_ALL,
	IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN,
	IORING_SETUP_R_DISABLED | IORING_SETUP_SINGLE_ISSUER,
};

/*
 * Stratified flag picker.  Bias toward kernel-accepted combinations so most
 * dispatches reach io_allocate_scq_urings rather than bouncing at the
 * flag-dependency validator:
 *   25%  vanilla (flags = 0) -- always accepted
 *   60%  pre-curated valid combinations from io_uring_setup_valid_combos[]
 *   15%  random bitmask via set_rand_bitmask() -- exercise the validator's
 *        reject paths so the strict-checking edges still get coverage
 */
static unsigned long pick_io_uring_setup_flags(void)
{
	unsigned int r = rnd_modulo_u32(100);

	if (r < 25)
		return 0;
	if (r < 85)
		return io_uring_setup_valid_combos[rnd_modulo_u32(ARRAY_SIZE(io_uring_setup_valid_combos))];
	return set_rand_bitmask(ARRAY_SIZE(io_uring_setup_flags), io_uring_setup_flags);
}

/*
 * struct io_uring_params is defined in <linux/io_uring.h> but we only
 * need the flags field at offset 0x0c and cq_entries at offset 0x08.
 * Use the kernel header if available, otherwise define a minimal version.
 */
#ifndef IORING_FEAT_SINGLE_MMAP
struct io_uring_params {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u32 sq_thread_cpu;
	__u32 sq_thread_idle;
	__u32 features;
	__u32 wq_fd;
	__u32 resv[3];
	/* sq_off and cq_off follow but are output-only */
};
#endif

static void sanitise_io_uring_setup(struct syscallrecord *rec)
{
	struct io_uring_params *params;

	rec->a1 = RAND_RANGE(1, 4096);

	params = zmalloc_tracked(sizeof(struct io_uring_params));
	params->flags = pick_io_uring_setup_flags();
	if (params->flags & IORING_SETUP_CQSIZE)
		params->cq_entries = RAND_RANGE(1, 4096);
	if (params->flags & IORING_SETUP_SQ_AFF)
		params->sq_thread_cpu = rnd_modulo_u32(64);
	if (params->flags & IORING_SETUP_SQPOLL)
		params->sq_thread_idle = RAND_RANGE(100, 10000);
	if (params->flags & IORING_SETUP_ATTACH_WQ) {
		/*
		 * ATTACH_WQ requires wq_fd to name a live io_uring fd so
		 * io_attach_wq_fd reaches io_uring_attach_wq -- without it
		 * fdget(wq_fd) returns NULL and the setup -EINVALs before
		 * io_allocate_scq_urings.  Pull from the pre-fork ring pool
		 * 75% of the time; the rest of the time inject a random fd
		 * (or (unsigned)-1 if the pool is empty) so the validator's
		 * "wrong fd type / closed fd" reject paths still get coverage.
		 */
		struct io_uringobj *src = get_io_uring_ring();
		if (src != NULL && rnd_modulo_u32(4) != 0)
			params->wq_fd = (unsigned int) src->fd;
		else
			params->wq_fd = (unsigned int) -1;
	}

	rec->a2 = (unsigned long) params;

	avoid_shared_buffer_inout(&rec->a2, sizeof(struct io_uring_params));

	/*
	 * Stash the canonical params pointer in rec->post_state so the
	 * .cleanup hook can free it independent of whether .post ran (the
	 * retfd_rejected / rzs_rejected gates in handle_syscall_ret() skip
	 * .post entirely; .cleanup is unconditional).  post_state is private
	 * to the post / cleanup pair and less stomp-prone than rec->a2,
	 * which the syscall-arg ABI exposes to sibling value-result writes.
	 * The kernel only reads params synchronously during the syscall
	 * (no async lifetime past return), so a deterministic post-dispatch
	 * free in .cleanup replaces the pre-dispatch
	 * deferred_free_enqueue_or_leak() that owned the lifecycle before.
	 */
	rec->post_state = (unsigned long) params;
}

static void post_io_uring_setup(struct syscallrecord *rec)
{
	if ((long)rec->retval < 0)
		return;

	publish_resource(OBJ_FD_IO_URING, (int)rec->retval, NULL);
}

static void cleanup_io_uring_setup(struct syscallrecord *rec)
{
	rec->a2 = 0;
	cleanup_release_post_state(rec);
}

struct syscallentry syscall_io_uring_setup = {
	.name = "io_uring_setup",
	.group = GROUP_IO_URING,
	.num_args = 2,
	.argtype = { [0] = ARG_LEN, [1] = ARG_STRUCT_PTR_IN },
	.argname = { [0] = "entries", [1] = "params" },
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_IO_URING,
	.flags = NEED_ALARM | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_io_uring_setup,
	.post = post_io_uring_setup,
	.cleanup = cleanup_io_uring_setup,
};
