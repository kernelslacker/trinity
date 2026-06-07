/*
 *   SYSCALL_DEFINE2(io_uring_setup, u32, entries, struct io_uring_params __user *, params)
 */
#include <linux/types.h>
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
	params->flags = set_rand_bitmask(ARRAY_SIZE(io_uring_setup_flags),
					 io_uring_setup_flags);
	if (params->flags & IORING_SETUP_CQSIZE)
		params->cq_entries = RAND_RANGE(1, 4096);
	if (params->flags & IORING_SETUP_SQ_AFF)
		params->sq_thread_cpu = rnd_modulo_u32(64);
	if (params->flags & IORING_SETUP_SQPOLL)
		params->sq_thread_idle = RAND_RANGE(100, 10000);

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
	struct io_uring_params *params =
		(struct io_uring_params *) rec->post_state;

	rec->post_state = 0;
	rec->a2 = 0;

	if (params == NULL)
		return;

	/*
	 * post_state is not exposed as a syscall arg, but the whole
	 * syscallrecord can still be wholesale-stomped by a sibling.  A
	 * shape-failing pointer is leaked rather than freed -- matches the
	 * old deferred_free_enqueue_or_leak() pressure-path behaviour
	 * (bounded leak reclaimed at child exit) and is strictly safer
	 * than calling free() on a foreign / pid-shaped address.
	 */
	if (looks_like_corrupted_ptr(rec, params))
		return;

	/*
	 * params came from zmalloc_tracked(), which registered the pointer
	 * in the alloc-track LRU.  tracked_free_now() removes it from the
	 * ring and calls free() in one step; a raw free() would leave the
	 * alloc-track side-set claiming the address is still live and
	 * mislead subsequent alloc_track_lookup() callers.
	 */
	tracked_free_now(params);
}

struct syscallentry syscall_io_uring_setup = {
	.name = "io_uring_setup",
	.group = GROUP_IO_URING,
	.num_args = 2,
	.argtype = { [1] = ARG_STRUCT_PTR_IN },
	.argname = { [0] = "entries", [1] = "params" },
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_IO_URING,
	.flags = NEED_ALARM | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_io_uring_setup,
	.post = post_io_uring_setup,
	.cleanup = cleanup_io_uring_setup,
};
