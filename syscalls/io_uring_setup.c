/*
 *   SYSCALL_DEFINE2(io_uring_setup, u32, entries, struct io_uring_params __user *, params)
 */
#include <linux/types.h>
#include "objects.h"
#include "random.h"
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

	params = zmalloc(sizeof(struct io_uring_params));
	params->flags = set_rand_bitmask(ARRAY_SIZE(io_uring_setup_flags),
					 io_uring_setup_flags);
	if (params->flags & IORING_SETUP_CQSIZE)
		params->cq_entries = RAND_RANGE(1, 4096);
	if (params->flags & IORING_SETUP_SQ_AFF)
		params->sq_thread_cpu = rand() % 64;
	if (params->flags & IORING_SETUP_SQPOLL)
		params->sq_thread_idle = RAND_RANGE(100, 10000);

	rec->a2 = (unsigned long) params;
	/* Snapshot for the post handler -- a2 may be scribbled by a sibling
	 * syscall before post_io_uring_setup() runs. */
	rec->post_state = (unsigned long) params;
}

static void post_io_uring_setup(struct syscallrecord *rec)
{
	int fd = rec->retval;
	void *params = (void *) rec->post_state;

	if (params == NULL)
		goto check_ret;

	if (looks_like_corrupted_ptr(params)) {
		outputerr("post_io_uring_setup: rejected suspicious params=%p (pid-scribbled?)\n", params);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->a2 = 0;
		rec->post_state = 0;
		goto check_ret;
	}

	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);

check_ret:
	if ((long)rec->retval < 0)
		return;

	struct object *new = alloc_object();
	new->io_uringobj.fd = fd;
	add_object(new, OBJ_LOCAL, OBJ_FD_IO_URING);
}

struct syscallentry syscall_io_uring_setup = {
	.name = "io_uring_setup",
	.group = GROUP_IO_URING,
	.num_args = 2,
	.argtype = { [1] = ARG_ADDRESS },
	.argname = { [0] = "entries", [1] = "params" },
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_IO_URING,
	.flags = NEED_ALARM,
	.sanitise = sanitise_io_uring_setup,
	.post = post_io_uring_setup,
};
