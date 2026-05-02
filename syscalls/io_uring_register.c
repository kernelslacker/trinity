/*
 *   SYSCALL_DEFINE4(io_uring_register, unsigned int, fd, unsigned int, opcode, void __user *, arg, unsigned int, nr_args)
 */
#include <string.h>
#include <linux/io_uring.h>
#include "arch.h"
#include "deferred-free.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"

/* Opcodes added after our system headers — guard with #ifndef. */
#ifndef IORING_REGISTER_PBUF_STATUS
#define IORING_REGISTER_PBUF_STATUS	26
#endif
#ifndef IORING_REGISTER_NAPI
#define IORING_REGISTER_NAPI		27
#endif
#ifndef IORING_UNREGISTER_NAPI
#define IORING_UNREGISTER_NAPI		28
#endif
#ifndef IORING_REGISTER_CLOCK
#define IORING_REGISTER_CLOCK		29
#endif
#ifndef IORING_REGISTER_CLONE_BUFFERS
#define IORING_REGISTER_CLONE_BUFFERS	30
#endif
#ifndef IORING_REGISTER_SEND_MSG_RING
#define IORING_REGISTER_SEND_MSG_RING	31
#endif
#ifndef IORING_REGISTER_ZCRX_IFQ
#define IORING_REGISTER_ZCRX_IFQ	32
#endif
#ifndef IORING_REGISTER_RESIZE_RINGS
#define IORING_REGISTER_RESIZE_RINGS	33
#endif
#ifndef IORING_REGISTER_MEM_REGION
#define IORING_REGISTER_MEM_REGION	34
#endif
#ifndef IORING_REGISTER_QUERY
#define IORING_REGISTER_QUERY		35
#endif
#ifndef IORING_REGISTER_ZCRX_CTRL
#define IORING_REGISTER_ZCRX_CTRL	36
#endif
#ifndef IORING_REGISTER_BPF_FILTER
#define IORING_REGISTER_BPF_FILTER	37
#endif

static unsigned long io_uring_register_opcodes[] = {
	IORING_REGISTER_BUFFERS,
	IORING_UNREGISTER_BUFFERS,
	IORING_REGISTER_FILES,
	IORING_UNREGISTER_FILES,
	IORING_REGISTER_EVENTFD,
	IORING_UNREGISTER_EVENTFD,
	IORING_REGISTER_FILES_UPDATE,
	IORING_REGISTER_EVENTFD_ASYNC,
	IORING_REGISTER_PROBE,
	IORING_REGISTER_PERSONALITY,
	IORING_UNREGISTER_PERSONALITY,
	IORING_REGISTER_RESTRICTIONS,
	IORING_REGISTER_ENABLE_RINGS,
	IORING_REGISTER_FILES2,
	IORING_REGISTER_FILES_UPDATE2,
	IORING_REGISTER_BUFFERS2,
	IORING_REGISTER_BUFFERS_UPDATE,
	IORING_REGISTER_IOWQ_AFF,
	IORING_UNREGISTER_IOWQ_AFF,
	IORING_REGISTER_IOWQ_MAX_WORKERS,
	IORING_REGISTER_RING_FDS,
	IORING_UNREGISTER_RING_FDS,
	IORING_REGISTER_PBUF_RING,
	IORING_UNREGISTER_PBUF_RING,
	IORING_REGISTER_SYNC_CANCEL,
	IORING_REGISTER_FILE_ALLOC_RANGE,
	IORING_REGISTER_PBUF_STATUS,
	IORING_REGISTER_NAPI,
	IORING_UNREGISTER_NAPI,
	IORING_REGISTER_CLOCK,
	IORING_REGISTER_CLONE_BUFFERS,
	IORING_REGISTER_SEND_MSG_RING,
	IORING_REGISTER_ZCRX_IFQ,
	IORING_REGISTER_RESIZE_RINGS,
	IORING_REGISTER_MEM_REGION,
	IORING_REGISTER_QUERY,
	IORING_REGISTER_ZCRX_CTRL,
	IORING_REGISTER_BPF_FILTER,
};

static void sanitise_io_uring_register(struct syscallrecord *rec)
{
	struct io_uringobj *ring;
	unsigned int opcode;
	unsigned int nr;
	void *buf;

	ring = get_io_uring_ring();
	if (ring != NULL)
		rec->a1 = ring->fd;

	opcode = rec->a2;

	switch (opcode) {
	/* Opcodes that take no arg — clear both to avoid early EFAULT. */
	case IORING_UNREGISTER_BUFFERS:
	case IORING_UNREGISTER_FILES:
	case IORING_UNREGISTER_EVENTFD:
	case IORING_REGISTER_ENABLE_RINGS:
	case IORING_REGISTER_PERSONALITY:
	case IORING_UNREGISTER_PERSONALITY:
	case IORING_UNREGISTER_IOWQ_AFF:
		rec->a3 = 0;
		rec->a4 = 0;
		break;

	/*
	 * IORING_REGISTER_BUFFERS: arg = struct iovec[], nr_args = count.
	 * Kernel iterates the array copying each iovec from userspace.
	 */
	case IORING_REGISTER_BUFFERS:
		nr = 1 + (rand() % 8);
		rec->a3 = (unsigned long) alloc_iovec(nr);
		rec->a4 = nr;
		break;

	/*
	 * IORING_REGISTER_FILES: arg = int[] of fds, nr_args = count.
	 * Use -1 as placeholder; kernel accepts sparse sets with -1 holes.
	 */
	case IORING_REGISTER_FILES:
		nr = 1 + (rand() % 16);
		buf = get_writable_struct(nr * sizeof(int));
		if (buf)
			memset(buf, 0xff, nr * sizeof(int));  /* fill with -1 */
		rec->a3 = (unsigned long) buf;
		rec->a4 = nr;
		break;

	/*
	 * IORING_REGISTER_PROBE: arg = struct io_uring_probe with trailing
	 * ops[], nr_args = number of op slots.
	 */
	case IORING_REGISTER_PROBE: {
		struct io_uring_probe *probe;
		nr = IORING_OP_LAST;
		probe = (struct io_uring_probe *)
			get_writable_struct(sizeof(*probe) +
					    nr * sizeof(probe->ops[0]));
		if (probe)
			memset(probe, 0, sizeof(*probe) + nr * sizeof(probe->ops[0]));
		rec->a3 = (unsigned long) probe;
		rec->a4 = nr;
		break;
	}

	/*
	 * IORING_REGISTER_IOWQ_MAX_WORKERS: arg = uint[2] (bounded/unbounded),
	 * nr_args = 2.
	 */
	case IORING_REGISTER_IOWQ_MAX_WORKERS:
		buf = get_writable_struct(2 * sizeof(unsigned int));
		rec->a3 = (unsigned long) buf;
		rec->a4 = 2;
		break;

	/*
	 * For opcodes with struct args we don't model in detail, provide a
	 * zeroed page so the kernel reaches argument parsing rather than
	 * faulting immediately on a garbage pointer.
	 */
	default:
		buf = get_writable_address(page_size);
		if (buf)
			memset(buf, 0, page_size);
		rec->a3 = (unsigned long) buf;
		rec->a4 = 1;
		break;
	}

	/*
	 * Several opcodes above (PROBE, IOWQ_MAX_WORKERS, the default
	 * catch-all) hand the kernel a get_writable_address()-derived
	 * pointer as a writeback target.  get_writable_address() pulls
	 * from the OBJ_MMAP pool which is structurally distinct from the
	 * alloc_shared() regions, but a VA-space alias is not impossible
	 * and the kernel writeback into a stomped shared region produces
	 * exactly the silent-corruption symptom we just chased through
	 * init_child_mappings.  Mirror the defensive scrub
	 * pick_random_ioctl() runs after ioctl_arg_for_request() — same
	 * reasoning, same shape, same negligible cost.
	 */
	avoid_shared_buffer(&rec->a3, page_size);
}

/*
 * IORING_REGISTER_BUFFERS is the only opcode whose sanitise path
 * allocates memory (via alloc_iovec()) into rec->a3.  Other opcodes
 * use pool-managed pointers (get_writable_address / get_writable_struct)
 * that must not be free()d.  Gate the deferred free on opcode so we
 * release exactly the iovec we allocated.
 */
static void post_io_uring_register(struct syscallrecord *rec)
{
	if (rec->a2 == IORING_REGISTER_BUFFERS && rec->a3 != 0)
		deferred_free_enqueue((void *)(unsigned long) rec->a3, NULL);
}

struct syscallentry syscall_io_uring_register = {
	.name = "io_uring_register",
	.group = GROUP_IO_URING,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_IO_URING, [1] = ARG_OP, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "opcode", [2] = "arg", [3] = "nr_args" },
	.arg_params[1].list = ARGLIST(io_uring_register_opcodes),
	.flags = NEED_ALARM,
	.sanitise = sanitise_io_uring_register,
	.post = post_io_uring_register,
	.rettype = RET_ZERO_SUCCESS,
};
