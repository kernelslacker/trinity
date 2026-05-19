/*
 *   SYSCALL_DEFINE4(io_uring_register, unsigned int, fd, unsigned int, opcode, void __user *, arg, unsigned int, nr_args)
 */
#include <limits.h>
#include <sched.h>
#include <string.h>
#include <linux/io_uring.h>
#include "arch.h"
#include "deferred-free.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

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
#ifndef IORING_REGISTER_USE_REGISTERED_RING
#define IORING_REGISTER_USE_REGISTERED_RING	(1U << 31)
#endif
#ifndef IORING_OP_MSG_RING
#define IORING_OP_MSG_RING			40
#endif

/*
 * IO_URING_BPF_CMD_FILTER: cmd_type selector inside struct io_uring_bpf.
 * No system-header sentinel #define; mirror the value here.
 */
#define TRINITY_IO_URING_BPF_CMD_FILTER	1

/*
 * Local mirrors of the FILE_ALLOC_RANGE / CLOCK opcode argument structs.
 * <linux/io_uring.h> declares io_uring_file_index_range and
 * io_uring_clock_register as enums-or-structs depending on the kernel
 * vintage, with no stable #define companion to detect via #ifndef.
 * Use trinity-private struct names with identical layout: the kernel
 * copies sizeof(its-own-struct) bytes from the user pointer, so layout
 * is the only thing that matters at the syscall boundary.  This keeps
 * the file building against any header vintage without redefinition.
 */
struct trinity_io_uring_file_index_range {
	__u32	off;
	__u32	len;
	__u64	resv;
};

struct trinity_io_uring_clock_register {
	__u32	clockid;
	__u32	__resv[3];
};

/*
 * Trinity-private mirrors for the IORING_REGISTER_* opcode arg structs added
 * in 6.4..6.14.  Same rationale as the file_index_range / clock_register
 * mirrors above: the kernel copies sizeof(its-own-struct) bytes from the user
 * pointer, so layout is the only thing that matters at the syscall boundary,
 * and there is no per-struct sentinel #define to test via #ifndef.  Mirroring
 * keeps the file building against any uapi header vintage trinity supports.
 */
struct trinity_io_uring_buf_reg {
	__u64	ring_addr;
	__u32	ring_entries;
	__u16	bgid;
	__u16	flags;
	__u64	resv[3];
};

struct trinity_io_uring_buf_status {
	__u32	buf_group;
	__u32	head;
	__u32	resv[8];
};

struct trinity_io_uring_napi {
	__u32	busy_poll_to;
	__u8	prefer_busy_poll;
	__u8	opcode;
	__u8	pad[2];
	__u32	op_param;
	__u32	resv;
};

struct trinity_io_uring_zcrx_offsets {
	__u32	head;
	__u32	tail;
	__u32	rqes;
	__u32	__resv2;
	__u64	__resv[2];
};

struct trinity_io_uring_zcrx_ifq_reg {
	__u32	if_idx;
	__u32	if_rxq;
	__u32	rq_entries;
	__u32	flags;
	__u64	area_ptr;
	__u64	region_ptr;
	struct trinity_io_uring_zcrx_offsets offsets;
	__u32	zcrx_id;
	__u32	__resv2;
	__u64	__resv[3];
};

struct trinity_io_uring_mem_region_reg {
	__u64	region_uptr;
	__u64	flags;
	__u64	__resv[2];
};

struct trinity_io_uring_clone_buffers {
	__u32	src_fd;
	__u32	flags;
	__u32	src_off;
	__u32	dst_off;
	__u32	nr;
	__u32	pad[3];
};

/*
 * Trinity-private mirrors for the blind-fd register opcode arg structs:
 * io_uring_restriction / io_uring_task_restriction (RESTRICTIONS task path)
 * and io_uring_bpf / io_uring_bpf_filter (BPF_FILTER task path).  Same
 * rationale as the other private mirrors here -- no per-struct sentinel
 * #define exists to test via #ifndef, so layout-only mirrors keep the
 * file building against any uapi header vintage trinity supports.
 */
struct trinity_io_uring_restriction {
	__u16	opcode;
	__u8	op;
	__u8	resv;
	__u32	resv2[3];
};

struct trinity_io_uring_task_restriction {
	__u16	flags;
	__u16	nr_res;
	__u32	resv[3];
	struct trinity_io_uring_restriction restrictions[];
};

struct trinity_io_uring_bpf_filter {
	__u32	opcode;
	__u32	flags;
	__u32	filter_len;
	__u8	pdu_size;
	__u8	resv[3];
	__u64	filter_ptr;
	__u64	resv2[5];
};

struct trinity_io_uring_bpf {
	__u16	cmd_type;
	__u16	cmd_flags;
	__u32	resv;
	union {
		struct trinity_io_uring_bpf_filter filter;
	};
};

/*
 * __kernel_timespec embedded by value -- inline its layout to avoid pulling
 * in <linux/time_types.h> and to insulate against any future ABI churn.
 */
struct trinity_io_uring_sync_cancel_reg {
	__u64	addr;
	__s32	fd;
	__u32	flags;
	__s64	timeout_tv_sec;
	__s64	timeout_tv_nsec;
	__u8	opcode;
	__u8	pad[7];
	__u64	pad2[3];
};

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
	/*
	 * Modifier bit OR'd onto the request opcode that tells the kernel
	 * to treat fd as a registered-ring index rather than a real fd.
	 * Listing it as a pool value exercises the masking path (low bits
	 * are zero, so the kernel decodes it as opcode 0 via the registered
	 * ring) -- a corner ARG_OP would not otherwise reach.
	 */
	IORING_REGISTER_USE_REGISTERED_RING,
};

/*
 * Stratified opcode picker.  Uniform sampling across the 38-entry
 * io_uring_register_opcodes[] table under-exercises the rarer kernel
 * paths because the list mixes a small set of common multi-purpose
 * opcodes (BUFFERS/FILES/EVENTFD/PROBE/PERSONALITY/IOWQ_MAX_WORKERS)
 * with newer narrowly-targeted ones (zcrx, mem_region, query,
 * bpf_filter, clock, resize_rings, ...).  Bias the picker so the rare
 * paths get hit ~50% of the time, and ~10% of the time OR the
 * IORING_REGISTER_USE_REGISTERED_RING modifier bit onto a re-rolled
 * base opcode to exercise the masking path that decodes fd as a
 * registered-ring index rather than a real fd.
 */
static const unsigned long io_uring_register_opcodes_common[] = {
	IORING_REGISTER_BUFFERS,
	IORING_REGISTER_FILES,
	IORING_REGISTER_EVENTFD,
	IORING_REGISTER_PROBE,
	IORING_REGISTER_PERSONALITY,
	IORING_REGISTER_IOWQ_MAX_WORKERS,
};

static const unsigned long io_uring_register_opcodes_rare[] = {
	IORING_REGISTER_RESIZE_RINGS,
	IORING_REGISTER_CLONE_BUFFERS,
	IORING_REGISTER_ZCRX_IFQ,
	IORING_REGISTER_MEM_REGION,
	IORING_REGISTER_QUERY,
	IORING_REGISTER_ZCRX_CTRL,
	IORING_REGISTER_BPF_FILTER,
	IORING_REGISTER_CLOCK,
	IORING_REGISTER_NAPI,
	IORING_REGISTER_SEND_MSG_RING,
	IORING_REGISTER_RING_FDS,
	IORING_REGISTER_RESTRICTIONS,
	IORING_REGISTER_ENABLE_RINGS,
	IORING_REGISTER_SYNC_CANCEL,
	IORING_REGISTER_PBUF_RING,
	IORING_REGISTER_PBUF_STATUS,
};

static unsigned long pick_io_uring_register_opcode(void)
{
	unsigned int r = rand() % 100;
	unsigned long base;

	if (r < 40)
		return io_uring_register_opcodes_common[rand() %
			ARRAY_SIZE(io_uring_register_opcodes_common)];
	if (r < 90)
		return io_uring_register_opcodes_rare[rand() %
			ARRAY_SIZE(io_uring_register_opcodes_rare)];

	/*
	 * 10%: re-roll a base opcode (50/50 common vs rare) and OR in the
	 * IORING_REGISTER_USE_REGISTERED_RING modifier bit.  The kernel
	 * masks this bit off before dispatching, decoding fd as a
	 * registered-ring index rather than a real fd -- a path the bare
	 * opcode list never reaches when the modifier is listed alone as
	 * a pool value (it decodes there as opcode 0).
	 */
	if (rand() % 2)
		base = io_uring_register_opcodes_common[rand() %
			ARRAY_SIZE(io_uring_register_opcodes_common)];
	else
		base = io_uring_register_opcodes_rare[rand() %
			ARRAY_SIZE(io_uring_register_opcodes_rare)];
	return base | IORING_REGISTER_USE_REGISTERED_RING;
}

/*
 * Snapshot of the opcode-gated heap allocation sanitise hands to the
 * kernel via rec->a3, captured at sanitise time and consumed by the
 * post handler.  Lives in rec->post_state, a slot the syscall ABI does
 * not expose, so the post path is immune to a sibling syscall scribbling
 * rec->a2 or rec->a3 between the syscall returning and the post handler
 * running.
 *
 * Per-op allocation matrix.  Of the ~38 IORING_REGISTER_* opcodes this
 * generator emits, only one allocates a heap buffer that the post
 * handler has to free:
 *
 *   IORING_REGISTER_BUFFERS -> struct iovec * (alloc_iovec)
 *
 * The other opcodes feed rec->a3 with non-heap values -- get_writable_
 * struct() / get_writable_address() pool pointers, or zero -- and leave
 * original_alloc NULL.  The post handler dispatches off the snapshot's
 * opcode, not rec->a2, so a sibling scribble of the opcode also cannot
 * redirect the free into a non-heap rec->a3 (which would UAF the
 * OBJ_MMAP pool).
 *
 * original_alloc captures the alloc_iovec() return value BEFORE the
 * trailing avoid_shared_buffer() call -- ASB relocates rec->a3 off the
 * libc heap into a parent-private writable region whenever the buffer
 * overlaps the shared regions, so by the time the post handler runs
 * rec->a3 may no longer point at the zmalloc()'d iovec at all.
 * deferred_free_enqueue()'s heap-bounds and alloc-track gates reject the
 * relocated pointer (writable-address pool, mmap'd, alloc-track-unknown),
 * so the original allocation would leak every IORING_REGISTER_BUFFERS
 * invocation if the post handler routed the free through rec->a3.
 *
 * The magic cookie hardens the post handler against rec->post_state
 * being scribbled with a heap-shaped pointer to a foreign allocation
 * (a sibling syscall's post_state, a stale alloc_iovec(1) in the same
 * free-list bucket, ...) -- a cookie mismatch rejects the forgery
 * before any inner-field deref.
 */
#define IO_URING_REGISTER_POST_STATE_MAGIC	0x494F5F55524D4147UL	/* "IO_URMAG" */
struct io_uring_register_post_state {
	unsigned long magic;
	unsigned int opcode;
	void *original_alloc;
};

static void sanitise_io_uring_register(struct syscallrecord *rec)
{
	struct io_uring_register_post_state *snap;
	struct io_uringobj *ring;
	unsigned int opcode;
	unsigned int nr;
	void *buf;
	void *iov_alloc = NULL;

	rec->a2 = pick_io_uring_register_opcode();

	ring = get_io_uring_ring();
	if (ring != NULL)
		rec->a1 = ring->fd;

	/*
	 * 15% of the time, override into the kernel's blind fd == -1
	 * registration path (io_uring_register_blind).  Three opcodes are
	 * only reachable that way: SEND_MSG_RING, RESTRICTIONS (task-scoped
	 * via io_register_restrictions_task), BPF_FILTER (task-scoped via
	 * io_register_bpf_filter_task).  QUERY is also a blind opcode but
	 * is reachable via the real-fd path too, so it isn't in the pool.
	 * The override only fires when the real-fd path was actually in
	 * play (ring != NULL); the remaining 85% keep the existing
	 * real-fd dispatch intact.  Done as a re-roll after
	 * pick_io_uring_register_opcode() returns rather than a new picker
	 * entry so the override stays decoupled from the picker tables.
	 */
	if (ring != NULL && (rand() % 100) < 15) {
		static const unsigned long blind_opcodes[] = {
			IORING_REGISTER_SEND_MSG_RING,
			IORING_REGISTER_RESTRICTIONS,
			IORING_REGISTER_BPF_FILTER,
		};
		rec->a1 = (unsigned long) -1U;
		rec->a2 = blind_opcodes[rand() % ARRAY_SIZE(blind_opcodes)];
	}

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
		iov_alloc = alloc_iovec(nr);
		rec->a3 = (unsigned long) iov_alloc;
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
	 * IORING_REGISTER_EVENTFD / IORING_REGISTER_EVENTFD_ASYNC:
	 * arg = int *eventfd_fd, nr_args = 1.  Seed *u with a real eventfd
	 * from the OBJ_FD_EVENTFD pool ~75% of the time so io_eventfd_register
	 * reaches eventfd_ctx_fdget() rather than -EBADF'ing on a garbage fd;
	 * the rest of the time inject a random int32 to walk the validator's
	 * "wrong fd type / closed fd" reject paths.
	 */
	case IORING_REGISTER_EVENTFD:
	case IORING_REGISTER_EVENTFD_ASYNC: {
		int *u = (int *) get_writable_struct(sizeof(int));
		if (u) {
			if ((rand() % 4) != 0) {
				int efd = get_typed_fd(ARG_FD_EVENTFD);
				*u = (efd >= 0) ? efd : (int) rand();
			} else {
				*u = (int) rand();
			}
		}
		rec->a3 = (unsigned long) u;
		rec->a4 = 1;
		break;
	}

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
	 * IORING_REGISTER_IOWQ_AFF: arg = cpu_set_t *, nr_args = sizeof(cpu_set_t).
	 * Build a small valid affinity mask (a couple of bits set on online CPUs)
	 * so io_register_iowq_aff's cpumask_parse / cpumask_subset checks pass
	 * and the call reaches io_wq_cpu_affinity().  Skip memset -- the
	 * cpu_set_t bit layout matters for the cpumask validator.
	 */
	case IORING_REGISTER_IOWQ_AFF: {
		cpu_set_t *cs = (cpu_set_t *) get_writable_address(sizeof(cpu_set_t));
		if (cs) {
			unsigned int n = num_online_cpus ? num_online_cpus : 1;
			unsigned int i, k = 1 + (rand() % 3);
			CPU_ZERO(cs);
			for (i = 0; i < k; i++)
				CPU_SET(rand() % n, cs);
		}
		rec->a3 = (unsigned long) cs;
		rec->a4 = sizeof(cpu_set_t);
		break;
	}

	/*
	 * IORING_REGISTER_FILE_ALLOC_RANGE: arg = struct io_uring_file_index_range,
	 * nr_args = 0.  Kernel rejects nr_args != 0 before dispatch, so the
	 * default catch-all (which sets nr_args = 1) never reaches the handler
	 * body.  Bias off/len against a small registered file table; 1-in-32
	 * inject INT_MAX to probe arithmetic overflow checks in the range
	 * allocator.
	 */
	case IORING_REGISTER_FILE_ALLOC_RANGE: {
		struct trinity_io_uring_file_index_range *r;
		r = (struct trinity_io_uring_file_index_range *)
			get_writable_struct(sizeof(*r));
		if (r) {
			memset(r, 0, sizeof(*r));
			if ((rand() % 32) == 0) {
				r->off = INT_MAX;
				r->len = INT_MAX;
			} else {
				r->off = rand() % 16;
				r->len = 1 + (rand() % 16);
			}
		}
		rec->a3 = (unsigned long) r;
		rec->a4 = 0;
		break;
	}

	/*
	 * IORING_REGISTER_CLOCK: arg = struct io_uring_clock_register,
	 * nr_args = 0.  Same nr_args == 0 gate as FILE_ALLOC_RANGE.  75% of
	 * the time pick a clockid the kernel's io_register_clock will accept
	 * (CLOCK_MONOTONIC / CLOCK_BOOTTIME -- CLOCK_REALTIME is rejected by
	 * the validator but exercises that reject path); 25% garbage to
	 * exercise the validator.  1-in-16 leave a non-zero __resv slot to
	 * exercise the memchr_inv reject path.  Hard-code the clockid values
	 * (0/1/7 from uapi/linux/time.h) to keep trinity hermetic against
	 * <time.h> enum drift.
	 */
	case IORING_REGISTER_CLOCK: {
		static const __s32 valid_clockids[] = {
			0,	/* CLOCK_REALTIME */
			1,	/* CLOCK_MONOTONIC */
			7,	/* CLOCK_BOOTTIME */
		};
		struct trinity_io_uring_clock_register *cr;
		cr = (struct trinity_io_uring_clock_register *)
			get_writable_struct(sizeof(*cr));
		if (cr) {
			memset(cr, 0, sizeof(*cr));
			if ((rand() % 4) == 0)
				cr->clockid = rand();
			else
				cr->clockid = valid_clockids[rand() %
					ARRAY_SIZE(valid_clockids)];
			if ((rand() % 16) == 0)
				cr->__resv[rand() % 3] = rand();
		}
		rec->a3 = (unsigned long) cr;
		rec->a4 = 0;
		break;
	}

	/*
	 * IORING_REGISTER_RING_FDS / IORING_UNREGISTER_RING_FDS:
	 * arg = struct io_uring_rsrc_update[], nr_args = entry count
	 * (kernel cap IO_RINGFD_REG_MAX = 16).  Both opcodes share the same
	 * payload shape -- io_ringfd_register iterates the array consuming
	 * data as the io_uring fd to install and offset as the slot id;
	 * io_ringfd_unregister consumes offset only.  Seed data with a real
	 * io_uring fd from the existing object pool ~75% of the time so the
	 * register path actually installs slots rather than -EBADF'ing on
	 * the first entry; the rest of the time inject -1 / garbage to walk
	 * the validator's reject paths.  resv must be 0 or io_ringfd_register
	 * bails at -EINVAL; occasionally fuzz it to exercise that gate.
	 * NULL-guard the writable buffer -- get_writable_struct() can return
	 * NULL on pool exhaustion and the populate loop must not deref it;
	 * a NULL rec->a3 still EFAULTs cleanly past the kernel's first
	 * copy_from_user, and the trailing avoid_shared_buffer scrub runs
	 * unconditionally for both paths.
	 */
	case IORING_REGISTER_RING_FDS:
	case IORING_UNREGISTER_RING_FDS: {
		struct io_uring_rsrc_update *u;
		unsigned int i;
		nr = 1 + (rand() % 16);
		u = (struct io_uring_rsrc_update *)
			get_writable_struct(nr * sizeof(*u));
		if (u) {
			memset(u, 0, nr * sizeof(*u));
			for (i = 0; i < nr; i++) {
				unsigned int roll = rand() % 100;
				u[i].offset = rand() & 0xf;
				if ((rand() % 32) == 0)
					u[i].resv = rand();
				if (roll < 75) {
					struct io_uringobj *r2 = get_io_uring_ring();
					u[i].data = (r2 != NULL) ?
						(__u64) r2->fd : (__u64) -1;
				} else if (roll < 87) {
					u[i].data = (__u64) -1;
				} else {
					u[i].data = ((__u64) rand() << 32) |
						(__u32) rand();
				}
			}
		}
		rec->a3 = (unsigned long) u;
		rec->a4 = nr;
		break;
	}

	/*
	 * IORING_REGISTER_PBUF_RING / IORING_UNREGISTER_PBUF_RING:
	 * arg = struct io_uring_buf_reg, nr_args = 1.  Seed ring_entries
	 * with a small power-of-2 so io_register_pbuf_ring's
	 * is_power_of_2(reg.ring_entries) sanity check passes and the
	 * handler reaches the buf_ring allocation path.  Leave ring_addr
	 * NULL -- the handler will EFAULT past the size check, which still
	 * exercises far more code than the default zero-page path.
	 */
	case IORING_REGISTER_PBUF_RING:
	case IORING_UNREGISTER_PBUF_RING: {
		struct trinity_io_uring_buf_reg *r;
		r = (struct trinity_io_uring_buf_reg *)
			get_writable_struct(sizeof(*r));
		if (r) {
			memset(r, 0, sizeof(*r));
			r->ring_entries = 1U << (4 + (rand() % 4));  /* 16..128 */
			r->bgid = rand() % 16;
		}
		rec->a3 = (unsigned long) r;
		rec->a4 = 1;
		break;
	}

	/*
	 * IORING_REGISTER_PBUF_STATUS: arg = struct io_uring_buf_status,
	 * nr_args = 1.  Seed buf_group small so io_register_pbuf_status's
	 * xa_load() lookup actually hits a registered buf-ring slot some of
	 * the time; head is an output field, leave 0.  The kernel walks resv[]
	 * with memchr_inv() and rejects non-zero -- mostly leave it zero, but
	 * 1-in-32 fuzz a slot to exercise that gate.
	 */
	case IORING_REGISTER_PBUF_STATUS: {
		struct trinity_io_uring_buf_status *s;
		s = (struct trinity_io_uring_buf_status *)
			get_writable_struct(sizeof(*s));
		if (s) {
			unsigned int i;
			memset(s, 0, sizeof(*s));
			s->buf_group = rand() & 0xf;
			for (i = 0; i < 8; i++)
				if ((rand() % 32) == 0)
					s->resv[i] = rand();
		}
		rec->a3 = (unsigned long) s;
		rec->a4 = 1;
		break;
	}

	/*
	 * IORING_REGISTER_NAPI / IORING_UNREGISTER_NAPI:
	 * arg = struct io_uring_napi, nr_args = 0.  Default opcode field
	 * to IO_URING_NAPI_REGISTER_OP (0) so io_register_napi reaches
	 * io_napi_register_napi() rather than rejecting at the opcode
	 * switch.  Occasionally fuzz the opcode/tracking-strategy fields.
	 */
	case IORING_REGISTER_NAPI:
	case IORING_UNREGISTER_NAPI: {
		struct trinity_io_uring_napi *n;
		n = (struct trinity_io_uring_napi *)
			get_writable_struct(sizeof(*n));
		if (n) {
			memset(n, 0, sizeof(*n));
			n->busy_poll_to = rand() % 1000;
			n->prefer_busy_poll = rand() & 1;
			n->opcode = (rand() % 8 == 0) ? rand() & 0xff : 0;
			n->op_param = rand();
		}
		rec->a3 = (unsigned long) n;
		rec->a4 = 0;
		break;
	}

	/*
	 * IORING_REGISTER_ZCRX_IFQ: arg = struct io_uring_zcrx_ifq_reg,
	 * nr_args = 1.  Seed rq_entries with a small power-of-2 so the
	 * is_power_of_2 check in io_register_zcrx_ifq passes; if_idx /
	 * if_rxq pick small values that may or may not resolve to a real
	 * netdev.  area_ptr / region_ptr are left NULL on purpose -- the
	 * handler EFAULTs past validation, exercising the early checks.
	 */
	case IORING_REGISTER_ZCRX_IFQ: {
		struct trinity_io_uring_zcrx_ifq_reg *z;
		z = (struct trinity_io_uring_zcrx_ifq_reg *)
			get_writable_struct(sizeof(*z));
		if (z) {
			memset(z, 0, sizeof(*z));
			z->rq_entries = 1U << (4 + (rand() % 4));
			z->if_idx = 1 + (rand() % 4);
			z->if_rxq = rand() % 4;
		}
		rec->a3 = (unsigned long) z;
		rec->a4 = 1;
		break;
	}

	/*
	 * IORING_REGISTER_RESIZE_RINGS: arg = struct io_uring_params,
	 * nr_args = 0.  Kernel-side this is gated on the source ring
	 * having been created with IORING_SETUP_DEFER_TASKRUN; trinity
	 * does not control how its ARG_FD_IO_URING fd was set up, so most
	 * invocations will be rejected at io_register_resize_rings's
	 * IORING_SETUP_DEFER_TASKRUN check.  Still seed sq_entries /
	 * cq_entries non-zero so the rare ring that does qualify reaches
	 * io_allocate_scq_urings rather than bailing on entry-count == 0.
	 */
	case IORING_REGISTER_RESIZE_RINGS: {
		struct io_uring_params *p;
		p = (struct io_uring_params *)
			get_writable_struct(sizeof(*p));
		if (p) {
			memset(p, 0, sizeof(*p));
			p->sq_entries = 1U << (3 + (rand() % 5));   /* 8..128 */
			p->cq_entries = p->sq_entries * 2;
		}
		rec->a3 = (unsigned long) p;
		rec->a4 = 0;
		break;
	}

	/*
	 * IORING_REGISTER_MEM_REGION: arg = struct io_uring_mem_region_reg,
	 * nr_args = 1.  region_uptr points to a struct io_uring_region_desc
	 * the kernel copy_from_users separately; wire it to a fresh
	 * get_writable_address() page so io_create_region reaches its own
	 * field validation rather than EFAULTing at the second copy.
	 */
	case IORING_REGISTER_MEM_REGION: {
		struct trinity_io_uring_mem_region_reg *m;
		void *region_desc;
		m = (struct trinity_io_uring_mem_region_reg *)
			get_writable_struct(sizeof(*m));
		region_desc = get_writable_address(page_size);
		if (region_desc)
			memset(region_desc, 0, page_size);
		if (m) {
			memset(m, 0, sizeof(*m));
			m->region_uptr = (unsigned long) region_desc;
		}
		rec->a3 = (unsigned long) m;
		rec->a4 = 1;
		break;
	}

	/*
	 * IORING_REGISTER_CLONE_BUFFERS: arg = struct io_uring_clone_buffers,
	 * nr_args = 1.  src_fd defaults to the same ring fd, exercising the
	 * src == dst rejection path; nr non-zero so we reach the buffer-table
	 * walk rather than bailing at the count==0 check.
	 */
	case IORING_REGISTER_CLONE_BUFFERS: {
		struct trinity_io_uring_clone_buffers *c;
		c = (struct trinity_io_uring_clone_buffers *)
			get_writable_struct(sizeof(*c));
		if (c) {
			memset(c, 0, sizeof(*c));
			c->src_fd = (ring != NULL) ? (__u32) ring->fd : (__u32) -1;
			c->nr = 1 + (rand() % 16);
		}
		rec->a3 = (unsigned long) c;
		rec->a4 = 1;
		break;
	}

	/*
	 * IORING_REGISTER_SYNC_CANCEL: arg = struct io_uring_sync_cancel_reg,
	 * nr_args = 1.  All-zero is a legal payload (matches "cancel any") and
	 * reaches io_sync_cancel's request-search loop, the bug-rich part.
	 * Occasionally seed a non-zero opcode/flags to walk the validator.
	 */
	case IORING_REGISTER_SYNC_CANCEL: {
		struct trinity_io_uring_sync_cancel_reg *s;
		s = (struct trinity_io_uring_sync_cancel_reg *)
			get_writable_struct(sizeof(*s));
		if (s) {
			memset(s, 0, sizeof(*s));
			s->fd = -1;
			if ((rand() % 8) == 0) {
				s->opcode = rand() & 0xff;
				s->flags = rand();
			}
		}
		rec->a3 = (unsigned long) s;
		rec->a4 = 1;
		break;
	}

	/*
	 * IORING_REGISTER_SEND_MSG_RING (blind, fd == -1 only): arg = struct
	 * io_uring_sqe with opcode = IORING_OP_MSG_RING, nr_args = 1.  The
	 * handler (io_uring_register_send_msg_ring) reads the SQE and
	 * dispatches as if it were an MSG_RING op via io_uring_sync_msg_ring
	 * -- otherwise it returns -EINVAL early on opcode mismatch.  flags
	 * must be 0 or the same -EINVAL gate fires.
	 */
	case IORING_REGISTER_SEND_MSG_RING: {
		struct io_uring_sqe *sqe;
		sqe = (struct io_uring_sqe *) get_writable_struct(sizeof(*sqe));
		if (sqe) {
			memset(sqe, 0, sizeof(*sqe));
			sqe->opcode = IORING_OP_MSG_RING;
		}
		rec->a3 = (unsigned long) sqe;
		rec->a4 = 1;
		break;
	}

	/*
	 * IORING_REGISTER_RESTRICTIONS (task-scoped via the blind fd == -1
	 * path): arg = struct io_uring_task_restriction with a flex-array of
	 * struct io_uring_restriction[nr_res], nr_args = 1.  flags must be 0
	 * and the resv slot must be all-zero or io_register_restrictions_task
	 * bails at -EINVAL.  Allocate room for a small nr_res so
	 * io_parse_restrictions actually iterates the array; zeroed entries
	 * still walk the parser.  The real-fd RESTRICTIONS path takes a flat
	 * array shape and reaches this case too -- a zeroed io_uring_task_-
	 * restriction overlays cleanly onto a single zero io_uring_restriction
	 * (both paths read sane payloads from the same buffer).
	 */
	case IORING_REGISTER_RESTRICTIONS: {
		struct trinity_io_uring_task_restriction *tr;
		unsigned int nr_res = rand() % 4;
		size_t sz = sizeof(*tr) +
			nr_res * sizeof(struct trinity_io_uring_restriction);
		tr = (struct trinity_io_uring_task_restriction *)
			get_writable_struct(sz);
		if (tr) {
			memset(tr, 0, sz);
			tr->nr_res = nr_res;
		}
		rec->a3 = (unsigned long) tr;
		rec->a4 = 1;
		break;
	}

	/*
	 * IORING_REGISTER_BPF_FILTER (task-scoped via the blind fd == -1
	 * path): arg = struct io_uring_bpf with cmd_type =
	 * IO_URING_BPF_CMD_FILTER and an embedded io_uring_bpf_filter,
	 * nr_args = 1.  CAP_SYS_ADMIN gates the path unless task_no_new_-
	 * privs is set; trinity may not satisfy either, but the EACCES
	 * reject still exercises the gate.  filter_ptr left NULL --
	 * bpf_prog_create_from_user EFAULTs past it, exercising the early
	 * io_bpf_filter_import validators (cmd_type/flags/opcode/filter_len
	 * checks) before the copy.
	 */
	case IORING_REGISTER_BPF_FILTER: {
		struct trinity_io_uring_bpf *bp;
		bp = (struct trinity_io_uring_bpf *)
			get_writable_struct(sizeof(*bp));
		if (bp) {
			memset(bp, 0, sizeof(*bp));
			bp->cmd_type = TRINITY_IO_URING_BPF_CMD_FILTER;
			bp->filter.opcode = rand() % IORING_OP_LAST;
			bp->filter.filter_len = rand() % 8;
		}
		rec->a3 = (unsigned long) bp;
		rec->a4 = 1;
		break;
	}

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

	/*
	 * Snapshot the opcode and the (possibly heap) pointer for the
	 * post handler.  A sibling syscall can scribble rec->a3 between
	 * the syscall returning and the post handler running, leaving a
	 * real-but-wrong heap pointer that looks_like_corrupted_ptr()
	 * cannot distinguish from the original; the old post handler
	 * then hands the wrong allocation to free, leaking ours and
	 * corrupting another sanitise routine's live buffer.  A scribble
	 * of rec->a2 is just as dangerous -- flipping the opcode from
	 * any non-allocating value to IORING_REGISTER_BUFFERS would
	 * redirect the old opcode-gated dispatch into a non-heap rec->a3
	 * (a get_writable_address / get_writable_struct pool pointer)
	 * and UAF the OBJ_MMAP pool.  rec->post_state is private to the
	 * post handler, so the scribblers have nothing to scribble there.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->magic = IO_URING_REGISTER_POST_STATE_MAGIC;
	snap->opcode = opcode;
	snap->original_alloc = (opcode == IORING_REGISTER_BUFFERS) ?
		iov_alloc : NULL;
	rec->post_state = (unsigned long) snap;
}

/*
 * IORING_REGISTER_BUFFERS is the only opcode whose sanitise path
 * allocates memory (via alloc_iovec()) into rec->a3.  Other opcodes
 * use pool-managed pointers (get_writable_address / get_writable_struct)
 * that must not be free()d.  Gate the deferred free on the snapshot's
 * opcode -- not rec->a2 -- so a sibling scribble of either rec->a2 or
 * rec->a3 cannot redirect or misdirect the free.
 */
static void post_io_uring_register(struct syscallrecord *rec)
{
	struct io_uring_register_post_state *snap =
		(struct io_uring_register_post_state *) rec->post_state;
	unsigned long ret = rec->retval;

	rec->a3 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_io_uring_register: rejected suspicious "
			  "post_state=%p (pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as an
	 * io_uring_register_post_state -- post_io_uring_register would
	 * then dispatch off a foreign opcode field and hand a foreign
	 * pointer to deferred_free_enqueue().
	 */
	if (snap->magic != IO_URING_REGISTER_POST_STATE_MAGIC) {
		outputerr("post_io_uring_register: rejected snap with bad "
			  "magic 0x%lx (post_state-stomped to foreign "
			  "allocation?)\n", snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	/*
	 * Per-opcode STRONG-VAL.  io_uring_register(2) is a multiplexer;
	 * each opcode has its own retval shape but every opcode shares the
	 * same -1UL failure return via the syscall return path.  On a
	 * non-failure return, three families of shape exist:
	 *
	 *   IORING_REGISTER_RING_FDS / IORING_UNREGISTER_RING_FDS: kernel
	 *     loops over the user-supplied ring-fd array in
	 *     fs/io_uring/register.c::io_ringfd_register /
	 *     io_ringfd_unregister and returns the loop count, bounded by
	 *     nr_args (rec->a4).  Anything > nr_args is a structural
	 *     regression: torn write of the count or -errno leaking through
	 *     the success return slot.
	 *
	 *   IORING_REGISTER_PERSONALITY: kernel allocates a personality id
	 *     via xa_alloc_cyclic() with XA_LIMIT(1, INT_MAX) and returns
	 *     the new id.  0 or any value > INT_MAX would be a structural
	 *     regression -- xa_alloc_cyclic() never returns 0 with that
	 *     limit, and ids do not legitimately span the high half of an
	 *     unsigned long.
	 *
	 *   All other emitted opcodes (BUFFERS / FILES / EVENTFD /
	 *     EVENTFD_ASYNC / FILES_UPDATE / BUFFERS_UPDATE / IOWQ_AFF /
	 *     IOWQ_MAX_WORKERS / FILE_ALLOC_RANGE / SYNC_CANCEL / NAPI /
	 *     PROBE / RESTRICTIONS / ENABLE_RINGS / *_UPDATE / etc.):
	 *     kernel returns 0 on success.  Any non-zero, non-(-1UL) value
	 *     is a sign-extension tear at the syscall ABI boundary or
	 *     -errno leaking through the success slot.  This default is
	 *     fail-soft for any future opcode the kernel adds: legitimate
	 *     0/-1UL still passes; only a spurious mid-range retval trips.
	 *
	 * Validate using the snapshot's opcode (not rec->a2) so a sibling
	 * scribble of rec->a2 cannot misroute the dispatch.  -1UL fall-
	 * through is intentional -- every opcode's documented failure path
	 * lands there.  The buffer cleanup tail below runs unchanged on
	 * every retval shape so heap allocations are released either way.
	 */
	if (ret != (unsigned long)-1L) {
		switch (snap->opcode) {
		case IORING_REGISTER_RING_FDS:
		case IORING_UNREGISTER_RING_FDS:
			if (ret > rec->a4) {
				outputerr("post_io_uring_register: opcode=%u rejected count retval=0x%lx > nr_args=%lu\n",
					  snap->opcode, ret, rec->a4);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
			break;
		case IORING_REGISTER_PERSONALITY:
			if (ret < 1 || ret > (unsigned long) INT_MAX) {
				outputerr("post_io_uring_register: opcode=PERSONALITY rejected id retval=0x%lx outside [1, INT_MAX]\n",
					  ret);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
			break;
		default:
			if (ret != 0) {
				outputerr("post_io_uring_register: opcode=%u rejected RZS retval=0x%lx (expected 0 or -1UL)\n",
					  snap->opcode, ret);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
			break;
		}
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner pointer may no longer reference our heap allocation.
	 * NULL is a legitimate value here (most opcodes do not allocate),
	 * so only flag a non-NULL value that fails the heuristic.  Leak
	 * rather than hand garbage to free().
	 */
	if (snap->original_alloc != NULL &&
	    looks_like_corrupted_ptr(rec, snap->original_alloc)) {
		outputerr("post_io_uring_register: rejected suspicious snap "
			  "original_alloc=%p (post_state-scribbled?)\n",
			  snap->original_alloc);
		deferred_freeptr(&rec->post_state);
		return;
	}

	/*
	 * Belt-and-suspenders: only release if both the snapshot's
	 * opcode says we allocated and we actually have a non-NULL heap
	 * pointer to release.  deferred_free_enqueue() (not
	 * deferred_freeptr) so concurrent observers that grabbed the
	 * address from rec->a3 before a scribble do not UAF.
	 */
	if (snap->original_alloc != NULL && snap->opcode == IORING_REGISTER_BUFFERS)
		deferred_free_enqueue(snap->original_alloc);

	deferred_freeptr(&rec->post_state);
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
};
