/*
 * iouring_net_multishot - io_uring multishot RECV on a UDP socket fed by a
 * sibling sender, racing IORING_OP_ASYNC_CANCEL against the multishot
 * lifecycle.
 *
 * Trinity already exercises one-shot io_uring SQEs (iouring_recipes covers
 * PROVIDE_BUFFERS + single RECV with IOSQE_BUFFER_SELECT, iouring_flood
 * floods the submission fast path).  What flat fuzzing essentially never
 * assembles is the multishot LIFECYCLE: a single SQE that re-arms on every
 * RX completion, dispatched against a registered buffer pool, then taken
 * down by ASYNC_CANCEL while completions are still in flight.  Multishot
 * net opcodes register the request on the socket's wait queue and re-post
 * a CQE for every receive — the bug class is "request still on the wait
 * queue when the socket / buffer pool is freed", which only fires when
 * the chain is assembled in order.
 *
 * Sequence:
 *   1. io_uring_setup with a small ring (32 SQ / 64 CQ entries).
 *   2. Try IORING_REGISTER_PBUF_RING (modern ring-based buffer pool); if
 *      the kernel rejects it (EINVAL on pre-5.19), fall back to the legacy
 *      IORING_OP_PROVIDE_BUFFERS path.  Either gives the kernel a buffer
 *      group it can pick from when servicing IOSQE_BUFFER_SELECT.
 *   3. socket(AF_INET, SOCK_DGRAM); bind to 127.0.0.1 ephemeral; getsockname
 *      to recover the assigned port.
 *   4. Submit IORING_OP_RECV with IORING_RECV_MULTISHOT (in ioprio) and
 *      IOSQE_BUFFER_SELECT (in flags), buf_group = our group id.
 *   5. io_uring_enter to publish; the request is now armed on the socket.
 *   6. From a separate UDP socket, sendto() N small packets to the bound
 *      port — each drives one multishot completion (CQE_F_MORE on all but
 *      the last; the final CQE may clear it on cancel/error).
 *   7. io_uring_enter again to drain pending completions, advancing CQ
 *      head as we go.
 *   8. Submit IORING_OP_ASYNC_CANCEL with IORING_ASYNC_CANCEL_USERDATA
 *      keyed on the multishot SQE's user_data.  Race window: the multishot
 *      may still be in the middle of posting a completion when the cancel
 *      walks the request list.
 *   9. Final io_uring_enter + drain, then teardown (unregister buffers,
 *      close sockets, munmap rings, close ring fd).
 *
 * CVE class: multishot completion accounting (CVE-2024-35915 multishot
 * recv leak), buffer-pool refcount (recurring io_uring/kbuf.c bugs), and
 * cancel-vs-completion races (CVE-2024-26771 io_uring poll re-arm,
 * CVE-2024-0582 io_uring iov UAF).  Subsystems reached: io_uring/net.c
 * (multishot dispatch + io_recv path), io_uring/kbuf.c (provided buffer
 * selection), io_uring/cancel.c (ASYNC_CANCEL match/cancel walk).
 *
 * Self-bounding: one full cycle per invocation.  Packet count is small
 * (4..16) so sibling RX queues never grow large.  Buffer pool is 8 buffers
 * of 256 bytes.  All sockets are loopback DGRAM — no external traffic, no
 * external ports.  Sockets and ring fd are O_CLOEXEC; child.c's alarm(1)
 * caps wall-clock if io_uring_enter ever blocks (it shouldn't with
 * IORING_ENTER_GETEVENTS and min_complete sized to what we've already seen
 * arrive on the socket).
 *
 * Failure modes are all expected coverage: ENOSYS (no CONFIG_IO_URING),
 * EPERM (kernel.io_uring_disabled sysctl), EINVAL on the modern PBUF_RING
 * register (older kernels), EADDRINUSE / EAGAIN on the loopback bind, and
 * zero-completion races where the cancel beats the first packet.  We
 * never propagate any of these as childop failure — they're all kernel
 * code-path coverage.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/io_uring.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#define __NR_io_uring_enter	426
#define __NR_io_uring_register	427
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_CQ_RING	0x8000000ULL
#define IORING_OFF_SQES		0x10000000ULL
#endif

/* IORING_REGISTER_PBUF_RING and friends are enum members in the uapi
 * header, so a plain #ifndef can't detect them.  Define them as macro
 * fallbacks for the rare build environment whose uapi predates them; if
 * the header already has them as enums the values match, and on older
 * kernels the syscall just returns EINVAL and we fall back to the legacy
 * PROVIDE_BUFFERS path at runtime.  io_uring_buf / io_uring_buf_reg
 * structs are required and assumed present — the build env has them. */
#ifndef IORING_REGISTER_PBUF_RING
#define IORING_REGISTER_PBUF_RING	22
#endif
#ifndef IORING_UNREGISTER_PBUF_RING
#define IORING_UNREGISTER_PBUF_RING	23
#endif

#ifndef IORING_RECV_MULTISHOT
#define IORING_RECV_MULTISHOT	(1U << 1)
#endif

#ifndef IORING_ASYNC_CANCEL_USERDATA
#define IORING_ASYNC_CANCEL_USERDATA	(1U << 4)
#endif

/* Buffer pool geometry: 8 buffers * 256 bytes == 2 KiB total.  Small on
 * purpose — the goal is to exercise the multishot re-arm + buffer
 * selection lifecycle, not move bulk data.  Power-of-two count is
 * required by IORING_REGISTER_PBUF_RING. */
#define PBUF_GROUP_ID		7
#define PBUF_COUNT		8U
#define PBUF_SIZE		256U
#define PBUF_RING_BYTES		((size_t)PBUF_COUNT * sizeof(struct io_uring_buf))

/* Per-cycle packet burst sent from the peer socket.  Bounded so the
 * receive socket's queue stays small even if cancel races a few drains. */
#define MIN_PKTS		4U
#define MAX_PKTS		16U

#define RING_ENTRIES		32U

#define MULTISHOT_USER_DATA	0xb1u
#define CANCEL_USER_DATA	0xc7u

/* Latched per-child: io_uring_setup returned ENOSYS or EPERM once.  The
 * kernel was built without CONFIG_IO_URING, or io_uring is disabled by
 * sysctl — neither flips during this process's lifetime, so further
 * attempts are pure overhead. */
static bool ns_unsupported;

struct ms_ctx {
	int		fd;
	void		*sq_ring;
	void		*cq_ring;	/* aliases sq_ring when SINGLE_MMAP */
	void		*sqes;
	size_t		sq_ring_sz;
	size_t		cq_ring_sz;	/* 0 when SINGLE_MMAP */
	size_t		sqes_sz;
	bool		single_mmap;

	unsigned int	sq_entries;

	unsigned int	sq_off_head;
	unsigned int	sq_off_tail;
	unsigned int	sq_off_mask;
	unsigned int	sq_off_array;

	unsigned int	cq_off_head;
	unsigned int	cq_off_tail;
	unsigned int	cq_off_mask;
	unsigned int	cq_off_cqes;
};

static inline unsigned int ring_u32(void *ring, unsigned int off)
{
	return *(volatile unsigned int *)((char *)ring + off);
}

static inline void ring_store_u32(void *ring, unsigned int off, unsigned int v)
{
	*(volatile unsigned int *)((char *)ring + off) = v;
}

static bool ms_setup(struct ms_ctx *ctx)
{
	struct io_uring_params p;
	size_t sq_sz, cq_sz, sqes_sz;
	void *sq_ring, *cq_ring, *sqes;
	int fd;

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;

	memset(&p, 0, sizeof(p));
	fd = (int)syscall(__NR_io_uring_setup, RING_ENTRIES, &p);
	if (fd < 0)
		return false;

	sq_sz   = (size_t)p.sq_off.array + (size_t)p.sq_entries * sizeof(unsigned int);
	cq_sz   = (size_t)p.cq_off.cqes  + (size_t)p.cq_entries * sizeof(struct io_uring_cqe);
	sqes_sz = (size_t)p.sq_entries   * sizeof(struct io_uring_sqe);

	sq_ring = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	if (sq_ring == MAP_FAILED) {
		close(fd);
		return false;
	}

	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		cq_ring = sq_ring;
		ctx->single_mmap = true;
	} else {
		cq_ring = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE,
			       fd, IORING_OFF_CQ_RING);
		if (cq_ring == MAP_FAILED) {
			munmap(sq_ring, sq_sz);
			close(fd);
			return false;
		}
	}

	sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		if (!ctx->single_mmap)
			munmap(cq_ring, cq_sz);
		munmap(sq_ring, sq_sz);
		close(fd);
		return false;
	}

	ctx->fd          = fd;
	ctx->sq_ring     = sq_ring;
	ctx->sq_ring_sz  = sq_sz;
	ctx->cq_ring     = cq_ring;
	ctx->cq_ring_sz  = ctx->single_mmap ? 0 : cq_sz;
	ctx->sqes        = sqes;
	ctx->sqes_sz     = sqes_sz;
	ctx->sq_entries  = p.sq_entries;

	ctx->sq_off_head  = p.sq_off.head;
	ctx->sq_off_tail  = p.sq_off.tail;
	ctx->sq_off_mask  = p.sq_off.ring_mask;
	ctx->sq_off_array = p.sq_off.array;

	ctx->cq_off_head  = p.cq_off.head;
	ctx->cq_off_tail  = p.cq_off.tail;
	ctx->cq_off_mask  = p.cq_off.ring_mask;
	ctx->cq_off_cqes  = p.cq_off.cqes;

	return true;
}

static void ms_teardown(struct ms_ctx *ctx)
{
	if (ctx->sqes)
		munmap(ctx->sqes, ctx->sqes_sz);
	if (ctx->cq_ring && !ctx->single_mmap)
		munmap(ctx->cq_ring, ctx->cq_ring_sz);
	if (ctx->sq_ring)
		munmap(ctx->sq_ring, ctx->sq_ring_sz);
	if (ctx->fd >= 0)
		close(ctx->fd);
}

static bool ms_submit(struct ms_ctx *ctx, struct io_uring_sqe *sqe, unsigned int n)
{
	unsigned int mask  = ring_u32(ctx->sq_ring, ctx->sq_off_mask);
	unsigned int head  = ring_u32(ctx->sq_ring, ctx->sq_off_head);
	unsigned int tail  = ring_u32(ctx->sq_ring, ctx->sq_off_tail);
	unsigned int avail = ctx->sq_entries - (tail - head);
	unsigned int *sq_array;
	struct io_uring_sqe *sqes = ctx->sqes;
	unsigned int i;

	if (n > avail)
		return false;

	sq_array = (unsigned int *)((char *)ctx->sq_ring + ctx->sq_off_array);

	for (i = 0; i < n; i++) {
		unsigned int slot = (tail + i) & mask;

		sqes[slot] = sqe[i];
		sq_array[slot] = slot;
	}

	__sync_synchronize();
	ring_store_u32(ctx->sq_ring, ctx->sq_off_tail, tail + n);
	return true;
}

static int ms_enter(struct ms_ctx *ctx, unsigned int n, unsigned int min_complete)
{
	return (int)syscall(__NR_io_uring_enter, ctx->fd, n, min_complete,
			    IORING_ENTER_GETEVENTS, NULL, 0);
}

static unsigned int ms_drain(struct ms_ctx *ctx)
{
	unsigned int mask = ring_u32(ctx->cq_ring, ctx->cq_off_mask);
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail;
	unsigned int reaped = 0;
	struct io_uring_cqe *cqes;

	cqes = (struct io_uring_cqe *)((char *)ctx->cq_ring + ctx->cq_off_cqes);
	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
		(void)cqes[head & mask];
		head++;
		reaped++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);
	return reaped;
}

/*
 * Modern provided-buffer ring registration.  Allocates a page-aligned
 * region (mmap to guarantee alignment), populates it with PBUF_COUNT
 * buffer descriptors pointing into a separate data region, and registers
 * it with the kernel via IORING_REGISTER_PBUF_RING.
 *
 * On older kernels (pre-5.19) the register call returns EINVAL; the
 * caller falls back to the legacy PROVIDE_BUFFERS opcode.  Both ring and
 * data regions are returned via *out_ring / *out_data so the caller can
 * unmap them after teardown.
 */
static bool register_pbuf_ring(struct ms_ctx *ctx,
			       void **out_ring, void **out_data)
{
	struct io_uring_buf_reg reg;
	struct io_uring_buf *bufs;
	void *ring;
	void *data;
	unsigned int i;
	int r;

	ring = mmap(NULL, PBUF_RING_BYTES, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ring == MAP_FAILED)
		return false;

	data = mmap(NULL, (size_t)PBUF_COUNT * PBUF_SIZE,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (data == MAP_FAILED) {
		munmap(ring, PBUF_RING_BYTES);
		return false;
	}

	memset(ring, 0, PBUF_RING_BYTES);
	bufs = (struct io_uring_buf *)ring;
	for (i = 0; i < PBUF_COUNT; i++) {
		bufs[i].addr = (__u64)(uintptr_t)((char *)data + i * PBUF_SIZE);
		bufs[i].len  = PBUF_SIZE;
		bufs[i].bid  = (__u16)i;
	}

	/* Publish all buffers by writing tail = PBUF_COUNT.  The tail field
	 * overlays io_uring_buf->resv at byte offset 14 within the first
	 * descriptor — see uapi io_uring_buf_ring union. */
	__sync_synchronize();
	*(volatile __u16 *)((char *)ring + 14) = (__u16)PBUF_COUNT;

	memset(&reg, 0, sizeof(reg));
	reg.ring_addr   = (__u64)(uintptr_t)ring;
	reg.ring_entries = PBUF_COUNT;
	reg.bgid        = PBUF_GROUP_ID;

	r = (int)syscall(__NR_io_uring_register, ctx->fd,
			 IORING_REGISTER_PBUF_RING, &reg, 1);
	if (r < 0) {
		munmap(data, (size_t)PBUF_COUNT * PBUF_SIZE);
		munmap(ring, PBUF_RING_BYTES);
		return false;
	}

	*out_ring = ring;
	*out_data = data;
	return true;
}

static void unregister_pbuf_ring(struct ms_ctx *ctx,
				 void *ring, void *data)
{
	struct io_uring_buf_reg reg;

	memset(&reg, 0, sizeof(reg));
	reg.bgid = PBUF_GROUP_ID;
	(void)syscall(__NR_io_uring_register, ctx->fd,
		      IORING_UNREGISTER_PBUF_RING, &reg, 1);

	munmap(data, (size_t)PBUF_COUNT * PBUF_SIZE);
	munmap(ring, PBUF_RING_BYTES);
}

/*
 * Legacy fallback: PROVIDE_BUFFERS opcode.  Returns malloc'd buffer block
 * via *out_bufs (caller free()s) on success.  On failure, no resources
 * need releasing.
 */
static bool provide_buffers_legacy(struct ms_ctx *ctx, void **out_bufs)
{
	struct io_uring_sqe sqe;
	void *bufs;
	int r;

	bufs = malloc((size_t)PBUF_COUNT * PBUF_SIZE);
	if (!bufs)
		return false;
	memset(bufs, 0, (size_t)PBUF_COUNT * PBUF_SIZE);

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode    = IORING_OP_PROVIDE_BUFFERS;
	sqe.addr      = (__u64)(uintptr_t)bufs;
	sqe.len       = PBUF_SIZE;
	sqe.fd        = (int)PBUF_COUNT;
	sqe.off       = 0;
	sqe.buf_group = PBUF_GROUP_ID;
	sqe.user_data = 0xb0;

	if (!ms_submit(ctx, &sqe, 1)) {
		free(bufs);
		return false;
	}
	r = ms_enter(ctx, 1, 1);
	if (r < 0) {
		free(bufs);
		return false;
	}
	(void)ms_drain(ctx);

	*out_bufs = bufs;
	return true;
}

static void remove_buffers_legacy(struct ms_ctx *ctx, void *bufs)
{
	struct io_uring_sqe sqe;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode    = IORING_OP_REMOVE_BUFFERS;
	sqe.fd        = (int)PBUF_COUNT;
	sqe.buf_group = PBUF_GROUP_ID;
	sqe.user_data = 0xb2;

	if (ms_submit(ctx, &sqe, 1)) {
		(void)ms_enter(ctx, 1, 0);
		(void)ms_drain(ctx);
	}
	free(bufs);
}

/*
 * Open a UDP socket bound to 127.0.0.1 with an ephemeral port; return
 * the bound port via *out_port (network byte order).  Returns -1 on
 * failure.  The socket is O_CLOEXEC.
 */
static int open_udp_loopback(uint16_t *out_port)
{
	struct sockaddr_in sin;
	socklen_t slen;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = 0;

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(fd);
		return -1;
	}

	slen = sizeof(sin);
	if (getsockname(fd, (struct sockaddr *)&sin, &slen) < 0) {
		close(fd);
		return -1;
	}
	*out_port = sin.sin_port;
	return fd;
}

bool iouring_net_multishot(struct childdata *child)
{
	struct ms_ctx ctx;
	struct io_uring_sqe sqe;
	int rxfd = -1, txfd = -1;
	uint16_t port = 0;
	void *pbuf_ring = NULL;
	void *pbuf_data = NULL;
	void *legacy_bufs = NULL;
	bool used_pbuf_ring = false;
	unsigned int npkts;
	unsigned int i;
	int r;

	(void)child;

	__atomic_add_fetch(&shm->stats.iouring_multishot_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	if (!ms_setup(&ctx)) {
		if (errno == ENOSYS || errno == EPERM)
			ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.iouring_multishot_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/* Try the modern ring-based buffer pool first.  Falls back to the
	 * legacy PROVIDE_BUFFERS opcode on EINVAL (pre-5.19 kernels), which
	 * keeps the multishot path reachable on older builds without
	 * special-casing per-kernel-version. */
	if (register_pbuf_ring(&ctx, &pbuf_ring, &pbuf_data)) {
		used_pbuf_ring = true;
		__atomic_add_fetch(&shm->stats.iouring_multishot_pbuf_ring_ok,
				   1, __ATOMIC_RELAXED);
	} else if (provide_buffers_legacy(&ctx, &legacy_bufs)) {
		__atomic_add_fetch(&shm->stats.iouring_multishot_pbuf_legacy_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.iouring_multishot_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	rxfd = open_udp_loopback(&port);
	if (rxfd < 0) {
		__atomic_add_fetch(&shm->stats.iouring_multishot_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	txfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (txfd < 0) {
		__atomic_add_fetch(&shm->stats.iouring_multishot_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Multishot RECV with buffer selection.  ioprio carries
	 * IORING_RECV_MULTISHOT; flags carries IOSQE_BUFFER_SELECT;
	 * buf_group selects our pool.  addr=0 / len=0 — kernel picks the
	 * buffer for us at completion time. */
	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode    = IORING_OP_RECV;
	sqe.fd        = rxfd;
	sqe.addr      = 0;
	sqe.len       = 0;
	sqe.ioprio    = IORING_RECV_MULTISHOT;
	sqe.flags     = IOSQE_BUFFER_SELECT;
	sqe.buf_group = PBUF_GROUP_ID;
	sqe.user_data = MULTISHOT_USER_DATA;

	if (!ms_submit(&ctx, &sqe, 1))
		goto out;
	r = ms_enter(&ctx, 1, 0);
	if (r < 0)
		goto out;
	__atomic_add_fetch(&shm->stats.iouring_multishot_armed,
			   1, __ATOMIC_RELAXED);

	/* Drive multishot completions: short burst of UDP packets.  Each
	 * accepted packet posts one CQE on the multishot SQE.  Loopback
	 * SOCK_DGRAM never blocks the sender for a small burst, but cap
	 * the count so a stuck receiver doesn't accumulate unbounded sk
	 * buffer charge. */
	{
		struct sockaddr_in dst;
		const char payload[64] = "trinity-multishot-payload";

		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		dst.sin_port = port;

		npkts = MIN_PKTS + ((unsigned int)rand() %
				    (MAX_PKTS - MIN_PKTS + 1));
		for (i = 0; i < npkts; i++) {
			ssize_t n = sendto(txfd, payload, sizeof(payload), 0,
					   (struct sockaddr *)&dst, sizeof(dst));
			if (n > 0)
				__atomic_add_fetch(&shm->stats.iouring_multishot_packets_sent,
						   1, __ATOMIC_RELAXED);
		}
	}

	r = ms_enter(&ctx, 0, 0);
	if (r >= 0) {
		unsigned int reaped = ms_drain(&ctx);

		__atomic_add_fetch(&shm->stats.iouring_multishot_completions,
				   (unsigned long)reaped, __ATOMIC_RELAXED);
	}

	/* Cancel the multishot.  USERDATA match drives the cancel walker
	 * through io_uring/cancel.c and tears down the request while
	 * io_uring/net.c may still be in the middle of posting the next
	 * completion — that overlap is the targeted race window. */
	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode       = IORING_OP_ASYNC_CANCEL;
	sqe.fd           = -1;
	sqe.addr         = MULTISHOT_USER_DATA;
	sqe.cancel_flags = IORING_ASYNC_CANCEL_USERDATA;
	sqe.user_data    = CANCEL_USER_DATA;

	if (ms_submit(&ctx, &sqe, 1)) {
		r = ms_enter(&ctx, 1, 0);
		if (r >= 0) {
			__atomic_add_fetch(&shm->stats.iouring_multishot_cancel_submitted,
					   1, __ATOMIC_RELAXED);
			(void)ms_drain(&ctx);
		}
	}

out:
	if (txfd >= 0)
		close(txfd);
	if (rxfd >= 0)
		close(rxfd);
	if (used_pbuf_ring) {
		if (pbuf_ring)
			unregister_pbuf_ring(&ctx, pbuf_ring, pbuf_data);
	} else if (legacy_bufs) {
		remove_buffers_legacy(&ctx, legacy_bufs);
	}
	ms_teardown(&ctx);
	return true;
}
