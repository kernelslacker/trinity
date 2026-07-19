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
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "syscall-gate.h"
#include "childops-iouring.h"
#include "childops/io_uring/ring.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
#include "kernel/unistd.h"
#ifndef __NR_io_uring_register
#define __NR_io_uring_register	427
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

/* IORING_REGISTER_NAPI / IORING_UNREGISTER_NAPI are also enum members
 * (introduced in 6.9), so the same shim shape applies — define op numbers
 * if the build env's uapi predates them.  struct io_uring_napi itself
 * cannot be #ifndef-detected; we assume uapi has it (kernel 6.9+).  On
 * older kernels the syscall just returns EINVAL/ENOTTY and we move on. */
#ifndef IORING_REGISTER_NAPI
#define IORING_REGISTER_NAPI		27
#endif
#ifndef IORING_UNREGISTER_NAPI
#define IORING_UNREGISTER_NAPI		28
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

static bool ms_submit(struct iour_ring *ctx, struct io_uring_sqe *sqe, unsigned int n)
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

static int ms_enter(struct iour_ring *ctx, unsigned int n, unsigned int min_complete)
{
	return (int)trinity_raw_syscall(__NR_io_uring_enter, ctx->fd, n, min_complete,
			    IORING_ENTER_GETEVENTS, NULL, 0);
}

static unsigned int ms_drain(struct iour_ring *ctx)
{
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail;
	unsigned int reaped = 0;

	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
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
static bool register_pbuf_ring(struct iour_ring *ctx,
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

	r = (int)trinity_raw_syscall(__NR_io_uring_register, ctx->fd,
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

static void unregister_pbuf_ring(struct iour_ring *ctx,
				 void *ring, void *data)
{
	struct io_uring_buf_reg reg;

	memset(&reg, 0, sizeof(reg));
	reg.bgid = PBUF_GROUP_ID;
	(void)trinity_raw_syscall(__NR_io_uring_register, ctx->fd,
		      IORING_UNREGISTER_PBUF_RING, &reg, 1);

	munmap(data, (size_t)PBUF_COUNT * PBUF_SIZE);
	munmap(ring, PBUF_RING_BYTES);
}

/*
 * Legacy fallback: PROVIDE_BUFFERS opcode.  Returns malloc'd buffer block
 * via *out_bufs (caller free()s) on success.  On failure, no resources
 * need releasing.
 */
static bool provide_buffers_legacy(struct iour_ring *ctx, void **out_bufs)
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

static void remove_buffers_legacy(struct iour_ring *ctx, void *bufs)
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

/*
 * Per-iteration scratchpad shared across the iouring_multishot_iter_<phase>
 * helpers.  Embeds the ring/SQ/CQ state owned by the iour_ring helper and adds the
 * UDP socket pair, bound port, provided-buffer pool handles, and the
 * NAPI-armed flag the post-burst probes consult.  Mirrors the
 * iouring_send_zc_iter_ctx shape: fds + ring/buffer ptrs + flags the
 * helpers actually share.
 */
struct iouring_multishot_iter_ctx {
	struct iour_ring ms;
	int		rxfd;
	int		txfd;
	uint16_t	port;
	void		*pbuf_ring;
	void		*pbuf_data;
	void		*legacy_bufs;
	bool		used_pbuf_ring;
	bool		napi_armed;
};

/*
 * Stand up the provided-buffer pool.  Tries the modern ring-based
 * IORING_REGISTER_PBUF_RING first, then falls back to the legacy
 * PROVIDE_BUFFERS opcode on EINVAL (pre-5.19 kernels) so the multishot
 * path stays reachable on older builds without per-version branching.
 * Returns 0 on success; nonzero means the caller should bail to the
 * shared teardown path.
 */
static int iouring_multishot_iter_setup_pbufs(struct iouring_multishot_iter_ctx *it)
{
	if (register_pbuf_ring(&it->ms, &it->pbuf_ring, &it->pbuf_data)) {
		it->used_pbuf_ring = true;
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.pbuf_ring_ok,
				   1, __ATOMIC_RELAXED);
	} else if (provide_buffers_legacy(&it->ms, &it->legacy_bufs)) {
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.pbuf_legacy_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Open the loopback UDP socket pair: rxfd is bound on 127.0.0.1 to an
 * ephemeral port (recovered into it->port) and will carry the multishot
 * RECV; txfd is the unbound sender used for the traffic burst.  Returns
 * 0 on success; nonzero means the caller should bail to the shared
 * teardown path, which closes whichever fd already came up.
 */
static int iouring_multishot_iter_setup_sockets(struct iouring_multishot_iter_ctx *it)
{
	it->rxfd = open_udp_loopback(&it->port);
	if (it->rxfd < 0) {
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	it->txfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (it->txfd < 0) {
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Optionally register NAPI busy-poll on the ring before arming the
 * multishot.  Pre-6.9 kernels return EINVAL/ENOTTY; we ignore the
 * error and continue.  The interesting coverage is the register +
 * later unregister cycle wrapping the multishot lifecycle, so
 * it->napi_armed latches success and the post-burst stale-NAPI probe
 * consults it later.
 */
static void iouring_multishot_iter_arm_napi(struct iouring_multishot_iter_ctx *it)
{
	struct io_uring_napi napi_in;
	int r;

	if (!ONE_IN(2))
		return;

	memset(&napi_in, 0, sizeof(napi_in));
	napi_in.busy_poll_to     = (__u32)rnd_modulo_u32(200);
	napi_in.prefer_busy_poll = (__u8)(rnd_u32() & 1);

	r = (int)trinity_raw_syscall(__NR_io_uring_register, it->ms.fd,
			 IORING_REGISTER_NAPI, &napi_in, 1);
	if (r == 0) {
		it->napi_armed = true;
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.napi_register_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.napi_register_fail,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Submit the multishot RECV SQE that arms the request on the socket
 * wait queue.  ioprio carries IORING_RECV_MULTISHOT; flags carries
 * IOSQE_BUFFER_SELECT; buf_group selects the pool registered by
 * iouring_multishot_iter_setup_pbufs.  addr=0 / len=0 — kernel picks
 * the buffer for us at completion time.  Returns 0 once the request
 * has been published via ms_enter; nonzero means the caller should
 * bail to the shared teardown path.
 */
static int iouring_multishot_iter_arm_recv(struct iouring_multishot_iter_ctx *it)
{
	struct io_uring_sqe sqe;
	int r;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode    = IORING_OP_RECV;
	sqe.fd        = it->rxfd;
	sqe.addr      = 0;
	sqe.len       = 0;
	sqe.ioprio    = IORING_RECV_MULTISHOT;
	sqe.flags     = IOSQE_BUFFER_SELECT;
	sqe.buf_group = PBUF_GROUP_ID;
	sqe.user_data = MULTISHOT_USER_DATA;

	if (!ms_submit(&it->ms, &sqe, 1))
		return -1;
	r = ms_enter(&it->ms, 1, 0);
	if (r < 0)
		return -1;
	__atomic_add_fetch(&shm->stats.iouring_net_multishot.armed,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Drive multishot completions: short burst of UDP packets from txfd
 * to the rxfd's bound port, then a non-blocking ms_enter + ms_drain to
 * reap whatever CQEs the kernel posted.  Each accepted packet posts
 * one CQE on the multishot SQE.  Loopback SOCK_DGRAM never blocks the
 * sender for a small burst, but the packet count is capped so a stuck
 * receiver doesn't accumulate unbounded sk buffer charge.
 */
static void iouring_multishot_iter_traffic(struct iouring_multishot_iter_ctx *it)
{
	struct sockaddr_in dst;
	const char payload[64] = "trinity-multishot-payload";
	unsigned int npkts, i;
	int r;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dst.sin_port = it->port;

	npkts = MIN_PKTS + rnd_modulo_u32(MAX_PKTS - MIN_PKTS + 1);
	for (i = 0; i < npkts; i++) {
		ssize_t n = sendto(it->txfd, payload, sizeof(payload), 0,
				   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.iouring_net_multishot.packets_sent,
					   1, __ATOMIC_RELAXED);
	}

	r = ms_enter(&it->ms, 0, 0);
	if (r >= 0) {
		unsigned int reaped = ms_drain(&it->ms);

		__atomic_add_fetch(&shm->stats.iouring_net_multishot.completions,
				   (unsigned long)reaped, __ATOMIC_RELAXED);
	}
}

/*
 * Post-burst race probes.  First issues IORING_OP_ASYNC_CANCEL with
 * USERDATA match — drives the cancel walker through io_uring/cancel.c
 * and tears down the request while io_uring/net.c may still be in the
 * middle of posting the next completion (the targeted overlap).  If
 * NAPI was armed, also runs the stale-NAPI probe (upstream b8c2e9e27636):
 * IORING_UNREGISTER_NAPI followed by one more multishot RECV + drain
 * exercises any post-unregister stale state in io_uring/net.c and
 * io_uring/napi.c.  Kernel writes the previous napi config back into
 * the passed struct, so it must be writable.
 */
static void iouring_multishot_iter_cancel(struct iouring_multishot_iter_ctx *it)
{
	struct io_uring_sqe sqe;
	struct io_uring_napi napi_out;
	int r;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode       = IORING_OP_ASYNC_CANCEL;
	sqe.fd           = -1;
	sqe.addr         = MULTISHOT_USER_DATA;
	sqe.cancel_flags = IORING_ASYNC_CANCEL_USERDATA;
	sqe.user_data    = CANCEL_USER_DATA;

	if (ms_submit(&it->ms, &sqe, 1)) {
		r = ms_enter(&it->ms, 1, 0);
		if (r >= 0) {
			__atomic_add_fetch(&shm->stats.iouring_net_multishot.cancel_submitted,
					   1, __ATOMIC_RELAXED);
			(void)ms_drain(&it->ms);
		}
	}

	if (!it->napi_armed)
		return;

	memset(&napi_out, 0, sizeof(napi_out));
	r = (int)trinity_raw_syscall(__NR_io_uring_register, it->ms.fd,
			 IORING_UNREGISTER_NAPI, &napi_out, 1);
	if (r == 0)
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.napi_unregister_ok,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.iouring_net_multishot.napi_unregister_fail,
				   1, __ATOMIC_RELAXED);

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode    = IORING_OP_RECV;
	sqe.fd        = it->rxfd;
	sqe.addr      = 0;
	sqe.len       = 0;
	sqe.ioprio    = IORING_RECV_MULTISHOT;
	sqe.flags     = IOSQE_BUFFER_SELECT;
	sqe.buf_group = PBUF_GROUP_ID;
	sqe.user_data = MULTISHOT_USER_DATA;

	if (ms_submit(&it->ms, &sqe, 1)) {
		r = ms_enter(&it->ms, 1, 0);
		if (r >= 0)
			(void)ms_drain(&it->ms);
	}
}

bool iouring_net_multishot(struct childdata *child)
{
	struct iouring_multishot_iter_ctx it;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.iouring_net_multishot.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	memset(&it, 0, sizeof(it));
	it.rxfd = -1;
	it.txfd = -1;

	{
		struct io_uring_params p;
		enum iour_setup_status st;

		memset(&p, 0, sizeof(p));
		st = iour_ring_setup(&p, RING_ENTRIES, &it.ms);
		if (st != IOUR_SUPPORTED) {
			if (st == IOUR_UNSUPPORTED) {
				ns_unsupported = true;
				if (valid_op)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
			__atomic_add_fetch(&shm->stats.iouring_net_multishot.setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	if (iouring_multishot_iter_setup_pbufs(&it) != 0)
		goto out;

	if (iouring_multishot_iter_setup_sockets(&it) != 0)
		goto out;

	iouring_multishot_iter_arm_napi(&it);

	if (iouring_multishot_iter_arm_recv(&it) != 0)
		goto out;
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	iouring_multishot_iter_traffic(&it);
	iouring_multishot_iter_cancel(&it);

out:
	if (it.txfd >= 0)
		close(it.txfd);
	if (it.rxfd >= 0)
		close(it.rxfd);
	if (it.used_pbuf_ring) {
		if (it.pbuf_ring)
			unregister_pbuf_ring(&it.ms, it.pbuf_ring, it.pbuf_data);
	} else if (it.legacy_bufs) {
		remove_buffers_legacy(&it.ms, it.legacy_bufs);
	}
	iour_ring_teardown(&it.ms);
	return true;
}
