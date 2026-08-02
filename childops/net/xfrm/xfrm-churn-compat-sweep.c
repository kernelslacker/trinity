/*
 * xfrm-churn-compat-sweep - defensive netlink_xfrm opcode-space sweep
 * for the xfrm_churn childop.  Carved out of
 * childops/net/xfrm/xfrm-churn.c so the compat-table off-end-read
 * driver compiles as its own TU alongside the netlink builders,
 * inner-traffic drivers, and the other alt-path sub-modes.
 *
 * Pure relocation: the function body is byte-for-byte the same as
 * the original.  xfrm_compat_msg_sweep widens from file-static to
 * external linkage so the xfrm-churn.c teardown phase can reach it
 * across the TU boundary; the shared ns_unsupported_xfrm latch it
 * consults keeps its definition in xfrm-churn.c and picks up an
 * extern declaration in xfrm-churn-internal.h.
 */

#include <sys/mman.h>

#include "xfrm-churn-internal.h"

/*
 * Defensive sweep of the netlink_xfrm opcode space, targeting off-end
 * indexing in net/xfrm/xfrm_compat.c::xfrm_msg_min[] and the broader
 * xfrm_user dispatch.  Pre-fix (upstream 28465227c80f) the compat
 * translation table was sized only through XFRM_MSG_GETAE while the
 * UAPI grew XFRM_MSG_MAPPING; a 32-bit task issuing MAPPING walked
 * off the end reading garbage.  A 64-bit-only fuzz binary doesn't
 * itself enter the compat translator, but iterating the full
 * XFRM_MSG_BASE..XFRM_MSG_MAX range exercises every kernel-side
 * dispatch slot, catching any later off-end index added since.
 *
 * Per-iteration: rebuild a minimal nlmsghdr with a fixed 64-byte
 * payload tail (small enough not to exceed any opcode's max, large
 * enough to satisfy the smaller of the 32-bit / 64-bit struct
 * minimums for most opcodes), sendto the bound NETLINK_XFRM fd
 * MSG_DONTWAIT, drain at most one reply per send.  Most opcodes
 * reject with EINVAL / E2BIG / EOPNOTSUPP — that's fine, the
 * dispatch slot lookup happens before the validation that emits the
 * rejection.  All I/O is non-blocking so the inner loop can't stall
 * past the SIGALRM(1s) cap.
 */
void xfrm_compat_msg_sweep(struct nl_ctx *ctx)
{
	struct sockaddr_nl dst;
	unsigned char buf[256];
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	unsigned int t;
	size_t off;
	ssize_t n;

	if (ns_unsupported_xfrm)
		return;

	__atomic_add_fetch(&shm->stats.xfrm_compat.sweep_runs,
			   1, __ATOMIC_RELAXED);

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	for (t = XFRM_MSG_NEWSA; t <= XFRM_COMPAT_SWEEP_MAX; t++) {
		memset(buf, 0, sizeof(buf));
		nlh = (struct nlmsghdr *)buf;
		nlh->nlmsg_type  = (__u16)t;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		nlh->nlmsg_seq   = nl_seq_next(ctx);
		off = NLMSG_HDRLEN + NLMSG_ALIGN(64);
		nlh->nlmsg_len   = (__u32)off;

		if (sendto(ctx->fd, buf, off, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			__atomic_add_fetch(&shm->stats.xfrm_compat.sends_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}
		__atomic_add_fetch(&shm->stats.xfrm_compat.sends_ok,
				   1, __ATOMIC_RELAXED);

		n = recv(ctx->fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
		if (n > 0)
			__atomic_add_fetch(&shm->stats.xfrm_compat.replies_seen,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * ALLOCSPI compat-mode driver.  xfrm_alloc_userspi() invokes
 * alloc_compat() on the original request skb AND dump_one_state() —
 * which produces the ALLOCSPI response — invokes it again on the
 * response skb.  For a compat request the translator interprets the
 * 228-byte compat xfrm_userspi_info as the 232-byte native layout and
 * reads four bytes past the declared payload; whether that overreads
 * into slab red-zone / next-allocation depends on payload sizing.  A
 * pure 64-bit fuzz binary never enters alloc_compat() — in_compat_syscall()
 * is false — so this lane deliberately routes the sendto through the
 * x86-64 ia32 compat entry (int 0x80) which sets TS_COMPAT before
 * dispatch.  Every user pointer visible to the compat wrapper must fit
 * in the low 4 GiB; we back the scratch with MAP_32BIT.
 *
 * Oracle: KASAN slab-OOB read fires from xfrm_compat.c on the
 * post-fix window; no additional user-side check is needed.
 *
 * Sweep axes per invocation:
 *   payload length ∈ {220, 222, 224, 226, 228, 230, 232, 234, 236}
 *     — straddles the 228-byte compat size so the 4-byte overread
 *       crosses the kmalloc allocation boundary rather than landing in
 *       intra-allocation slack;
 *   family        ∈ {AF_INET, AF_INET6};
 *   min / max     — random within [XFRM_SPI_MIN, XFRM_SPI_MIN+RANGE-1];
 *   reqid         — random within [1, XFRM_REQID_RANGE].
 *
 * Latches: ns_unsupported_xfrm short-circuits the whole lane.  A
 * per-child compat_int80_unsupported latch trips on the first ENOSYS
 * from the ia32 entry (kernel built without CONFIG_IA32_EMULATION —
 * some hardened / arm64 configs).  MAP_32BIT allocation failure trips
 * the same latch.  Non-x86_64 architectures compile the lane out
 * entirely at #ifdef time.
 */

#if defined(__x86_64__)

#ifndef MAP_32BIT
/* Linux/x86-64-only; header shim keeps -Werror quiet on stripped sysroots. */
#define MAP_32BIT		0x40
#endif

/* i386 socketcall multiplexer; sub-call for sendto. */
#define COMPAT_NR_SOCKETCALL	102
#define COMPAT_SYS_SENDTO	11

/* MAP_32BIT arena carrying the sendto arg array, the destination
 * sockaddr_nl, and the netlink message payload.  All three must live
 * below 4 GiB because the ia32 socketcall wrapper zero-extends each
 * user pointer through compat_ptr().  Layout:
 *   [0                        .. sizeof(compat_sendto_args))  args
 *   [args_end (padded to 8)   .. +sizeof(sockaddr_nl))        dst addr
 *   [addr_end (padded to 8)   ..                       )      nlmsghdr + body
 * A single 4 KiB page is ample: the largest sweep length is 236 + 16 (nlmsghdr).
 */
#define COMPAT_LOW_ARENA_BYTES	4096

struct compat_sendto_args {
	__u32	fd;
	__u32	buf;		/* low-32 pointer to netlink message */
	__u32	len;
	__u32	flags;
	__u32	dst;		/* low-32 pointer to sockaddr_nl */
	__u32	dstlen;
};

static __thread unsigned char *compat_low_arena;
static __thread bool compat_int80_unsupported;

static bool compat_low_arena_ready(void)
{
	void *p;

	if (compat_int80_unsupported)
		return false;
	if (compat_low_arena)
		return true;
	p = mmap(NULL, COMPAT_LOW_ARENA_BYTES, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	if (p == MAP_FAILED) {
		compat_int80_unsupported = true;
		return false;
	}
	/* Sanity: MAP_32BIT should give a low pointer; if the kernel
	 * silently ignored the flag (very old kernel) the address will be
	 * high and the sendto pointers won't round-trip.  Latch off. */
	if ((uintptr_t)p >> 32) {
		munmap(p, COMPAT_LOW_ARENA_BYTES);
		compat_int80_unsupported = true;
		return false;
	}
	compat_low_arena = (unsigned char *)p;
	return true;
}

/* Direct int-0x80 socketcall.  All pointers passed through *args must
 * live in the MAP_32BIT arena.  Returns the raw kernel return value;
 * -ENOSYS on kernels without CONFIG_IA32_EMULATION. */
static long compat_int80_socketcall(unsigned int call, const void *args)
{
	long ret;

	asm volatile (
		"int $0x80\n\t"
		: "=a" (ret)
		: "0" (COMPAT_NR_SOCKETCALL),
		  "b" (call),
		  "c" ((unsigned int)(uintptr_t)args)
		: "cc", "memory"
	);
	return ret;
}

/* Build the ALLOCSPI request body into buf at offset 0 and return its
 * total length in bytes.  payload_len is the size claimed by
 * nlmsghdr::nlmsg_len for the trailing xfrm_userspi_info; sweeping it
 * around the 228-byte compat struct size is the whole point of this
 * lane. */
static size_t compat_build_allocspi(unsigned char *buf, size_t cap,
				    __u32 seq, __u16 family,
				    size_t payload_len)
{
	struct nlmsghdr *nlh;
	struct xfrm_userspi_info *spi_info;
	size_t total;
	__u32 min_spi, max_spi, spi_range;

	total = NLMSG_HDRLEN + NLMSG_ALIGN(payload_len);
	if (total > cap)
		return 0;
	memset(buf, 0, total);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_ALLOCSPI;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = seq;
	nlh->nlmsg_len   = (__u32)total;

	spi_info = (struct xfrm_userspi_info *)NLMSG_DATA(nlh);
	xfrm_churn_fill_selector(&spi_info->info.sel, IPPROTO_UDP);
	spi_info->info.sel.family  = family;
	spi_info->info.id.daddr.a4 = XFRM_DADDR_BE;
	spi_info->info.id.spi      = 0;
	spi_info->info.id.proto    = IPPROTO_ESP;
	spi_info->info.saddr.a4    = XFRM_SADDR_BE;
	xfrm_churn_fill_lifetime(&spi_info->info.lft);
	spi_info->info.reqid  = (rand32() % XFRM_REQID_RANGE) + 1U;
	spi_info->info.family = family;
	spi_info->info.mode   = XFRM_MODE_TRANSPORT;
	spi_info->info.replay_window = 32;
	spi_info->info.flags  = 0;

	spi_range = XFRM_SPI_RANGE;
	min_spi = XFRM_SPI_MIN + (rand32() % spi_range);
	max_spi = min_spi + (rand32() % (XFRM_SPI_MIN + spi_range - min_spi));
	spi_info->min = min_spi;
	spi_info->max = max_spi;

	return total;
}

void xfrm_compat_allocspi_sweep(struct nl_ctx *ctx)
{
	static const size_t sweep_lens[] = {
		220, 222, 224, 226, 228, 230, 232, 234, 236,
	};
	static const __u16 families[] = { AF_INET, AF_INET6 };
	struct compat_sendto_args *args;
	struct sockaddr_nl *dst;
	unsigned char *body;
	unsigned char rbuf[1024];
	size_t off;
	size_t i, f;
	long rc;
	ssize_t n;

	if (ns_unsupported_xfrm)
		return;
	if (!compat_low_arena_ready())
		return;

	__atomic_add_fetch(&shm->stats.xfrm_compat.allocspi_runs,
			   1, __ATOMIC_RELAXED);

	args = (struct compat_sendto_args *)compat_low_arena;
	off = sizeof(*args);
	off = (off + 7U) & ~(size_t)7U;
	dst = (struct sockaddr_nl *)(compat_low_arena + off);
	memset(dst, 0, sizeof(*dst));
	dst->nl_family = AF_NETLINK;
	off += sizeof(*dst);
	off = (off + 7U) & ~(size_t)7U;
	body = compat_low_arena + off;

	for (f = 0; f < ARRAY_SIZE(families); f++) {
		for (i = 0; i < ARRAY_SIZE(sweep_lens); i++) {
			size_t msg_len;

			msg_len = compat_build_allocspi(body,
					COMPAT_LOW_ARENA_BYTES - off,
					nl_seq_next(ctx),
					families[f], sweep_lens[i]);
			if (!msg_len)
				continue;

			args->fd     = (__u32)ctx->fd;
			args->buf    = (__u32)(uintptr_t)body;
			args->len    = (__u32)msg_len;
			args->flags  = MSG_DONTWAIT;
			args->dst    = (__u32)(uintptr_t)dst;
			args->dstlen = (__u32)sizeof(*dst);

			rc = compat_int80_socketcall(COMPAT_SYS_SENDTO, args);
			if (rc == -ENOSYS) {
				compat_int80_unsupported = true;
				__atomic_add_fetch(
					&shm->stats.xfrm_compat.allocspi_unsupported,
					1, __ATOMIC_RELAXED);
				return;
			}
			if (rc < 0) {
				__atomic_add_fetch(
					&shm->stats.xfrm_compat.allocspi_sends_failed,
					1, __ATOMIC_RELAXED);
				continue;
			}
			__atomic_add_fetch(
				&shm->stats.xfrm_compat.allocspi_sends_ok,
				1, __ATOMIC_RELAXED);

			/* Drain at most one reply per send so the socket
			 * receive queue can't fill and back-pressure the
			 * next sendto.  Native recv() is fine — the compat
			 * translator ran on the request already; the reply
			 * path already invoked alloc_compat() from
			 * dump_one_state(). */
			n = recv(ctx->fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
			if (n > 0)
				__atomic_add_fetch(
					&shm->stats.xfrm_compat.allocspi_replies_seen,
					1, __ATOMIC_RELAXED);
		}
	}
}

#else /* !__x86_64__ */

/* No ia32 compat entry point on non-x86_64 targets; the sub-mode
 * short-circuits to a no-op so the caller unconditionally references
 * a real symbol. */
void xfrm_compat_allocspi_sweep(struct nl_ctx *ctx)
{
	(void)ctx;
}

#endif /* __x86_64__ */
