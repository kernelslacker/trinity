/*
 * afxdp_churn - AF_XDP UMEM + ring + XSKMAP + XDP redirect-prog churn.
 *
 * Random isolated syscall fuzzing essentially never assembles a working
 * AF_XDP socket because the family is the most step-heavy in the kernel:
 * a UMEM region, four rings (RX / TX / FILL / COMPLETION), an XDP program,
 * an XSKMAP entry, and a bind() are ALL required before a single packet
 * can flow.  This childop drives the full sequence per outer iteration so
 * the AF_XDP code in net/xdp/{xsk,xsk_buff_pool,xsk_queue}.c, net/core/xdp.c
 * and kernel/bpf/{devmap,cpumap,xskmap}.c gets exercised end-to-end and the
 * known historical bug classes get a race window opened against a live
 * bound socket:
 *
 *   - CVE-2022-3625 xsk_setsockopt UAF on duplicate XDP_*_RING setsockopt;
 *   - CVE-2023-39197 xsk_buff_pool refcount imbalance on bind/unbind churn;
 *   - CVE-2024-26800 xskmap update racing the xsk fd close path;
 *   - CVE-2024-50115 xdp_do_redirect map UAF when the bound XSKMAP entry
 *     is deleted while xdp_do_redirect is mid-walk.
 *
 * Per outer iteration (BUDGETED + JITTER, base 5 / floor 16 / cap 64,
 * 200 ms wall-clock cap):
 *
 *   1.  socket(AF_XDP, SOCK_RAW).  EAFNOSUPPORT / EPROTONOSUPPORT / EPERM
 *       latches ns_unsupported_afxdp for the rest of the child's life.
 *   2.  Allocate a 64 KiB anonymous mmap as the UMEM region (16 chunks of
 *       4 KiB each), setsockopt XDP_UMEM_REG with chunk_size=4096.
 *   3.  setsockopt XDP_RX_RING / XDP_TX_RING / XDP_UMEM_FILL_RING /
 *       XDP_UMEM_COMPLETION_RING with 64 entries each.
 *   4.  setsockopt XDP_MMAP_OFFSETS to harvest per-ring producer/consumer
 *       offsets, then mmap each ring at its documented pgoff.
 *   5.  bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_XSKMAP, max_entries=1).
 *   6.  bpf(BPF_PROG_LOAD, BPF_PROG_TYPE_XDP) loading the minimal 8-insn
 *       XDP program:  r2=0; r3=0; r1 = MAP_FD; call bpf_redirect_map;
 *       r0 = XDP_REDIRECT (3); exit.  XDP_REDIRECT result is what tells
 *       the core xdp_do_redirect() path to walk the XSKMAP entry, which
 *       is the historical UAF surface.
 *   7.  bpf(BPF_MAP_UPDATE_ELEM) installing the xsk_fd at xskmap key 0.
 *       This is the moment xsk_map_update_elem() looks up the xsk's
 *       socket and increments the xsk_buff_pool refcount.
 *   8.  bind(XDP_USE_NEED_WAKEUP, ifindex=lo, qid=0).  Lights up the
 *       per-socket xsk_buff_pool and arms the rings.
 *   9.  Attach the loaded XDP program to lo so xdp_do_redirect() actually
 *       runs against ingress packets.  bpf(BPF_LINK_CREATE, BPF_XDP) is
 *       tried first (auto-detach on link fd close, no separate detach
 *       syscall needed).  On older kernels without LINK_CREATE for XDP,
 *       or when another iter_one already won the lo slot, fall back to
 *       RTM_NEWLINK with a nested IFLA_XDP { IFLA_XDP_FD, IFLA_XDP_FLAGS
 *       = XDP_FLAGS_SKB_MODE } -- SKB mode is mandatory on lo (no
 *       native-XDP path).  Without this attach, no redirect-side walker
 *       runs and step 12's race window stays cold.
 *  10.  Inject a 1-byte packet via the TX ring (UMEM offset 0) and kick
 *       via sendto(MSG_DONTWAIT) so xsk_sendmsg drives a TX descriptor
 *       through the pool.
 *  11.  setsockopt XDP_STATISTICS read while RX is armed (the stats path
 *       walks per-ring counters while the bound rings could race it).
 *  12.  RACE A: bpf(BPF_MAP_DELETE_ELEM) on the bound XSKMAP key while
 *       the attached XDP program is live on lo.  This is CVE-2024-50115's
 *       surface: the redirect-side walker holds an RCU-protected map
 *       pointer that the delete frees underneath.
 *  13.  RACE B: munmap one of the ring mmaps while the socket is still
 *       bound.  CVE-2023-39197's surface: the xsk_buff_pool refcount on
 *       the umem region must keep the kernel's view alive past the
 *       munmap of the *user's* ring mapping.
 *
 * Brick-safety:
 *   - lo (loopback) is the only ifindex we touch -- never an external NIC.
 *     The bind() qid is 0; there's no zero-copy path on lo so XDP_COPY is
 *     the implicit fallback.
 *   - The attached XDP program is the redirect-only sequence from
 *     xdp_prog_load() below: it stamps bpf_redirect_info and returns
 *     XDP_REDIRECT.  When the bound XSKMAP slot is populated, packets
 *     get redirected into our private xsk and consumed (worst case they
 *     sit in the RX ring until teardown unmaps it).  When the slot is
 *     empty (between iter_one's, or after RACE A's delete),
 *     xdp_do_redirect() drops the packet.  Total attached wall-time per
 *     outer invocation is bounded by AFXDP_WALL_CAP_NS (200 ms) so any
 *     localhost-traffic disruption is bursty and short-lived.  The
 *     attach lifetime is the BPF link fd: closing it in teardown
 *     auto-detaches; trinity child crash also closes it (kernel reaps
 *     fds on exit).
 *   - All UMEM / ring memory is per-iteration MAP_PRIVATE | MAP_ANONYMOUS,
 *     unmapped on exit.
 *   - Outer loop is BUDGETED (base 5 / floor 16 / cap 64) with JITTER and
 *     a hard 200 ms wall-clock cap.  Inner setsockopt / sendto calls are
 *     non-blocking (MSG_DONTWAIT) so a wedged ring can't hang the loop.
 *   - Bounded retry <= 8 on EAGAIN/EBUSY for setsockopt and bind.
 *   - Two cap-gate latches: ns_unsupported_afxdp on the AF_XDP socket()
 *     probe (EAFNOSUPPORT / EPROTONOSUPPORT / EPERM), and
 *     ns_unsupported_bpf_xdp on BPF_PROG_LOAD failure -- the AF_XDP path
 *     is still useful (UMEM + rings + bind without redirect) when the
 *     kernel rejects unprivileged XDP prog load.
 *
 * Header gate: __has_include(<linux/if_xdp.h>); UAPI integers fall back
 * to their stable values when the toolchain header is missing (kernel
 * returns -ENOPROTOOPT / -EOPNOTSUPP and the cap-gate latches).
 */

#if __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>)

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "bpf.h"
#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* AF_XDP / SOL_XDP -- present in modern glibc but #define-fallback for
 * stripped sysroots.  Stable values from <bits/socket.h>. */
#ifndef AF_XDP
#define AF_XDP			44
#endif
#ifndef SOL_XDP
#define SOL_XDP			283
#endif

/* if_xdp.h sockopt fallbacks (only used when the toolchain header is
 * missing entirely; the __has_include gate above keeps that path off,
 * but the #ifndefs are kept for header-version drift). */
#ifndef XDP_MMAP_OFFSETS
#define XDP_MMAP_OFFSETS		1
#define XDP_RX_RING			2
#define XDP_TX_RING			3
#define XDP_UMEM_REG			4
#define XDP_UMEM_FILL_RING		5
#define XDP_UMEM_COMPLETION_RING	6
#define XDP_STATISTICS			7
#endif
#ifndef XDP_PGOFF_RX_RING
#define XDP_PGOFF_RX_RING		0
#define XDP_PGOFF_TX_RING		0x80000000
#define XDP_UMEM_PGOFF_FILL_RING	0x100000000ULL
#define XDP_UMEM_PGOFF_COMPLETION_RING	0x180000000ULL
#endif
#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP		(1 << 3)
#endif

/* BPF map type and helper id fallbacks (XSKMAP and bpf_redirect_map are
 * upstream since 4.18 / 4.18 respectively; the bpf.h on the build host
 * is overwhelmingly likely to have both). */
#ifndef BPF_MAP_TYPE_XSKMAP
#define BPF_MAP_TYPE_XSKMAP		17
#endif
#ifndef BPF_PROG_TYPE_XDP
#define BPF_PROG_TYPE_XDP		6
#endif
#ifndef BPF_FUNC_redirect_map
#define BPF_FUNC_redirect_map		51
#endif

/* BPF_LINK_CREATE landed in 5.7; older kernels return -EINVAL and the
 * netlink fallback below picks up the attach. */
#ifndef BPF_LINK_CREATE
#define BPF_LINK_CREATE			28
#endif

/* IFLA_XDP attach (UAPI fallbacks for stripped sysroots).  IFLA_XDP is a
 * nested rtnetlink attribute carrying IFLA_XDP_FD + IFLA_XDP_FLAGS
 * sub-attrs.  XDP_FLAGS_SKB_MODE is mandatory on lo (no native XDP);
 * XDP_FLAGS_REPLACE lets us boot a stale leftover prog from a prior
 * iteration if the kernel kept it bound past close(prog_fd). */
#ifndef IFLA_XDP
#define IFLA_XDP			43
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD			1
#define IFLA_XDP_FLAGS			3
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE		(1U << 1)
#endif
#ifndef XDP_FLAGS_REPLACE
#define XDP_FLAGS_REPLACE		(1U << 4)
#endif

/* XDP_REDIRECT action code returned by the program; tells the kernel's
 * xdp_do_redirect() to consult the redirect map (XSKMAP in our case). */
#define XDP_REDIRECT_RET		3

#define AFXDP_OUTER_BASE		5U
#define AFXDP_OUTER_FLOOR		16U
#define AFXDP_OUTER_CAP			64U
#define AFXDP_WALL_CAP_NS		(200ULL * 1000ULL * 1000ULL)
#define AFXDP_RETRY_CAP			8U

#define AFXDP_CHUNK_SIZE		4096U
#define AFXDP_NR_CHUNKS			16U
#define AFXDP_UMEM_BYTES		(AFXDP_CHUNK_SIZE * AFXDP_NR_CHUNKS)
#define AFXDP_RING_ENTRIES		64U

static bool ns_unsupported_afxdp;
static bool ns_unsupported_bpf_xdp;

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

static bool retryable(int e)
{
	return e == EAGAIN || e == EBUSY || e == EINTR;
}

/* setsockopt with bounded EAGAIN/EBUSY retry. */
static int setsockopt_retry(int s, int level, int name,
			    const void *val, socklen_t len)
{
	unsigned int i;
	int r = -1;

	for (i = 0; i < AFXDP_RETRY_CAP; i++) {
		r = setsockopt(s, level, name, val, len);
		if (r == 0 || !retryable(errno))
			return r;
	}
	return r;
}

static int xskmap_create(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type    = BPF_MAP_TYPE_XSKMAP;
	attr.key_size    = sizeof(uint32_t);
	attr.value_size  = sizeof(uint32_t);
	attr.max_entries = 1;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

/*
 * Build the minimal XDP redirect program:
 *
 *     r1 = MAP_FD            ; LD_MAP_FD (two slots)
 *     r2 = 0                 ; key
 *     r3 = 0                 ; flags
 *     call bpf_redirect_map  ; r0 = XDP_REDIRECT or XDP_ABORTED
 *     r0 = XDP_REDIRECT (3)  ; force the action regardless of map state
 *     exit
 *
 * Forcing r0 = XDP_REDIRECT after the helper means the verifier blesses
 * the program even if the map is empty at load time, and at runtime the
 * kernel's xdp_do_redirect() picks up the bpf_redirect_info the helper
 * stamped into the per-CPU slot -- which is exactly the path that walks
 * the XSKMAP and is the surface for CVE-2024-50115.
 */
static int xdp_prog_load(int xskmap_fd)
{
	struct bpf_insn insns[] = {
		/* r1 = MAP_FD (two-slot LD_IMM64 with src=BPF_PSEUDO_MAP_FD). */
		{ .code = BPF_LD | BPF_DW | BPF_IMM,
		  .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD,
		  .off = 0, .imm = 0 },		/* imm patched below */
		{ .code = 0,
		  .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
		/* r2 = 0 */
		EBPF_MOV64_IMM(BPF_REG_2, 0),
		/* r3 = 0 */
		EBPF_MOV64_IMM(BPF_REG_3, 0),
		/* call bpf_redirect_map */
		EBPF_CALL(BPF_FUNC_redirect_map),
		/* r0 = XDP_REDIRECT */
		EBPF_MOV64_IMM(BPF_REG_0, XDP_REDIRECT_RET),
		/* exit */
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	insns[0].imm = xskmap_fd;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt  = ARRAY_SIZE(insns);
	attr.insns     = (uintptr_t)insns;
	attr.license   = (uintptr_t)license;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int xskmap_install(int map_fd, uint32_t key, int xsk_fd)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key    = (uintptr_t)&key;
	attr.value  = (uintptr_t)&xsk_fd;
	attr.flags  = 0;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int xskmap_delete(int map_fd, uint32_t key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key    = (uintptr_t)&key;

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

struct xsk_state {
	int		xsk_fd;
	int		map_fd;
	int		prog_fd;
	int		xdp_link_fd;		/* BPF_LINK_CREATE auto-detach handle */
	int		rtnl_fd;		/* netlink fallback attach socket */
	unsigned int	nl_attached_ifindex;	/* non-zero => detach via netlink in teardown */
	void		*umem;
	void		*rx_ring;
	void		*tx_ring;
	void		*fr_ring;
	void		*cr_ring;
	size_t		rx_ring_sz;
	size_t		tx_ring_sz;
	size_t		fr_ring_sz;
	size_t		cr_ring_sz;
	struct xdp_mmap_offsets off;
	bool		bound;
};

static int xdp_netlink_set_fd(int rtnl, unsigned int ifindex, int prog_fd);

static void xsk_init(struct xsk_state *st)
{
	memset(st, 0, sizeof(*st));
	st->xsk_fd      = -1;
	st->map_fd      = -1;
	st->prog_fd     = -1;
	st->xdp_link_fd = -1;
	st->rtnl_fd     = -1;
	st->umem    = MAP_FAILED;
	st->rx_ring = MAP_FAILED;
	st->tx_ring = MAP_FAILED;
	st->fr_ring = MAP_FAILED;
	st->cr_ring = MAP_FAILED;
}

static void xsk_teardown(struct xsk_state *st)
{
	/* Detach order: BPF link first (auto-detaches on close), then any
	 * netlink-attached prog (explicit RTM_NEWLINK with prog_fd=-1 in
	 * SKB mode), then close prog/map fds. */
	if (st->xdp_link_fd >= 0)
		close(st->xdp_link_fd);
	if (st->nl_attached_ifindex && st->rtnl_fd >= 0)
		(void)xdp_netlink_set_fd(st->rtnl_fd,
					 st->nl_attached_ifindex, -1);
	if (st->rtnl_fd >= 0)
		close(st->rtnl_fd);
	if (st->fr_ring != MAP_FAILED && st->fr_ring_sz)
		(void)munmap(st->fr_ring, st->fr_ring_sz);
	if (st->cr_ring != MAP_FAILED && st->cr_ring_sz)
		(void)munmap(st->cr_ring, st->cr_ring_sz);
	if (st->rx_ring != MAP_FAILED && st->rx_ring_sz)
		(void)munmap(st->rx_ring, st->rx_ring_sz);
	if (st->tx_ring != MAP_FAILED && st->tx_ring_sz)
		(void)munmap(st->tx_ring, st->tx_ring_sz);
	if (st->umem != MAP_FAILED)
		(void)munmap(st->umem, AFXDP_UMEM_BYTES);
	if (st->xsk_fd  >= 0) close(st->xsk_fd);
	if (st->prog_fd >= 0) close(st->prog_fd);
	if (st->map_fd  >= 0) close(st->map_fd);
}

/*
 * BPF_LINK_CREATE attach for XDP.  Returns the link fd on success.
 * Auto-detaches on close(link_fd), so teardown is just close().
 */
static int xdp_link_attach(int prog_fd, unsigned int ifindex)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd        = (uint32_t)prog_fd;
	attr.link_create.target_ifindex = ifindex;
	attr.link_create.attach_type    = BPF_XDP;

	return sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
}

/*
 * Open a NETLINK_ROUTE socket for the XDP attach fallback.  Bound,
 * RCVTIMEO 1s so a wedged rtnl can't outlive the SIGALRM(1s) cap.
 */
static int xdp_netlink_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = 1;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

/*
 * Send an RTM_NEWLINK with a nested IFLA_XDP { IFLA_XDP_FD,
 * IFLA_XDP_FLAGS=SKB_MODE } attribute to attach (prog_fd >= 0) or
 * detach (prog_fd == -1) the XDP program on @ifindex.  Returns 0 on
 * success, kernel errno (negated) on failure, -EIO on transport error.
 */
static int xdp_netlink_set_fd(int rtnl, unsigned int ifindex, int prog_fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *nest;
	struct nlattr *nla;
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[256];
	size_t off;
	__u32 flags = XDP_FLAGS_SKB_MODE;
	__s32 fdval = prog_fd;
	ssize_t n;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = 1;

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = (int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	/* Open IFLA_XDP nested attribute. */
	nest = (struct nlattr *)(buf + off);
	nest->nla_type = IFLA_XDP | NLA_F_NESTED;
	off += NLA_HDRLEN;

	/* IFLA_XDP_FD */
	nla = (struct nlattr *)(buf + off);
	nla->nla_type = IFLA_XDP_FD;
	nla->nla_len  = (unsigned short)(NLA_HDRLEN + sizeof(fdval));
	memcpy(buf + off + NLA_HDRLEN, &fdval, sizeof(fdval));
	off += NLA_ALIGN(NLA_HDRLEN + sizeof(fdval));

	/* IFLA_XDP_FLAGS */
	nla = (struct nlattr *)(buf + off);
	nla->nla_type = IFLA_XDP_FLAGS;
	nla->nla_len  = (unsigned short)(NLA_HDRLEN + sizeof(flags));
	memcpy(buf + off + NLA_HDRLEN, &flags, sizeof(flags));
	off += NLA_ALIGN(NLA_HDRLEN + sizeof(flags));

	/* Close nest. */
	nest->nla_len = (unsigned short)((unsigned char *)(buf + off) -
					 (unsigned char *)nest);

	nlh->nlmsg_len = (__u32)off;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	iov.iov_base = buf;
	iov.iov_len  = off;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(rtnl, &mh, 0) < 0)
		return -EIO;

	n = recv(rtnl, rbuf, sizeof(rbuf), 0);
	if (n < 0 || (size_t)n < NLMSG_HDRLEN)
		return -EIO;
	{
		struct nlmsghdr *r = (struct nlmsghdr *)rbuf;

		if (r->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(r);

			return e->error;	/* 0 on ack */
		}
	}
	return -EIO;
}

/* One full setup + race + teardown cycle on a fresh AF_XDP socket. */
static void iter_one(unsigned int idx, const struct timespec *t_outer)
{
	struct xsk_state st;
	struct xdp_umem_reg umem_reg;
	struct xdp_statistics xstats;
	struct sockaddr_xdp sxdp;
	socklen_t off_len = sizeof(st.off);
	socklen_t xstats_len = sizeof(xstats);
	uint32_t ring_entries = AFXDP_RING_ENTRIES;
	unsigned int lo_ifindex;
	unsigned int retry;
	int rc;

	(void)idx;

	if ((unsigned long long)ns_since(t_outer) >= AFXDP_WALL_CAP_NS)
		return;

	xsk_init(&st);

	st.xsk_fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (st.xsk_fd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
		    errno == EPERM || errno == EACCES)
			ns_unsupported_afxdp = true;
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	st.umem = mmap(NULL, AFXDP_UMEM_BYTES, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (st.umem == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	memset(&umem_reg, 0, sizeof(umem_reg));
	umem_reg.addr       = (uint64_t)(uintptr_t)st.umem;
	umem_reg.len        = AFXDP_UMEM_BYTES;
	umem_reg.chunk_size = AFXDP_CHUNK_SIZE;
	umem_reg.headroom   = 0;
	umem_reg.flags      = 0;
	rc = setsockopt_retry(st.xsk_fd, SOL_XDP, XDP_UMEM_REG,
			      &umem_reg, sizeof(umem_reg));
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn_umem_reg_ok,
			   1, __ATOMIC_RELAXED);

	/* All four rings, same size.  CVE-2022-3625 is in this exact
	 * setsockopt path -- the fix landed in xsk_setsockopt() to refuse
	 * a duplicate XDP_*_RING setsockopt that previously freed the old
	 * queue out from under the bound socket. */
	if (setsockopt_retry(st.xsk_fd, SOL_XDP, XDP_RX_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st.xsk_fd, SOL_XDP, XDP_TX_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st.xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st.xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
			     &ring_entries, sizeof(ring_entries)) < 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn_rings_setup_ok,
			   1, __ATOMIC_RELAXED);

	if (getsockopt(st.xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS,
		       &st.off, &off_len) < 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	st.rx_ring_sz = (size_t)st.off.rx.desc +
			(size_t)AFXDP_RING_ENTRIES * sizeof(struct xdp_desc);
	st.tx_ring_sz = (size_t)st.off.tx.desc +
			(size_t)AFXDP_RING_ENTRIES * sizeof(struct xdp_desc);
	st.fr_ring_sz = (size_t)st.off.fr.desc +
			(size_t)AFXDP_RING_ENTRIES * sizeof(uint64_t);
	st.cr_ring_sz = (size_t)st.off.cr.desc +
			(size_t)AFXDP_RING_ENTRIES * sizeof(uint64_t);

	st.rx_ring = mmap(NULL, st.rx_ring_sz, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, st.xsk_fd,
			  XDP_PGOFF_RX_RING);
	st.tx_ring = mmap(NULL, st.tx_ring_sz, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, st.xsk_fd,
			  XDP_PGOFF_TX_RING);
	st.fr_ring = mmap(NULL, st.fr_ring_sz, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, st.xsk_fd,
			  XDP_UMEM_PGOFF_FILL_RING);
	st.cr_ring = mmap(NULL, st.cr_ring_sz, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, st.xsk_fd,
			  XDP_UMEM_PGOFF_COMPLETION_RING);
	if (st.rx_ring == MAP_FAILED || st.tx_ring == MAP_FAILED ||
	    st.fr_ring == MAP_FAILED || st.cr_ring == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	st.map_fd = xskmap_create();
	if (st.map_fd < 0) {
		if (errno == EPERM || errno == EACCES)
			ns_unsupported_bpf_xdp = true;
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn_map_create_ok,
			   1, __ATOMIC_RELAXED);

	if (!ns_unsupported_bpf_xdp) {
		st.prog_fd = xdp_prog_load(st.map_fd);
		if (st.prog_fd < 0) {
			if (errno == EPERM || errno == EACCES ||
			    errno == EINVAL || errno == EOPNOTSUPP)
				ns_unsupported_bpf_xdp = true;
			/* AF_XDP setup still useful without the prog -- the
			 * UMEM/ring/bind path exercises xsk_buff_pool by
			 * itself.  Don't fail the iteration. */
		} else {
			__atomic_add_fetch(&shm->stats.afxdp_churn_prog_load_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	if (xskmap_install(st.map_fd, 0, st.xsk_fd) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn_map_update_ok,
				   1, __ATOMIC_RELAXED);

	lo_ifindex = if_nametoindex("lo");
	if (lo_ifindex == 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	memset(&sxdp, 0, sizeof(sxdp));
	sxdp.sxdp_family       = AF_XDP;
	sxdp.sxdp_flags        = XDP_USE_NEED_WAKEUP;
	sxdp.sxdp_ifindex      = lo_ifindex;
	sxdp.sxdp_queue_id     = 0;
	sxdp.sxdp_shared_umem_fd = 0;

	rc = -1;
	for (retry = 0; retry < AFXDP_RETRY_CAP; retry++) {
		rc = bind(st.xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
		if (rc == 0 || !retryable(errno))
			break;
	}
	if (rc == 0) {
		st.bound = true;
		__atomic_add_fetch(&shm->stats.afxdp_churn_bind_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* Attach the loaded XDP program to lo so xdp_do_redirect() actually
	 * walks the XSKMAP -- without an attached program, the RACE A
	 * map-delete below has no concurrent reader and never opens the
	 * CVE-2024-50115 window.  Try BPF_LINK_CREATE first (auto-detach
	 * on link fd close), fall back to RTM_NEWLINK + IFLA_XDP_FD in
	 * SKB mode on older kernels (returns -EINVAL from BPF_LINK_CREATE)
	 * or when another iter_one already won the lo slot. */
	if (st.bound && st.prog_fd >= 0) {
		st.xdp_link_fd = xdp_link_attach(st.prog_fd, lo_ifindex);
		if (st.xdp_link_fd >= 0) {
			__atomic_add_fetch(&shm->stats.afxdp_churn_link_attach_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			st.rtnl_fd = xdp_netlink_open();
			if (st.rtnl_fd >= 0 &&
			    xdp_netlink_set_fd(st.rtnl_fd, lo_ifindex,
					       st.prog_fd) == 0) {
				st.nl_attached_ifindex = lo_ifindex;
				__atomic_add_fetch(&shm->stats.afxdp_churn_netlink_attach_ok,
						   1, __ATOMIC_RELAXED);
			} else {
				__atomic_add_fetch(&shm->stats.afxdp_churn_attach_failed,
						   1, __ATOMIC_RELAXED);
			}
		}
	}

	if (st.bound) {
		/* Inject one TX descriptor (UMEM offset 0, 1-byte payload)
		 * directly into the TX ring, then sendto-kick.  The kernel's
		 * xsk_sendmsg walks the TX ring and pulls the descriptor
		 * through xsk_buff_pool, which is the live-pool path we want
		 * to race against the deletes/munmaps below. */
		uint32_t *prod = (uint32_t *)((char *)st.tx_ring +
					      st.off.tx.producer);
		struct xdp_desc *desc = (struct xdp_desc *)((char *)st.tx_ring +
							    st.off.tx.desc);
		uint32_t p = __atomic_load_n(prod, __ATOMIC_RELAXED);

		desc[p % AFXDP_RING_ENTRIES].addr = 0;
		desc[p % AFXDP_RING_ENTRIES].len  = 1;
		desc[p % AFXDP_RING_ENTRIES].options = 0;
		__atomic_store_n(prod, p + 1, __ATOMIC_RELEASE);

		if (sendto(st.xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0) >= 0 ||
		    errno == EAGAIN || errno == ENOBUFS || errno == EBUSY)
			__atomic_add_fetch(&shm->stats.afxdp_churn_send_ok,
					   1, __ATOMIC_RELAXED);
	}

	/* XDP_STATISTICS read while RX is bound -- the stats walker reads
	 * the per-ring ring_full / fill_ring_empty_descs counters which
	 * the bound rings are concurrently producing into. */
	if (getsockopt(st.xsk_fd, SOL_XDP, XDP_STATISTICS,
		       &xstats, &xstats_len) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn_recv_ok,
				   1, __ATOMIC_RELAXED);

	/* RACE A: delete the bound XSKMAP entry.  CVE-2024-50115 surface --
	 * xdp_do_redirect()'s map walker holds an RCU-protected pointer
	 * that this delete frees from under it. */
	if (st.bound && xskmap_delete(st.map_fd, 0) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn_map_delete_ok,
				   1, __ATOMIC_RELAXED);

	/* RACE B: munmap the FILL ring while still bound.  CVE-2023-39197
	 * surface -- the xsk_buff_pool refcount on the umem region must
	 * keep the kernel's mapping alive past the user's munmap of its
	 * own ring view. */
	if (st.bound && st.fr_ring != MAP_FAILED && st.fr_ring_sz) {
		if (munmap(st.fr_ring, st.fr_ring_sz) == 0)
			__atomic_add_fetch(&shm->stats.afxdp_churn_munmap_race_ok,
					   1, __ATOMIC_RELAXED);
		st.fr_ring = MAP_FAILED;
		st.fr_ring_sz = 0;
	}

out:
	xsk_teardown(&st);
}

bool afxdp_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.afxdp_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_afxdp) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec  = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_AFXDP_CHURN,
			       JITTER_RANGE(AFXDP_OUTER_BASE));
	if (outer_iters < AFXDP_OUTER_FLOOR)
		outer_iters = AFXDP_OUTER_FLOOR;
	if (outer_iters > AFXDP_OUTER_CAP)
		outer_iters = AFXDP_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= AFXDP_WALL_CAP_NS)
			break;

		iter_one(i, &t_outer);

		if (ns_unsupported_afxdp)
			break;
	}

	return true;
}

#else  /* missing <linux/if_xdp.h> or <linux/bpf.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool afxdp_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.afxdp_churn_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
