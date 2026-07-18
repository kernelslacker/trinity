/*
 * afxdp_churn - AF_XDP UMEM + ring + XSKMAP + XDP redirect-prog churn.
 *
 * AF_XDP is the most step-heavy family in the kernel: UMEM + four
 * rings (RX/TX/FILL/COMPLETION) + XDP program + XSKMAP entry + bind()
 * all required before a packet flows, so random-syscall fuzzing never
 * assembles a working socket.  Target functions: net/xdp/xsk*.c,
 * net/core/xdp.c:xdp_do_redirect, kernel/bpf/xskmap.c.  Bug class:
 * xsk_setsockopt UAF on duplicate XDP_*_RING, xsk_buff_pool refcount
 * imbalance on bind/unbind churn, xskmap update vs xsk close, and the
 * xdp_do_redirect map-UAF when the bound XSKMAP entry is deleted mid-
 * walk.
 *
 * Per outer iteration (BUDGETED+JITTER, base 5 / floor 16 / cap 64,
 * 200 ms wall cap): stand up an AF_XDP socket with UMEM (64 KiB / 16
 * chunks) and all four rings, create an XSKMAP, BPF_PROG_LOAD the
 * minimal redirect-map program (returns XDP_REDIRECT), bind to lo
 * qid=0 with XDP_USE_NEED_WAKEUP, attach the XDP program (BPF_LINK_
 * CREATE preferred, RTM_NEWLINK IFLA_XDP with XDP_FLAGS_SKB_MODE as
 * fallback -- SKB mode is mandatory on lo), TX one packet, then race
 * MAP_DELETE_ELEM on the bound key against the live redirect walker
 * and munmap a ring while still bound.
 *
 * Brick-safety: lo only, no external NICs; qid=0 (XDP_COPY implicit --
 * no zero-copy on lo).  Attach lifetime is bounded by the link fd
 * (auto-detaches on teardown / child crash) and the 200 ms wall cap
 * bounds any localhost disruption.  UMEM/ring memory is per-iter
 * MAP_PRIVATE|MAP_ANONYMOUS.  setsockopt/sendto are non-blocking with
 * <= 8 EAGAIN/EBUSY retries.
 *
 * Latches: ns_unsupported_afxdp on AF_XDP socket() probe
 * (EAFNOSUPPORT/EPROTONOSUPPORT/EPERM), ns_unsupported_bpf_xdp on
 * BPF_PROG_LOAD failure (AF_XDP without redirect is still useful).
 * Header-gated by __has_include on <linux/if_xdp.h>/<linux/bpf.h>;
 * per-symbol UAPI-integer fallbacks let older sysroots compile
 * (kernel returns -ENOPROTOOPT/-EOPNOTSUPP, latches fire).
 */

#if __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>)

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "childops-netlink.h"

#include "bpf.h"
#include "bpf-syscall.h"
#include "child.h"
#include "jitter.h"
#include "kernel/if_xdp.h"
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

/* SOL_XDP -- present in modern glibc but #define-fallback for stripped
 * sysroots.  Stable value from <bits/socket.h>. */
#ifndef SOL_XDP
#define SOL_XDP			283
#endif

/* XDP_RX_RING / XDP_TX_RING sockopt fallbacks (kept for header-version
 * drift; the XDP_UMEM_* / XDP_STATISTICS / XDP_*_PGOFF / XDP_MMAP_OFFSETS
 * fallbacks live in include/kernel/if_xdp.h). */
#ifndef XDP_RX_RING
#define XDP_RX_RING			2
#endif
#ifndef XDP_TX_RING
#define XDP_TX_RING			3
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

/* Multibuf + sw-csum tx-metadata UAPI fallbacks (toolchain header drift).
 *   XDP_USE_SG               sxdp_flags bit:  multi-frag bind (0f3776583d28)
 *   XDP_UMEM_FLAGS_USE_SG    xdp_umem_reg.flags bit: multi-frag UMEM
 *   XDP_PKT_CONTD            desc->options bit: head of chained TX desc
 *   XDP_TX_METADATA          desc->options bit: read xsk_tx_metadata before addr
 *   XDP_TXMD_FLAGS_*         flags inside the stamped metadata header
 *   IFF_NAPI / IFF_NAPI_FRAGS  tun ifr_flags for napi-frag rx (d73a9a63f9f7) */
#ifndef XDP_USE_SG
#define XDP_USE_SG			(1 << 4)
#endif
#ifndef XDP_UMEM_FLAGS_USE_SG
#define XDP_UMEM_FLAGS_USE_SG		(1 << 1)
#endif
#ifndef XDP_PKT_CONTD
#define XDP_PKT_CONTD			(1 << 0)
#endif
#ifndef XDP_TX_METADATA
#define XDP_TX_METADATA			(1 << 1)
#endif
#ifndef XDP_TXMD_FLAGS_TIMESTAMP
#define XDP_TXMD_FLAGS_TIMESTAMP	(1 << 0)
#endif
#ifndef XDP_TXMD_FLAGS_CHECKSUM
#define XDP_TXMD_FLAGS_CHECKSUM		(1 << 1)
#endif
#ifndef IFF_NAPI
#define IFF_NAPI			0x0010
#endif
#ifndef IFF_NAPI_FRAGS
#define IFF_NAPI_FRAGS			0x0020
#endif

/* xsk_tx_metadata layout is fixed (16 bytes): u64 flags at off 0, then
 * a union — for sw checksum we use u16 csum_start at off 8 and u16
 * csum_offset at off 10. Use a raw 16-byte buffer to avoid toolchain
 * struct presence assumptions. */
#define AFXDP_TX_META_BYTES		16U
#define AFXDP_SG_CHUNK_SIZE		1024U

/* Failsafe iteration cap for the TX-metadata scribbler thread.  Main
 * signals stop after sendto() returns; the cap exists only so a wedged
 * main path can't leave the scribbler spinning forever.  ~1M tight-loop
 * writes is well under 100 ms on any modern CPU, which is comfortably
 * inside the per-iter AFXDP_WALL_CAP_NS budget. */
#define AFXDP_TX_META_SCRIBBLE_CAP	(1U << 20)

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
static bool ns_unsupported_xdp_sg;
static bool ns_unsupported_tx_metadata;

static bool retryable(int e)
{
	return e == EAGAIN || e == EBUSY || e == EINTR;
}

/*
 * Compute mmap length for an XDP ring as desc_off + entries * entry_sz.
 * Returns false on wrap from the kernel-supplied desc_off or the
 * multiplication so a short/corrupt XDP_MMAP_OFFSETS reply can't drive
 * a bogus mmap (and matching bogus munmap) length.
 */
static bool xdp_ring_mmap_size(__u64 desc_off, size_t entries,
			       size_t entry_sz, size_t *out)
{
	size_t prod;

	if (__builtin_mul_overflow(entries, entry_sz, &prod))
		return false;
	if (__builtin_add_overflow((size_t)desc_off, prod, out))
		return false;
	return true;
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
	struct nl_ctx	rtnl;			/* netlink fallback attach socket */
	int		tun_fd;			/* /dev/net/tun fd kept open while xsk bound to tunN */
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

static int xdp_netlink_set_fd(struct nl_ctx *rtnl, unsigned int ifindex,
			      int prog_fd);

static void xsk_init(struct xsk_state *st)
{
	memset(st, 0, sizeof(*st));
	st->xsk_fd      = -1;
	st->map_fd      = -1;
	st->prog_fd     = -1;
	st->xdp_link_fd = -1;
	st->rtnl.fd     = -1;
	st->tun_fd      = -1;
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
	if (st->nl_attached_ifindex && st->rtnl.fd >= 0)
		(void)xdp_netlink_set_fd(&st->rtnl,
					 st->nl_attached_ifindex, -1);
	if (st->rtnl.fd >= 0)
		nl_close(&st->rtnl);
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
	if (st->tun_fd  >= 0) close(st->tun_fd);
}

/*
 * Open /dev/net/tun and create a tunN device with IFF_NAPI_FRAGS so the
 * rx path uses the napi-frag (non-linear skb) shape — exactly the
 * IFF_TX_SKB_NO_LINEAR netdev class that d73a9a63f9f7 missed when
 * binding sw-csum TX metadata.  Returns fd on success and writes the
 * kernel-assigned name into @name_out (IFNAMSIZ buffer); -1 on failure.
 * Caller must keep the fd open while the xsk is bound to the device.
 * The kernel-assigned name is also recorded into the NAME_KIND_NETDEV
 * pool so later cross-syscall name draws can reference this live tunN
 * instead of always synthesising a fresh-random name that the kernel
 * has no entry for and that misses the name-keyed lookup branches.
 */
static int tun_open_napi_frags(char *name_out)
{
	struct ifreq ifr;
	size_t nlen;
	int fd;

	fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_NAPI | IFF_NAPI_FRAGS;
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		close(fd);
		return -1;
	}
	memcpy(name_out, ifr.ifr_name, IFNAMSIZ);
	nlen = strnlen(name_out, IFNAMSIZ);
	if (nlen > 0)
		name_pool_record(NAME_KIND_NETDEV, name_out, nlen);
	return fd;
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
 * Returns 0 on success and stamps @ctx; -1 on failure.
 */
static int xdp_netlink_open(struct nl_ctx *ctx)
{
	struct nl_open_opts opts;

	memset(&opts, 0, sizeof(opts));
	opts.proto         = NETLINK_ROUTE;
	opts.recv_timeo_s  = 1;
	return nl_open(ctx, &opts);
}

/*
 * Send an RTM_NEWLINK with a nested IFLA_XDP { IFLA_XDP_FD,
 * IFLA_XDP_FLAGS=SKB_MODE } attribute to attach (prog_fd >= 0) or
 * detach (prog_fd == -1) the XDP program on @ifindex.  Returns 0 on
 * success, kernel errno (negated) on failure, -EIO on transport error.
 */
static int xdp_netlink_set_fd(struct nl_ctx *rtnl, unsigned int ifindex,
			      int prog_fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, nest_off;
	__u32 flags = XDP_FLAGS_SKB_MODE;
	__s32 fdval = prog_fd;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = (int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	nest_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_XDP | NLA_F_NESTED);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FD,
		      &fdval, sizeof(fdval));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FLAGS,
		      &flags, sizeof(flags));
	if (!off)
		return -EIO;
	nla_nest_end(buf, nest_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/*
 * Phase 1: open the AF_XDP socket, mmap the UMEM region, pick the per-
 * iteration feature knobs, and run XDP_UMEM_REG.  On EINVAL with a new
 * feature bit set, latch that feature off and retry once with the
 * baseline layout — the rest of the iteration is still useful coverage.
 * Outputs want_sg / want_tx_md / want_tun for the downstream phases.
 */
static int afxdp_iter_setup_umem(struct childdata *child,
				 struct xsk_state *st,
				 bool *want_sg_out,
				 bool *want_tx_md_out,
				 bool *want_tun_out)
{
	struct afxdp_umem_reg_compat umem_reg;
	bool want_sg, want_tx_md, want_tun;
	int rc;

	st->xsk_fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (st->xsk_fd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
		    errno == EPERM || errno == EACCES) {
			ns_unsupported_afxdp = true;
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats arrays, same pattern
			 * the child.c dispatch loop uses for the unguarded
			 * write that motivated this guard. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	st->umem = mmap(NULL, AFXDP_UMEM_BYTES, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (st->umem == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	/* Per-iteration knobs.  Two latches gate the new feature flags off
	 * the moment the kernel rejects them with EINVAL — but we never
	 * disable the whole childop on either, the existing UMEM/ring/bind
	 * path is the baseline coverage and must keep running. */
	want_sg    = !ns_unsupported_xdp_sg     && (rnd_u32() & 1);
	want_tx_md = !ns_unsupported_tx_metadata && (rnd_u32() & 1);
	want_tun   = (rnd_u32() & 3) == 0;

	memset(&umem_reg, 0, sizeof(umem_reg));
	umem_reg.addr            = (uint64_t)(uintptr_t)st->umem;
	umem_reg.len             = AFXDP_UMEM_BYTES;
	umem_reg.chunk_size      = want_sg ? AFXDP_SG_CHUNK_SIZE : AFXDP_CHUNK_SIZE;
	umem_reg.headroom        = want_tx_md ? AFXDP_TX_META_BYTES : 0;
	umem_reg.flags           = want_sg ? XDP_UMEM_FLAGS_USE_SG : 0;
	umem_reg.tx_metadata_len = want_tx_md ? AFXDP_TX_META_BYTES : 0;
	rc = setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_UMEM_REG,
			      &umem_reg, sizeof(umem_reg));
	if (rc < 0 && errno == EINVAL && (want_sg || want_tx_md)) {
		/* Latch unsupported features off and retry once with the
		 * baseline (single-buf, no metadata) layout — the rest of
		 * the iteration is still useful coverage. */
		if (want_sg) {
			ns_unsupported_xdp_sg = true;
			__atomic_add_fetch(&shm->stats.afxdp_xsg_bind_failed,
					   1, __ATOMIC_RELAXED);
		}
		if (want_tx_md) {
			ns_unsupported_tx_metadata = true;
			__atomic_add_fetch(&shm->stats.afxdp_tx_md_bind_failed,
					   1, __ATOMIC_RELAXED);
		}
		want_sg = want_tx_md = false;
		umem_reg.chunk_size      = AFXDP_CHUNK_SIZE;
		umem_reg.headroom        = 0;
		umem_reg.flags           = 0;
		umem_reg.tx_metadata_len = 0;
		rc = setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_UMEM_REG,
				      &umem_reg, sizeof(umem_reg));
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn_umem_reg_ok,
			   1, __ATOMIC_RELAXED);
	if (want_sg)
		__atomic_add_fetch(&shm->stats.afxdp_xsg_iters,
				   1, __ATOMIC_RELAXED);
	if (want_tx_md)
		__atomic_add_fetch(&shm->stats.afxdp_tx_metadata_iters,
				   1, __ATOMIC_RELAXED);

	*want_sg_out    = want_sg;
	*want_tx_md_out = want_tx_md;
	*want_tun_out   = want_tun;
	return 0;
}

/*
 * Phase 2: setsockopt all four rings (RX / TX / FILL / COMPLETION), then
 * harvest XDP_MMAP_OFFSETS and mmap each ring at its documented pgoff.
 * Each ring's size + base is stamped into @st so the TX-inject and
 * munmap-race phases can poke them directly.
 */
static int afxdp_iter_setup_rings(struct xsk_state *st)
{
	uint32_t ring_entries = AFXDP_RING_ENTRIES;
	socklen_t off_len = sizeof(st->off);

	/* All four rings, same size.  CVE-2022-3625 is in this exact
	 * setsockopt path -- the fix landed in xsk_setsockopt() to refuse
	 * a duplicate XDP_*_RING setsockopt that previously freed the old
	 * queue out from under the bound socket. */
	if (setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_RX_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_TX_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
			     &ring_entries, sizeof(ring_entries)) < 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn_rings_setup_ok,
			   1, __ATOMIC_RELAXED);

	/* Zero before the getsockopt so a short reply leaves known state,
	 * then require the full struct came back before we trust any of
	 * its fields for downstream mmap sizing. */
	memset(&st->off, 0, sizeof(st->off));
	if (getsockopt(st->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS,
		       &st->off, &off_len) < 0 ||
	    off_len < sizeof(st->off)) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	if (!xdp_ring_mmap_size(st->off.rx.desc, AFXDP_RING_ENTRIES,
				sizeof(struct xdp_desc), &st->rx_ring_sz) ||
	    !xdp_ring_mmap_size(st->off.tx.desc, AFXDP_RING_ENTRIES,
				sizeof(struct xdp_desc), &st->tx_ring_sz) ||
	    !xdp_ring_mmap_size(st->off.fr.desc, AFXDP_RING_ENTRIES,
				sizeof(uint64_t), &st->fr_ring_sz) ||
	    !xdp_ring_mmap_size(st->off.cr.desc, AFXDP_RING_ENTRIES,
				sizeof(uint64_t), &st->cr_ring_sz)) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	st->rx_ring = mmap(NULL, st->rx_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, st->xsk_fd,
			   XDP_PGOFF_RX_RING);
	st->tx_ring = mmap(NULL, st->tx_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, st->xsk_fd,
			   XDP_PGOFF_TX_RING);
	st->fr_ring = mmap(NULL, st->fr_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, st->xsk_fd,
			   XDP_UMEM_PGOFF_FILL_RING);
	st->cr_ring = mmap(NULL, st->cr_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, st->xsk_fd,
			   XDP_UMEM_PGOFF_COMPLETION_RING);
	if (st->rx_ring == MAP_FAILED || st->tx_ring == MAP_FAILED ||
	    st->fr_ring == MAP_FAILED || st->cr_ring == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 3: stand up the BPF side -- create the single-entry XSKMAP, load
 * the minimal redirect XDP program (best-effort: prog-load failures latch
 * but do not fail the iter; AF_XDP UMEM/ring/bind alone is still useful
 * coverage), and install the xsk fd at xskmap key 0.  Map-create failure
 * is the only fatal step.
 */
static int afxdp_iter_setup_bpf(struct xsk_state *st)
{
	st->map_fd = xskmap_create();
	if (st->map_fd < 0) {
		if (errno == EPERM || errno == EACCES)
			ns_unsupported_bpf_xdp = true;
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn_map_create_ok,
			   1, __ATOMIC_RELAXED);

	if (!ns_unsupported_bpf_xdp) {
		st->prog_fd = xdp_prog_load(st->map_fd);
		if (st->prog_fd < 0) {
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

	if (xskmap_install(st->map_fd, 0, st->xsk_fd) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn_map_update_ok,
				   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Phase 4: pick the bind target ifindex (tun-with-NAPI_FRAGS when the
 * per-iter knob fires and the tunN is reachable, otherwise lo) and run
 * bind() with bounded EAGAIN/EBUSY retry.  Clears *want_tun if the tun
 * path fell through to lo so downstream stats reflect what actually
 * bound.  Returns -1 only when no ifindex is reachable; bind() failure
 * leaves st->bound == false and the iteration continues into races.
 */
static int afxdp_iter_bind(struct xsk_state *st, bool want_sg,
			   bool *want_tun, char *tun_name,
			   unsigned int *target_ifindex_out)
{
	struct sockaddr_xdp sxdp;
	unsigned int target_ifindex = 0;
	unsigned int retry;
	int rc;

	/* Pick bind target: tun-with-NAPI_FRAGS when the per-iter knob fired
	 * (and tun is reachable), else lo.  d73a9a63f9f7's bug surface is
	 * the IFF_TX_SKB_NO_LINEAR class of netdev — tun in NAPI mode
	 * exposes that path; lo does not. */
	if (*want_tun) {
		st->tun_fd = tun_open_napi_frags(tun_name);
		if (st->tun_fd >= 0)
			target_ifindex = if_nametoindex(tun_name);
		if (target_ifindex == 0) {
			if (st->tun_fd >= 0) {
				close(st->tun_fd);
				st->tun_fd = -1;
			}
			*want_tun = false;
		}
	}
	if (target_ifindex == 0)
		target_ifindex = if_nametoindex("lo");
	if (target_ifindex == 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	memset(&sxdp, 0, sizeof(sxdp));
	sxdp.sxdp_family       = AF_XDP;
	sxdp.sxdp_flags        = XDP_USE_NEED_WAKEUP |
				 (want_sg ? XDP_USE_SG : 0);
	sxdp.sxdp_ifindex      = target_ifindex;
	sxdp.sxdp_queue_id     = 0;
	sxdp.sxdp_shared_umem_fd = 0;

	rc = -1;
	for (retry = 0; retry < AFXDP_RETRY_CAP; retry++) {
		rc = bind(st->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
		if (rc == 0 || !retryable(errno))
			break;
	}
	if (rc == 0) {
		st->bound = true;
		__atomic_add_fetch(&shm->stats.afxdp_churn_bind_ok,
				   1, __ATOMIC_RELAXED);
		if (*want_tun)
			__atomic_add_fetch(&shm->stats.afxdp_tun_bind_iters,
					   1, __ATOMIC_RELAXED);
	} else if (want_sg && errno == EINVAL) {
		/* Bind-time rejection of XDP_USE_SG (e.g. driver path).
		 * Latch so subsequent iters don't ask for it again. */
		ns_unsupported_xdp_sg = true;
		__atomic_add_fetch(&shm->stats.afxdp_xsg_bind_failed,
				   1, __ATOMIC_RELAXED);
	}

	*target_ifindex_out = target_ifindex;
	return 0;
}

/*
 * Phase 5: attach the loaded XDP redirect program to the bound ifindex
 * so xdp_do_redirect() walks the XSKMAP -- without an attached prog,
 * the RACE A map-delete below has no concurrent reader and never opens
 * the CVE-2024-50115 window.  BPF_LINK_CREATE first (auto-detach on
 * link fd close), then RTM_NEWLINK + IFLA_XDP_FD in SKB mode on older
 * kernels or when another iter_one already won the slot.
 */
static void afxdp_iter_attach_prog(struct xsk_state *st,
				   unsigned int target_ifindex)
{
	if (!st->bound || st->prog_fd < 0)
		return;

	st->xdp_link_fd = xdp_link_attach(st->prog_fd, target_ifindex);
	if (st->xdp_link_fd >= 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn_link_attach_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		int rc_open = xdp_netlink_open(&st->rtnl);

		if (rc_open == 0 &&
		    xdp_netlink_set_fd(&st->rtnl, target_ifindex,
				       st->prog_fd) == 0) {
			st->nl_attached_ifindex = target_ifindex;
			__atomic_add_fetch(&shm->stats.afxdp_churn_netlink_attach_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.afxdp_churn_attach_failed,
					   1, __ATOMIC_RELAXED);
		}
	}
}

/*
 * Concurrent scribbler that tight-loops overwriting the 16-byte
 * xsk_tx_metadata header in the UMEM headroom while the kernel is
 * consuming the TX descriptor.  The kernel's sw-csum TX path reads
 * csum_start / csum_offset out of the user-writable UMEM region; a
 * concurrent overwrite between the kernel's two reads (a classic
 * double-fetch / TOCTOU window) can drive csum_start past the packet
 * end, exercising the bounds checks added in d73a9a63f9f7 and friends.
 *
 * Flips both the flags u64 at offset 0 and the (csum_start, csum_offset)
 * u16 pair at offsets 8/10 so any read order in the kernel sees a
 * moving target.  Bounded by an atomic stop flag (set by the main
 * thread after sendto() returns) AND a hard iteration cap as failsafe.
 */
struct afxdp_meta_scribbler_args {
	unsigned char	*meta;
	unsigned int	 stop;
};

static void *afxdp_meta_scribbler(void *p)
{
	struct afxdp_meta_scribbler_args *a = p;
	unsigned int i;
	__u64 mflags;
	__u16 cs;

	for (i = 0; i < AFXDP_TX_META_SCRIBBLE_CAP; i++) {
		if (__atomic_load_n(&a->stop, __ATOMIC_RELAXED))
			break;
		mflags = (i & 1U)
			? (XDP_TXMD_FLAGS_CHECKSUM | XDP_TXMD_FLAGS_TIMESTAMP)
			: XDP_TXMD_FLAGS_CHECKSUM;
		memcpy(a->meta, &mflags, sizeof(mflags));
		cs = (__u16)i;
		memcpy(a->meta + 8,  &cs, sizeof(cs));
		cs = (__u16)(i >> 1);
		memcpy(a->meta + 10, &cs, sizeof(cs));
	}
	return NULL;
}

/*
 * Phase 6: enqueue 1 (or 2 chained, for want_sg) TX descriptors into
 * the TX ring then sendto(MSG_DONTWAIT) to kick xsk_sendmsg.  This
 * drives descriptors through xsk_buff_pool — the live-pool path we
 * want to race against the deletes/munmaps below.  No-op when bind()
 * didn't take.  Touches the want_tx_md / want_sg per-iter knobs to
 * stamp xsk_tx_metadata in headroom and set XDP_PKT_CONTD/XDP_TX_METADATA
 * in desc->options where appropriate.
 *
 * When want_tx_md fires, a short-lived scribbler pthread is spawned
 * just before the sendto() kick to overwrite the metadata bytes WHILE
 * the kernel reads them, opening the TOCTOU window on the sw-csum
 * double-read.  The thread is hard-joined before this function returns
 * — trinity children keep fuzzing past here and a leaked thread would
 * corrupt subsequent ops.
 */
static void afxdp_iter_tx_burst(struct xsk_state *st,
				bool want_sg, bool want_tx_md)
{
	struct afxdp_meta_scribbler_args sa;
	pthread_t scribbler_tid;
	bool scribbler_spawned = false;
	uint32_t *prod;
	struct xdp_desc *desc;
	uint32_t p, chunk_sz, enq = 1U;
	uint64_t head_addr;
	uint16_t head_opts;

	if (!st->bound)
		return;

	/* Inject TX descriptor(s) into the TX ring, then sendto-kick.
	 * xsk_sendmsg walks the TX ring and pulls the descriptors
	 * through xsk_buff_pool — the live-pool path we want to race
	 * against the deletes/munmaps below.
	 *
	 * Multibuf path (want_sg): enqueue two chained descriptors,
	 * head with XDP_PKT_CONTD set in options.  Hits the chained-
	 * frag walker that 0f3776583d28 fixes (per-desc UAF when the
	 * chain crosses UMEM frag boundaries).
	 *
	 * TX-metadata path (want_tx_md): stamp xsk_tx_metadata into
	 * the headroom region just before the head desc->addr and set
	 * XDP_TX_METADATA in head->options.  The kernel reads csum
	 * fields from there; d73a9a63f9f7 mishandled this when the
	 * bound netdev advertises IFF_TX_SKB_NO_LINEAR. */
	prod = (uint32_t *)((char *)st->tx_ring + st->off.tx.producer);
	desc = (struct xdp_desc *)((char *)st->tx_ring + st->off.tx.desc);
	p         = __atomic_load_n(prod, __ATOMIC_RELAXED);
	chunk_sz  = want_sg ? AFXDP_SG_CHUNK_SIZE : AFXDP_CHUNK_SIZE;
	head_addr = want_tx_md ? AFXDP_TX_META_BYTES : 0;
	head_opts = (want_sg ? XDP_PKT_CONTD : 0) |
		    (want_tx_md ? XDP_TX_METADATA : 0);

	if (want_tx_md && (char *)st->umem != MAP_FAILED) {
		/* metadata header is 16 bytes immediately preceding
		 * head_addr in the UMEM region — relies on headroom
		 * being set to AFXDP_TX_META_BYTES at UMEM_REG. */
		unsigned char *meta = (unsigned char *)st->umem +
				      head_addr - AFXDP_TX_META_BYTES;
		__u64 mflags = XDP_TXMD_FLAGS_CHECKSUM |
			       ((rnd_u32() & 1) ? XDP_TXMD_FLAGS_TIMESTAMP : 0);

		memset(meta, 0, AFXDP_TX_META_BYTES);
		memcpy(meta, &mflags, sizeof(mflags));
		/* csum_start=0, csum_offset=0 — bytes 8..11 already zero. */

		/* Spawn the scribbler BEFORE the sendto() kick so the
		 * overwrite is already in flight when xsk_sendmsg reads
		 * the metadata.  pthread_create failure (EAGAIN under
		 * nproc/thread limits) is non-fatal — the TX path still
		 * runs, just without the race. */
		sa.meta = meta;
		sa.stop = 0;
		if (pthread_create(&scribbler_tid, NULL,
				   afxdp_meta_scribbler, &sa) == 0)
			scribbler_spawned = true;
	}

	desc[p % AFXDP_RING_ENTRIES].addr    = head_addr;
	desc[p % AFXDP_RING_ENTRIES].len     = 1;
	desc[p % AFXDP_RING_ENTRIES].options = head_opts;
	if (want_sg) {
		uint32_t q = (p + 1) % AFXDP_RING_ENTRIES;

		desc[q].addr    = (uint64_t)chunk_sz + head_addr;
		desc[q].len     = 1;
		desc[q].options = 0;	/* tail of chain */
		enq = 2U;
	}
	__atomic_store_n(prod, p + enq, __ATOMIC_RELEASE);

	if (sendto(st->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0) >= 0 ||
	    errno == EAGAIN || errno == ENOBUFS || errno == EBUSY)
		__atomic_add_fetch(&shm->stats.afxdp_churn_send_ok,
				   1, __ATOMIC_RELAXED);

	/* HARD REQUIREMENT: stop + join the scribbler before returning.
	 * trinity children keep fuzzing after this op completes; a leaked
	 * thread would scribble UMEM that has already been munmap'd or
	 * scribble subsequent ops' shared state. */
	if (scribbler_spawned) {
		__atomic_store_n(&sa.stop, 1, __ATOMIC_RELAXED);
		(void)pthread_join(scribbler_tid, NULL);
	}
}

/*
 * Phase 7: the live-socket race window.  XDP_STATISTICS read while RX
 * is bound (stats walker concurrently reads ring counters the bound
 * rings are producing into), RACE A = XSKMAP delete on the bound key
 * (CVE-2024-50115: xdp_do_redirect's RCU-protected map pointer freed
 * under the walker), RACE B = munmap the FILL ring while still bound
 * (CVE-2023-39197: xsk_buff_pool refcount must outlive the user's
 * munmap of its own ring view).  All three are no-ops without bind.
 */
static void afxdp_iter_run_races(struct xsk_state *st)
{
	struct xdp_statistics xstats;
	socklen_t xstats_len = sizeof(xstats);

	/* XDP_STATISTICS read while RX is bound -- the stats walker reads
	 * the per-ring ring_full / fill_ring_empty_descs counters which
	 * the bound rings are concurrently producing into. */
	if (getsockopt(st->xsk_fd, SOL_XDP, XDP_STATISTICS,
		       &xstats, &xstats_len) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn_recv_ok,
				   1, __ATOMIC_RELAXED);

	/* RACE A: delete the bound XSKMAP entry.  CVE-2024-50115 surface --
	 * xdp_do_redirect()'s map walker holds an RCU-protected pointer
	 * that this delete frees from under it. */
	if (st->bound && xskmap_delete(st->map_fd, 0) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn_map_delete_ok,
				   1, __ATOMIC_RELAXED);

	/* RACE B: munmap the FILL ring while still bound.  CVE-2023-39197
	 * surface -- the xsk_buff_pool refcount on the umem region must
	 * keep the kernel's mapping alive past the user's munmap of its
	 * own ring view. */
	if (st->bound && st->fr_ring != MAP_FAILED && st->fr_ring_sz) {
		if (munmap(st->fr_ring, st->fr_ring_sz) == 0)
			__atomic_add_fetch(&shm->stats.afxdp_churn_munmap_race_ok,
					   1, __ATOMIC_RELAXED);
		st->fr_ring = MAP_FAILED;
		st->fr_ring_sz = 0;
	}
}

/* One full setup + race + teardown cycle on a fresh AF_XDP socket. */
static void iter_one(struct childdata *child, unsigned int idx,
		     const struct timespec *t_outer)
{
	struct xsk_state st;
	char tun_name[IFNAMSIZ];
	unsigned int target_ifindex;
	bool want_sg, want_tx_md, want_tun;

	(void)idx;

	if ((unsigned long long)ns_since(t_outer) >= AFXDP_WALL_CAP_NS)
		return;

	xsk_init(&st);

	if (afxdp_iter_setup_umem(child, &st, &want_sg, &want_tx_md, &want_tun) < 0)
		goto out;

	if (afxdp_iter_setup_rings(&st) < 0)
		goto out;

	if (afxdp_iter_setup_bpf(&st) < 0)
		goto out;

	if (afxdp_iter_bind(&st, want_sg, &want_tun, tun_name,
			    &target_ifindex) < 0)
		goto out;

	/* Per-iter acceptance / data-path counters: only credit an iter that
	 * reached a bound xsk — without bind() the downstream attach / tx /
	 * race phases all no-op internally, so neither counter applies.  Gating
	 * both on st.bound preserves the data_path <= setup_accepted invariant
	 * (either both bump together or neither does). */

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (st.bound && valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
	}

	afxdp_iter_attach_prog(&st, target_ifindex);

	if (st.bound && valid_op) {
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	afxdp_iter_tx_burst(&st, want_sg, want_tx_md);

	afxdp_iter_run_races(&st);

out:
	xsk_teardown(&st);
}

bool afxdp_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

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

		iter_one(child, i, &t_outer);

		if (ns_unsupported_afxdp)
			break;
	}

	return true;
}

#else  /* missing <linux/if_xdp.h> or <linux/bpf.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
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
