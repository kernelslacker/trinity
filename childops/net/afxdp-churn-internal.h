#ifndef _CHILDOPS_NET_AFXDP_CHURN_INTERNAL_H
#define _CHILDOPS_NET_AFXDP_CHURN_INTERNAL_H

/*
 * Shared declarations for the afxdp-churn translation units.
 *
 * afxdp-churn started as a single ~1150-line .c file covering AF_XDP
 * socket setup, XDP program attach, TX/RX kick, and teardown.  It is
 * carved along the AF_XDP-lifecycle seams so the parallel make can
 * cover more work:
 *
 *   afxdp-churn.c            CHILDOP entry + iter_one orchestrator
 *   afxdp-churn-umem.c       UMEM + ring + BPF (XSKMAP + prog) setup
 *   afxdp-churn-attach.c     tun open, xsk bind, XDP prog attach
 *   afxdp-churn-io.c         TX descriptor kick + live-socket races
 *   afxdp-churn-teardown.c   xsk_init / xsk_teardown
 *
 * This header carries the UAPI/toolchain fallbacks, per-op constants,
 * the per-iteration state struct, and prototypes for the entry points
 * the orchestrator calls into.  Everything is gated on the same
 * __has_include guard as the .c files so a stripped sysroot without
 * <linux/if_xdp.h> or <linux/bpf.h> falls back cleanly to the stub
 * afxdp_churn() in afxdp-churn.c.
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

/* Per-op unsupported latches.  Defined in afxdp-churn.c; read/written
 * from the split TUs (umem/attach/etc.) as the kernel rejects feature
 * bits with EINVAL/EPERM/EAFNOSUPPORT.  Non-static so the split TUs can
 * see them; single-threaded per child so no ordering games needed. */
extern bool ns_unsupported_afxdp;
extern bool ns_unsupported_bpf_xdp;
extern bool ns_unsupported_xdp_sg;
extern bool ns_unsupported_tx_metadata;

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

/* Shared errno-classifier for the bounded-retry loops.  static inline so
 * every TU that runs a retry loop (umem setsockopt, bind) gets its own
 * copy without pulling an extern symbol. */
static inline bool afxdp_retryable(int e)
{
	return e == EAGAIN || e == EBUSY || e == EINTR;
}

/* Lifecycle: init zeroes/-1s the fd fields and MAP_FAILEDs the mmap
 * pointers so partial-setup teardown is safe on every early return.
 * Teardown is the mirror image; both live in afxdp-churn-teardown.c. */
void xsk_init(struct xsk_state *st);
void xsk_teardown(struct xsk_state *st);

/* Setup phases (afxdp-churn-umem.c): open the AF_XDP socket + UMEM,
 * then all four rings, then the BPF side (XSKMAP + redirect prog +
 * xskmap_install). */
int afxdp_iter_setup_umem(struct childdata *child, struct xsk_state *st,
			  bool *want_sg_out, bool *want_tx_md_out,
			  bool *want_tun_out);
int afxdp_iter_setup_rings(struct xsk_state *st);
int afxdp_iter_setup_bpf(struct xsk_state *st);

/* Bind + XDP-attach phases (afxdp-churn-attach.c).  bind() picks the
 * tun-vs-lo target and stamps *target_ifindex_out; attach_prog runs
 * BPF_LINK_CREATE with an RTM_NEWLINK IFLA_XDP fallback. */
int afxdp_iter_bind(struct xsk_state *st, bool want_sg,
		    bool *want_tun, char *tun_name,
		    unsigned int *target_ifindex_out);
void afxdp_iter_attach_prog(struct xsk_state *st,
			    unsigned int target_ifindex);

/* Detach helper.  Lives in afxdp-churn-attach.c next to its send-side
 * twin; xsk_teardown() calls it to reverse a netlink-fallback attach. */
int xdp_netlink_set_fd(struct nl_ctx *rtnl, unsigned int ifindex,
		       int prog_fd);

/* Data-path phases (afxdp-churn-io.c): enqueue + kick a TX burst, then
 * open the CVE-2024-50115 / CVE-2023-39197 race windows on the live
 * socket. */
void afxdp_iter_tx_burst(struct xsk_state *st,
			 bool want_sg, bool want_tx_md);
void afxdp_iter_run_races(struct xsk_state *st);

#endif /* __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>) */

#endif /* _CHILDOPS_NET_AFXDP_CHURN_INTERNAL_H */
