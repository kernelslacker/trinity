#ifndef _CHILDOPS_NET_BRIDGE_FDB_STP_INTERNAL_H
#define _CHILDOPS_NET_BRIDGE_FDB_STP_INTERNAL_H

/*
 * Shared declarations for the bridge-fdb-stp translation units.
 *
 * The op was a single ~1075-line .c file.  Splitting the link-setup
 * builders, FDB helpers, STP sysfs toggles, receive-path traffic burst
 * and the mass-VLAN sub-mode into per-concern translation units lets
 * the parallel make cover more work; this header carries the UAPI
 * fallbacks, per-op constants, the per-invocation state struct and the
 * cross-TU function prototypes.
 *
 * The single non-static file-scope pieces below (the ns_unsupported_*
 * latches) were static in the pre-split file; they live in
 * bridge-fdb-stp.c after the split and are extern-declared here so the
 * mass-VLAN TU can gate on them without a duplicate copy.
 */

#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#if __has_include(<linux/if_bridge.h>)
#include <linux/if_bridge.h>
#endif
#if __has_include(<linux/veth.h>)
#include <linux/veth.h>
#endif

#include <linux/netlink.h>

#include "childops-netlink.h"

/* if_bridge.h on stripped sysroots may not have BRIDGE_FLAGS_* / the
 * IFLA_BRIDGE_* enum.  These IDs are stable in the UAPI; redefine the
 * minimal subset we emit if the header didn't supply them. */
#ifndef BRIDGE_FLAGS_MASTER
#define BRIDGE_FLAGS_MASTER	1
#endif
#ifndef BRIDGE_FLAGS_SELF
#define BRIDGE_FLAGS_SELF	2
#endif
#ifndef IFLA_BRIDGE_FLAGS
#define IFLA_BRIDGE_FLAGS	0
#define IFLA_BRIDGE_MODE	1
#endif

#ifndef IFLA_BRIDGE_VLAN_INFO
#define IFLA_BRIDGE_VLAN_INFO	2
#endif

#ifndef BRIDGE_VLAN_INFO_MASTER
#define BRIDGE_VLAN_INFO_MASTER	(1 << 0)
#endif

/* If <linux/if_bridge.h> is missing (stripped sysroot), the UAPI struct
 * still has a stable layout: u16 flags + u16 vid. */
#if !__has_include(<linux/if_bridge.h>)
struct bridge_vlan_info {
	__u16 flags;
	__u16 vid;
};
#endif

/* IFLA_BRPORT_LEARNING value 8 from net/bridge UAPI; redefine if the
 * if_link.h on this sysroot is too old to expose it. */
#ifndef IFLA_BRPORT_LEARNING
#define IFLA_BRPORT_LEARNING	8
#endif

/* IFLA_PROTINFO is the legacy per-port nested attribute slot used by
 * br_setlink for IFLA_BRPORT_*. */
#ifndef IFLA_PROTINFO
#define IFLA_PROTINFO		12
#endif

#ifndef NDA_DST
#define NDA_DST			1
#endif
#ifndef NDA_LLADDR
#define NDA_LLADDR		2
#endif
#ifndef NDA_MASTER
#define NDA_MASTER		9
#endif

#ifndef NUD_REACHABLE
#define NUD_REACHABLE		0x02
#endif

#ifndef NTF_MASTER
#define NTF_MASTER		(1 << 2)
#endif

/* Reasonable ceiling on a single rtnl message + payload.  A bridge or
 * veth NEWLINK with IFLA_LINKINFO + IFLA_INFO_DATA + nested peer
 * ifinfomsg fits well under 1 KiB; 2 KiB leaves headroom. */
#define RTNL_BUF_BYTES		2048

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it: a
 * productive run grows to ~iter*4 sends, an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * the iteration past the SIGALRM(1s) cap. */
#define BRIDGE_PACKET_BASE	3U
#define BRIDGE_PACKET_FLOOR	8U	/* always send at least this many */
#define BRIDGE_PACKET_CAP	64U	/* upper clamp on per-iter burst */
#define STORM_BUDGET_NS		200000000L	/* 200 ms */

/* mass-VLAN-add sub-mode: a single RTM_SETLINK whose IFLA_AF_SPEC nest
 * carries up to ~100k IFLA_BRIDGE_VLAN_INFO entries.  Drives the kernel's
 * nbp_vlan_add → fdb_create → rhashtable_insert_rehash path, which on
 * rehash can request an 8 MiB+ vmalloc and trip the vmalloc_huge cap in
 * mm/vmalloc.c.  Kernels that reject the message early return -ENOBUFS
 * or -EMSGSIZE; we count those rather than treating them as failures.
 *
 * Outer-loop budget mirrors the rest of the op: BUDGETED+JITTER around
 * base 4 with a hard cap of 12, and a 200 ms wall-clock cap so a single
 * sub-mode invocation can't outrun the SIGALRM(1s) inherited from
 * child.c even if every sendmsg blocks behind kernel processing.
 *
 * IFLA_BRIDGE_VLAN_INFO is plain (struct bridge_vlan_info){flags,vid};
 * vid is 12-bit on the wire so the {1..4094} space wraps for the larger
 * Ns — the duplicate-vid adds still walk the same fdb_create path the
 * bug lives on.  Some entries set BRIDGE_VLAN_INFO_MASTER to vary
 * between the per-port and the master-bridge insertion paths. */
#define VLAN_MASS_OUTER_BASE	4U
#define VLAN_MASS_OUTER_CAP	12U
#define VLAN_MASS_BUDGET_NS	200000000L	/* 200 ms */
#define VLAN_MASS_BUF_BYTES	(1U << 20)	/* 1 MiB scratch */

/* Per-child latches shared across TUs.  Set on the first structural
 * failure of the corresponding subsystem and never cleared -- kernel
 * module / config presence is static for the child's lifetime, so we
 * pay the EFAIL once and skip the path on subsequent invocations.
 * Definitions live in bridge-fdb-stp.c. */
extern bool ns_unsupported_bridge;
extern bool ns_unsupported_veth;

/*
 * Per-invocation state shared across the extracted phase helpers.  Fd
 * fields default to -1 via the orchestrator's designated initialiser
 * so the teardown helper can close them unconditionally regardless of
 * which earlier phase bailed.  Name buffers are filled in by
 * setup_names; br_idx/bridge_added by bridge_create;
 * port_idx[]/veth0_added/veth1_added by veth_attach; raw by
 * traffic_burst.
 */
struct bridge_fdb_stp_iter_ctx {
	char		br_name[IFNAMSIZ];
	char		veth0a[IFNAMSIZ];
	char		veth0b[IFNAMSIZ];
	char		veth1a[IFNAMSIZ];
	char		veth1b[IFNAMSIZ];
	struct nl_ctx	ctx;
	int		port_idx[4];
	int		raw;
	int		br_idx;
	bool		bridge_added;
	bool		veth0_added;
	bool		veth1_added;
};

/* bridge-fdb-stp-setup.c */
int bfs_build_bridge_create(struct nl_ctx *ctx, const char *name);
int bfs_build_veth_create(struct nl_ctx *ctx, const char *name,
		      const char *peer_name);
int bfs_build_setlink_master(struct nl_ctx *ctx, int ifindex,
			 int master_ifindex);
int bfs_build_setlink_brport_learning(struct nl_ctx *ctx, int ifindex);

/* bridge-fdb-stp-fdb.c */
int build_fdb_del(struct nl_ctx *ctx, int port_ifindex,
		  const unsigned char *mac);
void random_unicast_lla(unsigned char *mac);

/* bridge-fdb-stp-stp.c */
void bridge_fdb_stp_iter_stp_toggle(struct bridge_fdb_stp_iter_ctx *ctx);

/* bridge-fdb-stp-traffic.c */
void bridge_fdb_stp_iter_traffic_burst(struct bridge_fdb_stp_iter_ctx *ctx);

#endif /* _CHILDOPS_NET_BRIDGE_FDB_STP_INTERNAL_H */
