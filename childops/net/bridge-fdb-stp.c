/*
 * bridge_fdb_stp - bridge fdb learn vs delete vs STP topology race.
 *
 * Flat netlink fuzzing rarely stands up the full chain the software
 * bridge needs to co-fire learning + topology-change: a bridge dev,
 * enslaved+UP ports with BR_LEARNING, rx-path traffic driving
 * net/bridge/br_fdb.c:br_fdb_update (not RTM_NEWNEIGH NTF_MASTER,
 * which bypasses the receive-path window), and a live STP state
 * machine.  Bug class: br_fdb_delete_by_port lineage (UAF on port
 * teardown racing br_fdb_update from rx softirq), STP topology-change
 * timer races (br_stp_change_bridge_id vs port state transition).
 *
 * Per invocation, inside a private user+net namespace via
 * userns_run_in_ns (grandchild _exit reaps the bridge/veths/fdb/
 * netns): create a bridge, two veth pairs enslaved and UP with
 * BR_LEARNING armed, AF_PACKET SOCK_RAW into one port sending frames
 * with random unicast SMACs to drive br_fdb_update, toggle STP via
 * /sys/class/net/<br>/bridge/stp_state, then race RTM_DELNEIGH on a
 * just-learned entry and RTM_DELLINK on the bridge against the still-
 * draining rx path.
 *
 * Brick-safety: one create/destroy cycle per invocation inside the
 * private netns; loopback only; packet burst BUDGETED+JITTER (base 3,
 * 200 ms wall cap); MSG_DONTWAIT + SO_RCVTIMEO=1s so no I/O outlives
 * child.c's SIGALRM(1s).
 *
 * Latches: userns -EPERM permanently gates the op off for this child;
 * -EAGAIN skips without latching.  Per-feature latches
 * (ns_unsupported_bridge / _veth / _sysfs_stp) fire on the first
 * EOPNOTSUPP/EROFS/EACCES so a kernel without CONFIG_BRIDGE / veth /
 * sysfs-writable knobs pays the failure once.  Header-gated by
 * __has_include on <linux/if_bridge.h>/<linux/veth.h>.
 */

#if __has_include(<linux/if_bridge.h>)
#include <linux/if_bridge.h>
#endif
#if __has_include(<linux/veth.h>)
#include <linux/veth.h>
#endif

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
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

static const unsigned int vlan_mass_n_choices[] = {
	100, 1000, 10000, 50000, 100000,
};

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared — kernel module / config
 * presence is static for the child's lifetime, so we pay the EFAIL
 * once and skip the path on subsequent invocations. */
static bool ns_unsupported_bridge;
static bool ns_unsupported_veth;
static bool ns_unsupported_sysfs_stp;

/* Latched per-child: userns_run_in_ns() reported -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by a hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private netns we MUST NOT touch the host's main bridge /
 * fdb / veth tables, so the op stays disabled for the remainder of
 * this child's lifetime.  Transient setup failures (helper return
 * -EAGAIN) do not set this — they may not recur on the next
 * iteration. */
static bool ns_unsupported;
static bool lo_brought_up;

/* Per-invocation state shared across the extracted phase helpers.  Fd
 * fields default to -1 via the orchestrator's designated initialiser
 * so the teardown helper can close them unconditionally regardless of
 * which earlier phase bailed.  Name buffers are filled in by
 * setup_names; br_idx/bridge_added by bridge_create;
 * port_idx[]/veth0_added/veth1_added by veth_attach; raw by
 * traffic_burst. */
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

/*
 * Bring lo up inside the private netns.  A freshly-unshared netns has
 * lo present but DOWN; some bridge / fdb code paths short-circuit on
 * the upper-layer carrier state, so flip lo up once-per-child.
 * Failures are ignored — they latch through the rest of the sequence
 * naturally.
 */
/*
 * RTM_NEWLINK type=bridge with the supplied dev name.  No
 * IFLA_INFO_DATA — defaults are fine for our purposes (STP off,
 * default ageing, default forward delay).  STP gets toggled later
 * via sysfs.  Returns 0 on accept, negated errno on rejection,
 * -EIO on local failure.
 */
static int build_bridge_create(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;
	size_t li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off)
		return -EIO;

	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK type=veth with VETH_INFO_PEER carrying the peer's
 * ifinfomsg + IFLA_IFNAME.  Distinct peer names per pair so the four
 * veth ends in this op are unambiguously addressable by name.
 */
static int build_veth_create(struct nl_ctx *ctx, const char *name,
			     const char *peer_name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct ifinfomsg *peer_ifi;
	size_t off;
	size_t li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off)
		return -EIO;

	/* VETH_INFO_PEER's payload starts with an ifinfomsg, then
	 * regular IFLA attributes (IFLA_IFNAME for the peer name). */
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer_name);
	if (!off)
		return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK with IFLA_MASTER=master_ifindex on ifindex.  Enslaves
 * the veth end to the bridge.
 */
static int build_setlink_master(struct nl_ctx *ctx, int ifindex,
				int master_ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER,
			  (__u32)master_ifindex);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK family=AF_BRIDGE with IFLA_PROTINFO containing
 * IFLA_BRPORT_LEARNING=1 — arms BR_LEARNING on the port.  This is
 * what makes the receive-path frame ingress drive br_fdb_update
 * (the rx-driven learning path the op exists to exercise).
 */
static int build_setlink_brport_learning(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, pi_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	pi_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     IFLA_PROTINFO | NLA_F_NESTED);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), IFLA_BRPORT_LEARNING, 1);
	if (!off)
		return -EIO;

	nla_nest_end(buf, pi_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_DELNEIGH for a fdb entry: family=AF_BRIDGE, ndm_ifindex=port,
 * NDA_LLADDR=mac.  Races the receive-path learning that may be
 * re-installing the same entry concurrently — the targeted
 * learn-vs-delete window.
 */
static int build_fdb_del(struct nl_ctx *ctx, int port_ifindex,
			 const unsigned char *mac)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ndm = (struct ndmsg *)NLMSG_DATA(nlh);
	ndm->ndm_family  = AF_BRIDGE;
	ndm->ndm_ifindex = port_ifindex;
	ndm->ndm_state   = NUD_REACHABLE;
	ndm->ndm_flags   = NTF_MASTER;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ndm));
	off = nla_put(buf, off, sizeof(buf), NDA_LLADDR, mac, 6);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Toggle STP via /sys/class/net/<br>/bridge/stp_state.  Open + write
 * + close per call.  EROFS / EACCES / ENOENT all latch
 * ns_unsupported_sysfs_stp — those are the failure modes for a
 * kernel without sysfs writeable bridge knobs (read-only bind mount,
 * lockdown=integrity, missing CONFIG_SYSFS).
 */
static bool sysfs_stp_write(const char *brname, char val)
{
	char path[64];
	int fd;
	ssize_t n;

	if (snprintf(path, sizeof(path),
		     "/sys/class/net/%s/bridge/stp_state", brname) >= (int)sizeof(path))
		return false;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == EROFS || errno == EACCES || errno == ENOENT)
			ns_unsupported_sysfs_stp = true;
		return false;
	}

	n = write(fd, &val, 1);
	close(fd);
	return n == 1;
}

/*
 * Generate a random unicast, locally-administered MAC.  Bit 0 of the
 * first byte is the multicast bit (must be 0); bit 1 is the
 * locally-administered bit (set so we don't collide with any host
 * OUI).  br_fdb_update accepts any unicast lladdr.
 */
static void random_unicast_lla(unsigned char *mac)
{
	generate_rand_bytes(mac, 6);
	mac[0] = (unsigned char)((mac[0] & 0xfc) | 0x02);
}

/*
 * Build + sendmsg one RTM_SETLINK on `port_ifindex` whose IFLA_AF_SPEC
 * nest holds `n` IFLA_BRIDGE_VLAN_INFO entries.  Returns 0 on send +
 * ack receipt, or -errno (ENOBUFS / EMSGSIZE / EIO) on rejection.  The
 * 1 MiB scratch buffer caps the actual on-wire size; if `n` would
 * overflow we truncate and send what fits.
 *
 * Open-codes the sendmsg here (instead of going through nl_send_recv)
 * because this path uses MSG_DONTWAIT and discards the recv result —
 * a 1 MiB request can face slow kernel processing and we don't want
 * to block past the SIGALRM(1s) child cap waiting for a tx queue slot.
 */
static int build_setlink_vlan_mass(struct nl_ctx *ctx, int port_ifindex,
				   unsigned int n, unsigned int *vid_seed)
{
	unsigned char *buf;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	struct bridge_vlan_info bvi;
	__u16 br_flags = BRIDGE_FLAGS_MASTER;
	size_t off, af_off, cap = VLAN_MASS_BUF_BYTES;
	unsigned int i;
	unsigned char rbuf[1024];
	ssize_t s;
	int rc = 0;

	buf = malloc(cap);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, cap);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	af_off = off;
	off = nla_nest_start(buf, off, cap, IFLA_AF_SPEC | NLA_F_NESTED);
	if (!off) { free(buf); return -EIO; }

	off = nla_put(buf, off, cap, IFLA_BRIDGE_FLAGS,
		      &br_flags, sizeof(br_flags));
	if (!off) { free(buf); return -EIO; }

	for (i = 0; i < n; i++) {
		size_t next;

		bvi.flags = ((i & 7) == 0) ? BRIDGE_VLAN_INFO_MASTER : 0;
		bvi.vid   = (__u16)(((*vid_seed)++ % 4094U) + 1U);
		next = nla_put(buf, off, cap, IFLA_BRIDGE_VLAN_INFO,
			       &bvi, sizeof(bvi));
		if (!next)
			break;	/* buffer full — send what we have */
		off = next;
	}

	nla_nest_end(buf, af_off, off);
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

	s = sendmsg(ctx->fd, &mh, MSG_DONTWAIT);
	if (s < 0)
		rc = -errno;
	else
		(void)recv(ctx->fd, rbuf, sizeof(rbuf), 0);

	free(buf);
	return rc;
}

/*
 * Mass-VLAN-add sub-mode entry.  Builds a fresh br + veth pair in the
 * (already-unshared) netns, enslaves + ups the veth, then runs the
 * BUDGETED outer loop, each iter picking N from {100,1k,10k,50k,100k}
 * and pushing one bulk SETLINK.  Cleanup deletes the bridge (cascades
 * the veth) plus the surviving veth end on error.
 */
static void bridge_vlan_mass_add(struct nl_ctx *ctx)
{
	char br_name[IFNAMSIZ];
	char veth_a[IFNAMSIZ], veth_b[IFNAMSIZ];
	int br_idx = 0, va_idx = 0;
	bool bridge_added = false, veth_added = false;
	struct timespec t0;
	unsigned int rng = (unsigned int)(rand32() & 0xffffu);
	unsigned int iters, i;
	unsigned int vid_seed = 0;

	__atomic_add_fetch(&shm->stats.bridge_vlan_mass_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_bridge || ns_unsupported_veth)
		return;

	snprintf(br_name, sizeof(br_name), "trbm%u", rng);
	snprintf(veth_a, sizeof(veth_a), "trbmv%ua", rng);
	snprintf(veth_b, sizeof(veth_b), "trbmv%ub", rng);

	if (build_bridge_create(ctx, br_name) != 0)
		goto out;
	bridge_added = true;
	br_idx = (int)if_nametoindex(br_name);
	if (br_idx <= 0)
		goto out;

	if (build_veth_create(ctx, veth_a, veth_b) != 0)
		goto out;
	veth_added = true;
	va_idx = (int)if_nametoindex(veth_a);
	if (va_idx <= 0)
		goto out;

	(void)build_setlink_master(ctx, va_idx, br_idx);
	(void)rtnl_setlink_up(ctx, br_idx);
	(void)rtnl_setlink_up(ctx, va_idx);

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_BRIDGE_FDB_STP,
			 JITTER_RANGE(VLAN_MASS_OUTER_BASE));
	if (iters < 1)
		iters = 1;
	if (iters > VLAN_MASS_OUTER_CAP)
		iters = VLAN_MASS_OUTER_CAP;

	for (i = 0; i < iters; i++) {
		unsigned long want, cur;
		unsigned int n;
		int rc;

		if (ns_since(&t0) >= VLAN_MASS_BUDGET_NS)
			break;

		n = vlan_mass_n_choices[rnd_modulo_u32(
			sizeof(vlan_mass_n_choices) /
			sizeof(vlan_mass_n_choices[0]))];

		rc = build_setlink_vlan_mass(ctx, va_idx, n, &vid_seed);
		if (rc == -ENOBUFS || rc == -EMSGSIZE)
			__atomic_add_fetch(&shm->stats.bridge_vlan_mass_enotbufs,
					   1, __ATOMIC_RELAXED);

		want = n;
		cur = __atomic_load_n(&shm->stats.bridge_vlan_mass_max_n,
				      __ATOMIC_RELAXED);
		while (want > cur &&
		       !__atomic_compare_exchange_n(&shm->stats.bridge_vlan_mass_max_n,
						    &cur, want, false,
						    __ATOMIC_RELAXED,
						    __ATOMIC_RELAXED))
			;
	}

out:
	if (bridge_added && br_idx > 0)
		(void)rtnl_dellink(ctx, br_idx);
	if (veth_added && va_idx > 0)
		(void)rtnl_dellink(ctx, va_idx);
}

/*
 * Phase 1: pick the per-invocation interface names.  All five names
 * (one bridge + two veth pairs) share a single 16-bit random suffix so
 * a long-lived child's traces correlate by suffix inside its private
 * netns.  Cheap and infallible — no return value.
 */
static void bridge_fdb_stp_iter_setup_names(struct bridge_fdb_stp_iter_ctx *ctx)
{
	unsigned int rng = (unsigned int)(rand32() & 0xffffu);

	snprintf(ctx->br_name, sizeof(ctx->br_name), "trbr%u", rng);
	snprintf(ctx->veth0a, sizeof(ctx->veth0a), "trbv%ua0", rng);
	snprintf(ctx->veth0b, sizeof(ctx->veth0b), "trbv%ub0", rng);
	snprintf(ctx->veth1a, sizeof(ctx->veth1a), "trbv%ua1", rng);
	snprintf(ctx->veth1b, sizeof(ctx->veth1b), "trbv%ub1", rng);
}

/*
 * Phase 2: create the bridge link and capture its ifindex.  Latches
 * ns_unsupported_bridge on the family/proto rejection codes the
 * rtnetlink layer returns when CONFIG_BRIDGE is absent so siblings
 * stop probing; EBUSY / EEXIST from a stale name are NOT latched —
 * those leave the gate open for the next iteration to retry with
 * fresh rng.  The if_nametoindex call is folded in because losing
 * the index makes every later step a no-op.  Returns 0 on success
 * or -1 if the iteration should bail to the out: cleanup path; on
 * success ctx->bridge_added is set so the teardown helper knows to
 * RTM_DELLINK it.
 */
static int bridge_fdb_stp_iter_bridge_create(struct bridge_fdb_stp_iter_ctx *ctx)
{
	int rc;

	rc = build_bridge_create(&ctx->ctx, ctx->br_name);
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -ENOENT || rc == -EPROTONOSUPPORT)
			ns_unsupported_bridge = true;
		return -1;
	}
	ctx->bridge_added = true;
	__atomic_add_fetch(&shm->stats.bridge_fdb_stp_bridge_create_ok,
			   1, __ATOMIC_RELAXED);

	ctx->br_idx = (int)if_nametoindex(ctx->br_name);
	if (ctx->br_idx == 0)
		return -1;

	/* Kernel confirmed ctx->br_name now names a real bridge master;
	 * publish it via the NETDEV name pool so sibling childops (and
	 * per-syscall fuzzers drawing this kind) can collide with it on
	 * subsequent invocations -- reaches "name a previous syscall
	 * planted" lookup codepaths instead of always-fresh-random
	 * near-miss space.  Record the master only; the two veth pairs
	 * created later are deliberately skipped to keep the per-kind
	 * 16-slot ring from being dominated by a single op's leaves. */
	name_pool_record(NAME_KIND_NETDEV, ctx->br_name,
			 strlen(ctx->br_name));
	return 0;
}

/*
 * Phase 3: create both veth pairs, resolve their port ifindices,
 * enslave each end to the bridge, bring all five interfaces (bridge
 * + four veth ends) UP, and arm BR_LEARNING on every surviving port.
 * ns_unsupported_veth latches on pair 0's structural-errno failure
 * (CONFIG_VETH absent) so pair 1 short-circuits in the same call.
 * The setlink_master / setlink_up / brport_learning calls are
 * best-effort by design (they were (void)-casts in the original) — a
 * missing slave or DOWN port still leaves the receive-path learning
 * window partially open; the failure shape just shrinks the surface
 * area rather than aborting the iteration.  No return value: later
 * phases gate independently on ctx->port_idx[i] > 0.
 */
static void bridge_fdb_stp_iter_veth_attach(struct bridge_fdb_stp_iter_ctx *ctx)
{
	const char *port_names[4];
	unsigned int i;
	int rc;

	if (!ns_unsupported_veth) {
		rc = build_veth_create(&ctx->ctx, ctx->veth0a, ctx->veth0b);
		if (rc != 0) {
			if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
			    rc == -ENOTSUP || rc == -ENOENT)
				ns_unsupported_veth = true;
		} else {
			ctx->veth0_added = true;
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp_veth_create_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	if (!ns_unsupported_veth) {
		rc = build_veth_create(&ctx->ctx, ctx->veth1a, ctx->veth1b);
		if (rc == 0) {
			ctx->veth1_added = true;
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp_veth_create_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	port_names[0] = ctx->veth0_added ? ctx->veth0a : NULL;
	port_names[1] = ctx->veth0_added ? ctx->veth0b : NULL;
	port_names[2] = ctx->veth1_added ? ctx->veth1a : NULL;
	port_names[3] = ctx->veth1_added ? ctx->veth1b : NULL;

	for (i = 0; i < 4; i++) {
		if (!port_names[i])
			continue;
		ctx->port_idx[i] = (int)if_nametoindex(port_names[i]);
		if (ctx->port_idx[i] > 0)
			(void)build_setlink_master(&ctx->ctx, ctx->port_idx[i],
						   ctx->br_idx);
	}

	(void)rtnl_setlink_up(&ctx->ctx, ctx->br_idx);
	for (i = 0; i < 4; i++) {
		if (ctx->port_idx[i] > 0)
			(void)rtnl_setlink_up(&ctx->ctx, ctx->port_idx[i]);
	}

	for (i = 0; i < 4; i++) {
		if (ctx->port_idx[i] > 0)
			(void)build_setlink_brport_learning(&ctx->ctx,
							    ctx->port_idx[i]);
	}
}

/*
 * Phase 4: open the AF_PACKET raw socket on the first surviving port,
 * spray a bounded burst of broadcast frames with random
 * locally-administered unicast src MACs to drive br_fdb_update via the
 * receive path, then race an RTM_DELNEIGH against the rx-driven
 * learning that may be re-installing the last src.  The bridge-flooded
 * broadcast destination guarantees the bridge ingress hook sees every
 * frame regardless of fdb state; the random src is what triggers the
 * learn-on-rx path the op exists to exercise.  Wall-cap STORM_BUDGET_NS
 * holds the inner send loop well inside the SIGALRM(1s) child cap; the
 * raw socket open / bind failures degrade gracefully — there's no
 * targeted race left to run if the raw fd is missing, so we just skip.
 */
static void bridge_fdb_stp_iter_traffic_burst(struct bridge_fdb_stp_iter_ctx *ctx)
{
	unsigned char last_src_mac[6] = { 0 };
	bool have_last_mac = false;
	struct timespec t0;
	unsigned int iters, i, j;
	int tx_port_idx = 0;

	for (j = 0; j < 4; j++) {
		if (ctx->port_idx[j] > 0) {
			tx_port_idx = ctx->port_idx[j];
			break;
		}
	}
	if (tx_port_idx <= 0)
		return;

	ctx->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			  htons(ETH_P_ALL));
	if (ctx->raw >= 0) {
		struct sockaddr_ll sll;

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex  = tx_port_idx;
		(void)bind(ctx->raw, (struct sockaddr *)&sll, sizeof(sll));
	}

	if (ctx->raw >= 0) {
		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_BRIDGE_FDB_STP,
				 JITTER_RANGE(BRIDGE_PACKET_BASE));
		if (iters < BRIDGE_PACKET_FLOOR)
			iters = BRIDGE_PACKET_FLOOR;
		if (iters > BRIDGE_PACKET_CAP)
			iters = BRIDGE_PACKET_CAP;

		for (i = 0; i < iters; i++) {
			struct sockaddr_ll sll;
			unsigned char frame[64];
			unsigned char dst_mac[6];
			unsigned char src_mac[6];
			ssize_t n;

			if (ns_since(&t0) >= STORM_BUDGET_NS)
				break;

			/* Random locally-administered unicast src;
			 * deterministic broadcast dst so the bridge floods
			 * the frame and the src triggers br_fdb_update on
			 * ingress. */
			random_unicast_lla(src_mac);
			memset(dst_mac, 0xff, sizeof(dst_mac));

			memset(frame, 0, sizeof(frame));
			memcpy(frame + 0, dst_mac, 6);
			memcpy(frame + 6, src_mac, 6);
			frame[12] = 0x08;	/* ETH_P_IP */
			frame[13] = 0x00;
			/* payload is zeros — the bridge doesn't parse
			 * upper layers for the learning-on-rx path. */

			memset(&sll, 0, sizeof(sll));
			sll.sll_family   = AF_PACKET;
			sll.sll_protocol = htons(ETH_P_ALL);
			sll.sll_ifindex  = tx_port_idx;
			sll.sll_halen    = 6;
			memcpy(sll.sll_addr, dst_mac, 6);

			n = sendto(ctx->raw, frame, sizeof(frame),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&sll, sizeof(sll));
			if (n > 0) {
				__atomic_add_fetch(&shm->stats.bridge_fdb_stp_raw_send_ok,
						   1, __ATOMIC_RELAXED);
				memcpy(last_src_mac, src_mac,
				       sizeof(last_src_mac));
				have_last_mac = true;
			}
		}
	}

	/* fdb DELNEIGH on the most-recently-sent src mac races the
	 * rx-driven learning that may be re-installing it.  Use the
	 * same port we sent on. */
	if (have_last_mac) {
		if (build_fdb_del(&ctx->ctx, tx_port_idx, last_src_mac) == 0)
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp_fdb_del_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase 5: drive the STP state machine via sysfs.  Writing "1" then
 * "0" arms then disarms br_stp_start / br_stp_stop and the
 * topology-change timer, giving the rx-driven fdb learning in
 * traffic_burst a live STP state machine to race against.  The
 * ns_unsupported_sysfs_stp latch (set by sysfs_stp_write on
 * EROFS / EACCES / ENOENT) gates the whole helper so a sysfs-locked
 * kernel pays the EFAIL once per child rather than per iteration.
 */
static void bridge_fdb_stp_iter_stp_toggle(struct bridge_fdb_stp_iter_ctx *ctx)
{
	if (ns_unsupported_sysfs_stp)
		return;

	if (sysfs_stp_write(ctx->br_name, '1'))
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp_stp_toggle_ok,
				   1, __ATOMIC_RELAXED);
	if (sysfs_stp_write(ctx->br_name, '0'))
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp_stp_toggle_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase 6: close whichever resources we managed to open.  Runs on
 * every exit path — both the success path after stp_toggle returns
 * and any early-bail goto out from an earlier phase.  Order matches
 * the original out: cleanup: close the raw fd first (any frames still
 * buffered there get discarded), then RTM_DELLINK the bridge before
 * closing rtnl itself.  The bridge dellink cascades both veth pairs
 * via br_dev_delete — that's the targeted teardown-vs-rx window, so
 * the veths must NOT be pre-DELLINKed.  The mop-up DELLINKs on
 * port_idx[0]/port_idx[2] catch veths whose bridge enslave failed,
 * so a long-lived child doesn't accumulate orphan veths in its
 * private netns.  All fields default to -1 / false via the
 * orchestrator's designated initialiser so the guards skip work that
 * was never set up.
 */
static void bridge_fdb_stp_iter_teardown(struct bridge_fdb_stp_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);

	if (ctx->ctx.fd >= 0) {
		if (ctx->bridge_added && ctx->br_idx > 0) {
			if (rtnl_dellink(&ctx->ctx, ctx->br_idx) == 0)
				__atomic_add_fetch(&shm->stats.bridge_fdb_stp_link_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		if (ctx->veth0_added && ctx->port_idx[0] > 0)
			(void)rtnl_dellink(&ctx->ctx, ctx->port_idx[0]);
		if (ctx->veth1_added && ctx->port_idx[2] > 0)
			(void)rtnl_dellink(&ctx->ctx, ctx->port_idx[2]);
		nl_close(&ctx->ctx);
	}
}

/*
 * Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot.
 */
struct bridge_fdb_stp_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any bridges,
 * veth pairs, fdb entries, sockets and sysfs handles left behind are
 * reaped by the kernel along with the namespace.  Return value is
 * ignored by the helper.
 */
static int bridge_fdb_stp_in_ns(void *arg)
{
	struct bridge_fdb_stp_ctx *cctx = (struct bridge_fdb_stp_ctx *)arg;
	struct childdata *child = cctx->child;
	struct bridge_fdb_stp_iter_ctx ictx = {
		.ctx = { .fd = -1 },
		.raw = -1,
	};
	struct nl_open_opts nl_opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ictx.ctx, &nl_opts) < 0) {
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp_setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	if (!lo_brought_up) {
		rtnl_bring_lo_up(&ictx.ctx);
		lo_brought_up = true;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (ONE_IN(8)) {
		bridge_vlan_mass_add(&ictx.ctx);
		nl_close(&ictx.ctx);
		return 0;
	}

	bridge_fdb_stp_iter_setup_names(&ictx);

	if (bridge_fdb_stp_iter_bridge_create(&ictx) != 0)
		goto out;

	bridge_fdb_stp_iter_veth_attach(&ictx);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	bridge_fdb_stp_iter_traffic_burst(&ictx);

	bridge_fdb_stp_iter_stp_toggle(&ictx);

out:
	bridge_fdb_stp_iter_teardown(&ictx);
	return 0;
}

bool bridge_fdb_stp(struct childdata *child)
{
	struct bridge_fdb_stp_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.bridge_fdb_stp_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported || ns_unsupported_bridge)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, bridge_fdb_stp_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, same pattern the child.c dispatch loop uses for the
		 * unguarded write that motivated this guard. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
