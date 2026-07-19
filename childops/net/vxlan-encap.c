/*
 * vxlan_encap_churn - VXLAN / GRE / GENEVE encap setup + packet inject,
 * targeting the teardown-vs-in-flight-tx race on overlay tunnels.  Reaches
 * drivers/net/vxlan/, net/ipv4/ip_gre.c, drivers/net/geneve.c encap fast
 * paths (vxlan_xmit_one / ipgre_xmit / geneve_xmit) and the RTM_DELLINK
 * window that opens the vxlan_remcsum UAF lineage.  Flat fuzzing can't keep
 * IFLA_INFO_DATA (vni for vxlan/geneve, ikey/okey for gre), NTF_SELF fdb,
 * IFF_UP setlink, and AF_PACKET/SOCK_RAW traffic coherent across the four
 * messages needed.
 *
 * Sequence per invocation runs inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET, _exit reaps).  Persistent child runs a
 * one-shot best-effort modprobe of vxlan / ip_gre / geneve before the userns
 * hop (finit_module needs CAP_SYS_MODULE in init_user_ns).  Pick a
 * non-latched kind, RTM_NEWLINK it with local/remote pinned to
 * 127.0.0.1/127.0.0.2, bring it up, for vxlan add an NTF_SELF fdb entry to
 * arm the static-fdb decap path, blast a BUDGETED+JITTER (base 3) AF_PACKET
 * burst, then RTM_DELLINK the dev while the raw socket is still draining.
 *
 * Brick-safety: loopback only inside the private netns (peer 127.0.0.2),
 * one create/destroy per invocation, all I/O MSG_DONTWAIT, netlink ack
 * SO_RCVTIMEO=1s so an unresponsive rtnl can't wedge past child.c's SIGALRM.
 *
 * Latches: ns_unsupported_vxlan_encap master gate on userns_run_in_ns()
 * -EPERM.  shm->vxlan_encap_kind_unsupported[] per-kind (indexed by enum
 * tun_kind) on RTM_NEWLINK EAFNOSUPPORT / EOPNOTSUPP / ENOTSUP / ENOENT /
 * EPROTONOSUPPORT.  Per-kind latches live in shm because the rejection is
 * observed inside the grandchild -- a process-local static would die on
 * _exit and re-attempt the missing kind forever.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/neighbour.h"
#include "kernel/socket.h"
/* if_link.h on stripped sysroots may not have the full VXLAN/GENEVE/GRE
 * attribute enums.  Provide the minimal subset we actually emit: the
 * IDs are stable in the UAPI, so re-defining as a fallback is safe.
 * We test the canonical anchor for each family (IFLA_VXLAN_ID,
 * IFLA_GENEVE_ID, IFLA_GRE_LINK) and fall back wholesale if any one
 * of them is missing rather than per-symbol — keeps the gate simple. */
#ifndef IFLA_VXLAN_ID
#define IFLA_VXLAN_ID		1
#define IFLA_VXLAN_GROUP	2
#define IFLA_VXLAN_LINK		3
#define IFLA_VXLAN_LOCAL	4
#define IFLA_VXLAN_PORT		15
#endif

#ifndef IFLA_GENEVE_ID
#define IFLA_GENEVE_ID		1
#define IFLA_GENEVE_REMOTE	2
#endif

#ifndef IFLA_GRE_LINK
#define IFLA_GRE_LINK		1
#define IFLA_GRE_IKEY		3
#define IFLA_GRE_OKEY		4
#define IFLA_GRE_LOCAL		5
#define IFLA_GRE_REMOTE		6
#endif

#ifndef NDA_DST
#define NDA_DST			1
#define NDA_LLADDR		2
#endif

#ifndef NTF_SELF
#define NTF_SELF		(1 << 1)
#endif

/* Reasonable ceiling on a single rtnl message + payload.  vxlan link
 * create with all attributes set fits in well under 1 KiB; 2 KiB
 * leaves headroom for any future attribute additions. */
#define RTNL_BUF_BYTES		2048

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it: a
 * productive run grows to ~iter*4 sends, an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT so even an unlimited burst can't
 * stall the iteration past the inherited SIGALRM(1s) cap. */
#define VXLAN_PACKET_BASE	3U

/* VXLAN VNI is 24-bit; mask to that width so we never emit values the
 * kernel will reject as malformed.  GRE keys are 32-bit u32 and accept
 * any value, so they get the raw rand32(). */
#define VNI_MASK		0x00ffffffU

/* UDP destination port for sent test packets.  Loopback-only — the
 * value doesn't matter functionally; pinning it to a fixed
 * non-privileged port keeps any escaped packet trivially identifiable
 * in tcpdump traces during triage. */
#define INNER_DST_PORT		34567

/* Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (the grandchild's unshare(CLONE_NEWUSER) was
 * refused by a hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * MUST NOT touch the host's main routing / fdb / link tables, so the
 * op stays disabled for the remainder of this child's lifetime. */
static bool ns_unsupported_vxlan_encap;

/* Per-kind feature-absent gates live in shm
 * (shm->vxlan_encap_kind_unsupported[], indexed by enum tun_kind).
 * The write site is inside the userns_run_in_ns() grandchild --
 * a process-local static would die with the grandchild on _exit()
 * and the next invocation would re-attempt the same unsupported
 * kind every call.  Set when RTM_NEWLINK rejects the kind with
 * rtnl_link_ops-not-registered errno (absent module / CONFIG);
 * persists fleet-wide via shm so the unsupported attempt is paid
 * once per fleet rather than once per grandchild. */

/* Per-grandchild bookkeeping.  Inherited as false at grandchild fork
 * time (the persistent child never sets it -- the in-ns body runs
 * exclusively in transient grandchildren), set to true after the
 * grandchild's first rtnl_bring_lo_up() in its own fresh netns.  Dies
 * with the grandchild on _exit(), so each subsequent grandchild
 * correctly re-runs the bring-lo-up once in its own netns. */
static bool lo_brought_up;

/* Set once per persistent child after the best-effort modprobe burst
 * runs.  modprobe needs CAP_SYS_MODULE in init_user_ns, which the
 * grandchild does not hold, so the modprobes fire from the persistent
 * child before the userns hop. */
static bool modprobes_attempted;

enum tun_kind {
	TUN_VXLAN = 0,
	TUN_GRE,
	TUN_GENEVE,
	TUN_NR,
};

/* The shm latch array is sized and indexed by enum tun_kind, so the
 * enum values above must agree with VXLAN_ENCAP_NR_KINDS in shm.h.
 * If a future kind is added, both sides must move together. */
_Static_assert(TUN_NR == VXLAN_ENCAP_NR_KINDS,
	       "enum tun_kind must match shm->vxlan_encap_kind_unsupported[] size");

static const char *kind_name(enum tun_kind k)
{
	switch (k) {
	case TUN_VXLAN:		return "vxlan";
	case TUN_GRE:		return "gre";
	case TUN_GENEVE:	return "geneve";
	case TUN_NR:		break;
	}
	return "unknown";
}

static bool kind_unsupported(enum tun_kind k)
{
	return __atomic_load_n(&shm->vxlan_encap_kind_unsupported[k],
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(enum tun_kind k)
{
	__atomic_store_n(&shm->vxlan_encap_kind_unsupported[k], true,
			 __ATOMIC_RELAXED);
}

/*
 * Build & send RTM_NEWLINK creating a tunnel of the requested kind.
 * Local pinned to 127.0.0.1, remote to 127.0.0.2.  vni / keys are
 * randomised so each iteration hashes into a different hash-table
 * bucket on the kernel side.  Returns 0 on accept, negated errno on
 * rejection, -EIO on local failure.
 */
static int build_tunnel_link(struct nl_ctx *ctx, enum tun_kind kind,
			     const char *name, __u32 vni_or_key)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	__u32 local_addr;
	__u32 remote_addr;
	size_t off;
	size_t li_off, id_off;

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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND,
			  kind_name(kind));
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	local_addr  = htonl(0x7f000001U);	/* 127.0.0.1 */
	remote_addr = htonl(0x7f000002U);	/* 127.0.0.2 */

	switch (kind) {
	case TUN_VXLAN:
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_VXLAN_ID,
				  vni_or_key & VNI_MASK);
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_VXLAN_LOCAL,
			      &local_addr, sizeof(local_addr));
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_VXLAN_GROUP,
			      &remote_addr, sizeof(remote_addr));
		if (!off)
			return -EIO;
		/* IFLA_VXLAN_PORT is __be16; htons keeps it network-order
		 * regardless of the nla_put_u16 helper's host-order intent. */
		off = nla_put_u16(buf, off, sizeof(buf), IFLA_VXLAN_PORT,
				  htons(4789));
		if (!off)
			return -EIO;
		break;
	case TUN_GRE:
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_GRE_IKEY,
				  htonl(vni_or_key));
		if (!off)
			return -EIO;
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_GRE_OKEY,
				  htonl(vni_or_key));
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_GRE_LOCAL,
			      &local_addr, sizeof(local_addr));
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_GRE_REMOTE,
			      &remote_addr, sizeof(remote_addr));
		if (!off)
			return -EIO;
		break;
	case TUN_GENEVE:
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_GENEVE_ID,
				  vni_or_key & VNI_MASK);
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_GENEVE_REMOTE,
			      &remote_addr, sizeof(remote_addr));
		if (!off)
			return -EIO;
		break;
	case TUN_NR:
		return -EIO;
	}

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int build_setlink_up(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build & send RTM_NEWNEIGH NTF_SELF for the vxlan fdb.  Adds a
 * permanent entry mapping a random inner mac to peer remote
 * 127.0.0.2.  Drives vxlan_fdb_add and the static-fdb path that the
 * vxlan_remcsum UAF history hangs off.
 */
static int build_fdb_add(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[256];
	unsigned char mac[6];
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	__u32 dst;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ndm = (struct ndmsg *)NLMSG_DATA(nlh);
	ndm->ndm_family  = AF_BRIDGE;
	ndm->ndm_ifindex = ifindex;
	ndm->ndm_state   = NUD_PERMANENT;
	ndm->ndm_flags   = NTF_SELF;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ndm));

	/* Random unicast mac (clear the multicast bit, set locally-
	 * administered).  vxlan_fdb_add insists on a unicast lladdr for
	 * NTF_SELF entries so colliding with an actual host mac is not
	 * a concern inside the private netns. */
	generate_rand_bytes(mac, sizeof(mac));
	mac[0] = (unsigned char)((mac[0] & 0xfe) | 0x02);

	off = nla_put(buf, off, sizeof(buf), NDA_LLADDR, mac, sizeof(mac));
	if (!off)
		return -EIO;

	dst = htonl(0x7f000002U);	/* 127.0.0.2 — peer remote */
	off = nla_put(buf, off, sizeof(buf), NDA_DST, &dst, sizeof(dst));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Pick a starting kind that isn't latched off.  Returns TUN_NR if
 * every kind's latch is tripped — caller treats that as "all kinds
 * structurally unsupported, return cheaply".
 */
static enum tun_kind pick_kind(void)
{
	enum tun_kind start = (enum tun_kind)rnd_modulo_u32(TUN_NR);
	unsigned int i;

	for (i = 0; i < TUN_NR; i++) {
		enum tun_kind k = (enum tun_kind)((start + i) % TUN_NR);
		if (!kind_unsupported(k))
			return k;
	}
	return TUN_NR;
}

/*
 * Per-invocation state shared across the vxlan_encap_iter_* helpers.
 * Lives on the orchestrator's stack and is fresh per invocation.  Only
 * fields read or written across helper boundaries are lifted here; the
 * packet-burst scratch (sockaddr_ll, pkt buffer) stays on its helper's
 * stack.  The nl_opened / link_added gates and the raw / nl.fd / ifindex
 * fields collectively encode the partial-state cleanup that the
 * teardown helper has to thread back through.
 */
struct vxlan_encap_iter_ctx {
	struct nl_ctx	nl;
	char		ifname[IFNAMSIZ];
	enum tun_kind	kind;
	__u32		vni_or_key;
	int		ifindex;
	int		raw;		/* AF_PACKET fd, -1 until opened */
	bool		nl_opened;	/* rtnl socket is open */
	bool		link_added;	/* RTM_NEWLINK ack received */
	struct childdata *child;
};

/*
 * Open the rtnl socket and bring lo up inside the private netns.
 * Returns 0 on success and -1 on failure (with setup_failed bumped so
 * caller can bail without entering teardown — although teardown is also
 * safe to call on failure because it gates on ctx->nl_opened).  The
 * lo_brought_up latch is shared across invocations so the setlink only
 * fires the first time through.
 */
static int vxlan_encap_iter_open_ctx(struct vxlan_encap_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ctx->nl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.vxlan_encap_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->nl_opened = true;

	if (!lo_brought_up) {
		rtnl_bring_lo_up(&ctx->nl);
		lo_brought_up = true;
	}
	return 0;
}

/*
 * Build phase: generate a random ifname and vni-or-key, fire
 * RTM_NEWLINK to create the tunnel device, resolve its ifindex, and
 * (for vxlan) install a permanent NTF_SELF fdb entry plus bring the
 * device up.  Returns 0 if the burst phase should run, -1 on any
 * failure.  On the link-create rejection path, "rtnl_link_ops not
 * registered" errnos latch the kind off so subsequent invocations
 * skip it; other rejections leave the latch alone so the next
 * iteration retries with a fresh ifname.  Teardown stays safe to
 * call on -1 because it gates on ctx->link_added and ctx->ifindex.
 */
static int vxlan_encap_iter_build_link(struct vxlan_encap_iter_ctx *ctx)
{
	bool name_from_pool = false;
	int rc;

	/* Minority arm: seed ctx->ifname from a previously-recorded NETDEV
	 * pool entry (optionally mutated) instead of a fresh "trtun<rand>".
	 * A drawn name may collide with an in-use ifname (RTM_NEWLINK rejects
	 * EEXIST under NLM_F_EXCL) or carry a kernel-invalid byte (EINVAL);
	 * both are caught on the build_tunnel_link rc != 0 path and neither
	 * errno is in the rtnl_link_ops-not-registered latch set, so an
	 * unproductive draw costs at most one iteration and never latches the
	 * kind off.  Kept rare (ONE_IN(8)) so the dominant fresh-random arm
	 * keeps the create/up/burst/destroy chain warm. */
	if (ONE_IN(8)) {
		size_t got = name_pool_draw_mutated(NAME_KIND_NETDEV,
						    ctx->ifname,
						    sizeof(ctx->ifname));
		if (got > 0) {
			if (got >= sizeof(ctx->ifname))
				got = sizeof(ctx->ifname) - 1;
			ctx->ifname[got] = '\0';
			name_from_pool = true;
		}
	}
	if (!name_from_pool) {
		snprintf(ctx->ifname, sizeof(ctx->ifname), "trtun%u",
			 (unsigned int)(rand32() & 0xffffu));
	}
	ctx->vni_or_key = rand32();

	rc = build_tunnel_link(&ctx->nl, ctx->kind, ctx->ifname,
			       ctx->vni_or_key);
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -ENOENT || rc == -EPROTONOSUPPORT) {
			mark_kind_unsupported(ctx->kind);
			/* ctx->child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array, same pattern the
			 * child.c dispatch loop uses for the unguarded write
			 * that motivated this guard. */
			{
				const enum child_op_type op = ctx->child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		return -1;
	}
	ctx->link_added = true;
	__atomic_add_fetch(&shm->stats.vxlan_encap_churn.link_create_ok,
			   1, __ATOMIC_RELAXED);

	ctx->ifindex = (int)if_nametoindex(ctx->ifname);
	if (ctx->ifindex == 0)
		return -1;

	/* Kernel confirmed ctx->ifname now names a real device; publish it
	 * via the NETDEV name pool so sibling childops (and per-syscall
	 * fuzzers drawing this kind) can collide with it on subsequent
	 * invocations -- reaches "name a previous syscall planted" lookup
	 * codepaths instead of always-fresh-random near-miss space. */
	name_pool_record(NAME_KIND_NETDEV, ctx->ifname, strlen(ctx->ifname));

	if (ctx->kind == TUN_VXLAN) {
		if (build_fdb_add(&ctx->nl, ctx->ifindex) == 0)
			__atomic_add_fetch(&shm->stats.vxlan_encap_churn.fdb_add_ok,
					   1, __ATOMIC_RELAXED);
	}

	if (build_setlink_up(&ctx->nl, ctx->ifindex) == 0)
		__atomic_add_fetch(&shm->stats.vxlan_encap_churn.link_up_ok,
				   1, __ATOMIC_RELAXED);

	return 0;
}

/*
 * Burst phase: open an AF_PACKET SOCK_RAW socket, bind it to the
 * tunnel device's ifindex, then push BUDGETED+JITTER frames at it.
 * Each send drives one trip through the encap-tx path
 * (vxlan_xmit_one / geneve_xmit / ipgre_xmit, depending on kind);
 * the DELLINK in teardown races against in-flight sends from the
 * tail of this loop, which is the targeted teardown-vs-tx window.
 * All sends are MSG_DONTWAIT so the inherited SIGALRM(1s) cap is
 * never gated on socket-buffer backpressure.  The sockaddr_ll and
 * packet buffer stay on the helper's stack — they are not read
 * across helper boundaries, so they stay out of the iter ctx.
 */
static void vxlan_encap_iter_send_burst(struct vxlan_encap_iter_ctx *ctx)
{
	struct sockaddr_ll sll;
	unsigned int iters;
	unsigned int i;

	ctx->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			  htons(ETH_P_IP));
	if (ctx->raw < 0)
		return;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex  = ctx->ifindex;
	(void)bind(ctx->raw, (struct sockaddr *)&sll, sizeof(sll));

	iters = BUDGETED(CHILD_OP_VXLAN_ENCAP_CHURN,
			 JITTER_RANGE(VXLAN_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		unsigned char pkt[128];
		struct iphdr *iph;
		ssize_t n;
		size_t pkt_len;

		/* Random length in [40, sizeof(pkt)] so the encap path
		 * sees small / medium / fragmenting candidates instead of
		 * one fixed shape.  Minimum sized to fit the iphdr we
		 * stamp; maximum sized to fit the buffer. */
		pkt_len = 40U + rnd_modulo_u32((unsigned int)(sizeof(pkt) - 40U));

		memset(pkt, 0, sizeof(pkt));
		iph = (struct iphdr *)pkt;
		iph->version  = 4;
		iph->ihl      = 5;
		iph->tot_len  = htons((__u16)pkt_len);
		iph->ttl      = 64;
		iph->protocol = IPPROTO_UDP;
		iph->saddr    = htonl(0x7f000001U);
		iph->daddr    = htonl(0x7f000002U);

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_IP);
		sll.sll_ifindex  = ctx->ifindex;
		sll.sll_halen    = 6;

		n = sendto(ctx->raw, pkt, pkt_len, MSG_DONTWAIT,
			   (struct sockaddr *)&sll, sizeof(sll));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.vxlan_encap_churn.packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Teardown phase: close the AF_PACKET fd and tear down the tunnel
 * device + rtnl socket.  Each cleanup is gated independently
 * (ctx->raw >= 0, ctx->nl_opened, ctx->link_added && ctx->ifindex > 0)
 * so it is safe to call from any bail-out point in the orchestrator
 * — including the early returns above the call where ctx is fully
 * zero-initialised — without leaking the raw fd or sending a dellink
 * for an ifindex that was never resolved.  Netns destruction on child
 * exit catches anything we leave behind.
 */
static void vxlan_encap_iter_teardown(struct vxlan_encap_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);

	if (!ctx->nl_opened)
		return;

	if (ctx->link_added && ctx->ifindex > 0) {
		if (rtnl_dellink(&ctx->nl, ctx->ifindex) == 0)
			__atomic_add_fetch(&shm->stats.vxlan_encap_churn.link_del_ok,
					   1, __ATOMIC_RELAXED);
	}
	nl_close(&ctx->nl);
}

/*
 * Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot.
 */
struct vxlan_encap_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any tunnel
 * devs, fdb entries, raw sockets and packet buffers left behind are
 * reaped by the kernel along with the namespace.  Return value is
 * ignored by the helper.
 */
static int vxlan_encap_in_ns(void *arg)
{
	struct vxlan_encap_ctx *cctx = (struct vxlan_encap_ctx *)arg;
	struct childdata *child = cctx->child;
	struct vxlan_encap_iter_ctx ctx = {
		.nl = { .fd = -1 },
		.raw = -1,
		.child = child,
	};
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	ctx.kind = pick_kind();
	if (ctx.kind == TUN_NR)
		return 0;

	if (vxlan_encap_iter_open_ctx(&ctx) == 0 &&
	    vxlan_encap_iter_build_link(&ctx) == 0) {
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		vxlan_encap_iter_send_burst(&ctx);
	}

	vxlan_encap_iter_teardown(&ctx);
	return 0;
}

bool vxlan_encap_churn(struct childdata *child)
{
	struct vxlan_encap_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.vxlan_encap_churn.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_vxlan_encap)
		return true;

	if (!modprobes_attempted) {
		modprobes_attempted = true;
		try_modprobe("vxlan");
		try_modprobe("ip_gre");
		try_modprobe("geneve");
	}

	rc = userns_run_in_ns(CLONE_NEWNET, vxlan_encap_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_vxlan_encap = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, same pattern the child.c dispatch loop uses for the
		 * unguarded write that motivated this guard. */
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.vxlan_encap_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.vxlan_encap_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
