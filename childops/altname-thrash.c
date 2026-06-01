/*
 * altname_thrash - concurrent IFLA_ALT_IFNAME add/del under RTM_GETLINK
 * read pressure.
 *
 * The bug class this op exists to expose is a UAF in
 * rtnl_prop_list_size() and the broader prop-list walker family: an
 * altname property installed via RTM_NEWLINKPROP / IFLA_PROP_LIST is
 * exposed via list_for_each_entry_rcu() to readers (RTM_GETLINK with
 * IFLA_EXT_MASK=RTEXT_FILTER_VF walks the property list to compute
 * the dump size), and a racing RTM_DELLINKPROP can free the entry
 * before the reader's grace period elapses.  The default rtnetlink
 * fuzzer rolls a fresh single-attr message every call and never
 * builds a structured IFLA_PROP_LIST nest carrying multiple
 * IFLA_ALT_IFNAME entries against the same netdev, so the prop_list
 * walker's RCU lifetime simply isn't reached.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) once per child into a private net
 *      namespace.  Failure latches the whole op off.
 *   2. Open NETLINK_ROUTE.  Failure latches.
 *   3. RTM_NEWLINK type=dummy with a randomised dev name.  ENOPKG /
 *      EOPNOTSUPP latches the dummy gate (kernel without
 *      CONFIG_DUMMY).
 *   4. RTM_SETLINK IFF_UP on the dummy.
 *   5. Tight interleaved loop, BUDGETED+JITTER around base 5, floor
 *      16, cap 64, STORM_BUDGET_NS 200 ms wall:
 *        - add side: RTM_NEWLINKPROP carrying a nested IFLA_PROP_LIST
 *          with 1..ALT_BURST IFLA_ALT_IFNAME entries (each
 *          "alt_<rand6>", under the kernel's 15-byte altname cap).
 *        - del side: RTM_DELLINKPROP carrying the same shape with
 *          names drawn from the in-memory ring of recently-added
 *          altnames (or the just-added batch).
 *        - read side: RTM_GETLINK targeted at the dummy with
 *          IFLA_EXT_MASK = RTEXT_FILTER_VF set.  This is the read
 *          path that walks the property list under RCU.
 *      The three operations are emitted back-to-back per iteration so
 *      the kernel sees overlapping RCU read / writer grace periods.
 *   6. RTM_DELLINK to clean up the dummy.  netns destroy on child
 *      exit catches anything left behind.
 *
 * Self-bounding: one full create/destroy cycle per invocation.  Inner
 * loop BUDGETED+JITTER around base 5 with STORM_BUDGET_NS wall-clock
 * cap and a 64-iteration ceiling.  All netlink I/O is sync; the rtnl
 * socket has SO_RCVTIMEO=1s so an unresponsive kernel can't wedge us
 * past the SIGALRM(1s) cap inherited from child.c.  Single dummy in a
 * private netns; no other netdev kinds touched.
 */

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/*
 * UAPI fallbacks.  Stripped sysroots may predate the altname plumbing;
 * the IDs are stable in the kernel UAPI.
 */
#ifndef IFLA_PROP_LIST
#define IFLA_PROP_LIST		52
#endif
#ifndef IFLA_ALT_IFNAME
#define IFLA_ALT_IFNAME		53
#endif
#ifndef RTM_NEWLINKPROP
#define RTM_NEWLINKPROP		108
#endif
#ifndef RTM_DELLINKPROP
#define RTM_DELLINKPROP		109
#endif
#ifndef RTEXT_FILTER_VF
#define RTEXT_FILTER_VF		(1U << 0)
#endif

#define RTNL_BUF_BYTES		2048
#define RTNL_RECV_TIMEO_S	1

/* Per-iteration loop tuning.  BUDGETED+JITTER scales the base; the
 * floor/cap clamp the result, and STORM_BUDGET_NS provides a hard
 * wall-clock cap so even an unbounded burst can't stall past the
 * SIGALRM(1s) inherited from child.c. */
#define ALT_THRASH_BASE		5U
#define ALT_THRASH_FLOOR	16U
#define ALT_THRASH_CAP		64U
#define STORM_BUDGET_NS		200000000L	/* 200 ms */

/* Number of altnames per RTM_NEWLINKPROP / RTM_DELLINKPROP message.
 * Picked uniformly in [1, ALT_BURST] each iteration so the prop_list
 * walker sees both single-entry and multi-entry shapes. */
#define ALT_BURST		8U

/* Kernel cap on a single altname is ALTIFNAMSIZ (128 in modern
 * kernels), but the practical primary-name compatibility cap is
 * IFNAMSIZ-1 = 15.  Keep our names under 15 so any kernel old enough
 * to enforce the IFNAMSIZ cap still accepts them. */
#define ALT_NAME_MAX		15

/* Ring of recently-added altnames.  The del side draws from this so
 * delete messages reference names the kernel actually knows; using
 * fresh random names for the del would just bounce off the kernel's
 * lookup gate before reaching the prop_list walker.  Sized at
 * ALT_RING_SZ * ALT_NAME_MAX bytes — small constant. */
#define ALT_RING_SZ		32
static char alt_ring[ALT_RING_SZ][ALT_NAME_MAX + 1];
static unsigned int alt_ring_head;	/* next write slot */
static unsigned int alt_ring_count;	/* min(written, ALT_RING_SZ) */

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared. */
static bool ns_unsupported_altname_thrash;
static bool ns_unsupported_dummy_altname_thrash;
static bool ns_unshared_altname_thrash;
static bool ns_setup_failed_altname_thrash;

static int build_dummy_create(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo;
	size_t off, li_off;

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
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "dummy");
	if (!off)
		return -EIO;

	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

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
	nlh->nlmsg_type  = RTM_SETLINK;
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

static int build_dellink(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/* Generate one altname under the IFNAMSIZ-1 cap.  Format
 * "alt_XXXXXX" with XXXXXX hex-derived from rand32(); 10 bytes plus
 * NUL fits comfortably under 15. */
static void gen_altname(char *out)
{
	(void)snprintf(out, ALT_NAME_MAX + 1, "alt_%06x",
		       (unsigned int)(rand32() & 0xffffffu));
}

static void ring_push(const char name[ALT_NAME_MAX + 1])
{
	memcpy(alt_ring[alt_ring_head], name, ALT_NAME_MAX + 1);
	alt_ring_head = (alt_ring_head + 1) % ALT_RING_SZ;
	if (alt_ring_count < ALT_RING_SZ)
		alt_ring_count++;
}

/*
 * Build an RTM_NEWLINKPROP / RTM_DELLINKPROP carrying a nested
 * IFLA_PROP_LIST with `count` IFLA_ALT_IFNAME entries.  `names` is an
 * array of `count` NUL-terminated strings.
 */
static int build_linkprop(struct nl_ctx *ctx, __u16 msg_type, int ifindex,
			  const char (*names)[ALT_NAME_MAX + 1],
			  unsigned int count)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *plist;
	size_t off, plist_off;
	unsigned int i;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	plist_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_PROP_LIST | NLA_F_NESTED,
		      NULL, 0);
	if (!off)
		return -EIO;

	for (i = 0; i < count; i++) {
		off = nla_put_str(buf, off, sizeof(buf), IFLA_ALT_IFNAME,
				  names[i]);
		if (!off)
			return -EIO;
	}

	plist = (struct nlattr *)(buf + plist_off);
	plist->nla_len = (unsigned short)(off - plist_off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_GETLINK targeted at one ifindex with IFLA_EXT_MASK =
 * RTEXT_FILTER_VF.  This is the read path that walks the prop_list
 * under RCU to compute the dump size (rtnl_prop_list_size).  Uses
 * nl_send_recv_any() because the kernel responds with the RTM_NEWLINK
 * dump head, not an NLMSG_ERROR ack — nl_send_recv() would return
 * -EIO on that wire shape and silently kill the getlink_done stat.
 */
static int build_getlink(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_EXT_MASK,
			  RTEXT_FILTER_VF);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_any(ctx, buf, off);
}

static bool is_unsupported_err(int rc)
{
	return rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -ENOPKG;
}

/*
 * Per-invocation context shared across the altname_thrash phase
 * helpers.  Only state read or written across helper boundaries lives
 * here; the burst-local scratch arrays stay on the helper's stack.
 * File-local statics (alt_ring, the ns_* latches) are not lifted —
 * they're already visible to every helper.
 */
struct altname_iter_ctx {
	struct nl_ctx nl;
	char dummy_name[IFNAMSIZ];
	int dummy_idx;
	bool nl_opened;
	bool dummy_added;
};

/*
 * Setup phase: latch checks, lazy unshare(CLONE_NEWNET), open the
 * rtnetlink socket, create the dummy device, and bring it up.  Returns
 * 0 if the burst phase should run, -1 on any failure (with the
 * appropriate ns_*_altname_thrash latch raised so subsequent
 * invocations skip the failing subsystem).  On -1 the teardown helper
 * is still safe to call: it gates on ctx->nl_opened / ctx->dummy_added.
 */
static int altname_thrash_iter_setup(struct altname_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = RTNL_RECV_TIMEO_S,
	};
	int rc;

	if (!ns_unshared_altname_thrash) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed_altname_thrash = true;
			__atomic_add_fetch(&shm->stats.altname_thrash_unshare_failed,
					   1, __ATOMIC_RELAXED);
			return -1;
		}
		ns_unshared_altname_thrash = true;
	}

	if (nl_open(&ctx->nl, &opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			ns_unsupported_altname_thrash = true;
		return -1;
	}
	ctx->nl_opened = true;

	(void)snprintf(ctx->dummy_name, sizeof(ctx->dummy_name), "tralt%u",
		       (unsigned int)(rand32() & 0xffffu));

	rc = build_dummy_create(&ctx->nl, ctx->dummy_name);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_dummy_altname_thrash = true;
		return -1;
	}
	ctx->dummy_added = true;

	ctx->dummy_idx = (int)if_nametoindex(ctx->dummy_name);
	if (ctx->dummy_idx == 0)
		return -1;

	(void)build_setlink_up(&ctx->nl, ctx->dummy_idx);
	return 0;
}

/*
 * Burst phase: BUDGETED+JITTER iteration count, clamped by
 * ALT_THRASH_FLOOR/CAP, with a STORM_BUDGET_NS wall-clock cap so even
 * an unbounded burst can't outrun the SIGALRM(1s) inherited from
 * child.c.  Each iteration emits an add / get / del altname triplet so
 * the kernel sees overlapping RCU read and prop_list writer grace
 * periods.  The add/victim scratch arrays live on the helper's stack
 * — they are not read across helper boundaries, so they stay out of
 * struct altname_iter_ctx.
 */
static void altname_thrash_iter_burst(struct altname_iter_ctx *ctx)
{
	char added[ALT_BURST][ALT_NAME_MAX + 1];
	char victims[ALT_BURST][ALT_NAME_MAX + 1];
	struct timespec t0;
	unsigned int iters, i;

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_ALTNAME_THRASH,
			 JITTER_RANGE(ALT_THRASH_BASE));
	if (iters < ALT_THRASH_FLOOR)
		iters = ALT_THRASH_FLOOR;
	if (iters > ALT_THRASH_CAP)
		iters = ALT_THRASH_CAP;

	for (i = 0; i < iters; i++) {
		unsigned int batch, j, vbatch;

		if (ns_since(&t0) >= STORM_BUDGET_NS)
			break;

		batch = ((unsigned int)rand32() % ALT_BURST) + 1U;
		for (j = 0; j < batch; j++) {
			gen_altname(added[j]);
			ring_push(added[j]);
		}

		if (build_linkprop(&ctx->nl, RTM_NEWLINKPROP, ctx->dummy_idx,
				   (const char (*)[ALT_NAME_MAX + 1])added,
				   batch) == 0) {
			__atomic_add_fetch(&shm->stats.altname_thrash_addprop_done,
					   1, __ATOMIC_RELAXED);
		}

		if (build_getlink(&ctx->nl, ctx->dummy_idx) == 0) {
			__atomic_add_fetch(&shm->stats.altname_thrash_getlink_done,
					   1, __ATOMIC_RELAXED);
		}

		/* Pick victims for the del side from the ring of
		 * recently-added names.  This keeps the kernel-side
		 * lookup successful so the prop_list walker is actually
		 * reached; a fresh-random victim list would bounce off
		 * the lookup gate. */
		if (alt_ring_count == 0)
			continue;
		vbatch = ((unsigned int)rand32() % ALT_BURST) + 1U;
		if (vbatch > alt_ring_count)
			vbatch = alt_ring_count;
		for (j = 0; j < vbatch; j++) {
			unsigned int idx = (unsigned int)rand32() %
					   alt_ring_count;
			memcpy(victims[j], alt_ring[idx], ALT_NAME_MAX + 1);
		}

		if (build_linkprop(&ctx->nl, RTM_DELLINKPROP, ctx->dummy_idx,
				   (const char (*)[ALT_NAME_MAX + 1])victims,
				   vbatch) == 0) {
			__atomic_add_fetch(&shm->stats.altname_thrash_delprop_done,
					   1, __ATOMIC_RELAXED);
		}
	}
}

bool altname_thrash(struct childdata *child)
{
	struct altname_iter_ctx ctx = { .nl = { .fd = -1 } };

	(void)child;

	__atomic_add_fetch(&shm->stats.altname_thrash_invocations, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed_altname_thrash ||
	    ns_unsupported_altname_thrash ||
	    ns_unsupported_dummy_altname_thrash)
		return true;

	if (altname_thrash_iter_setup(&ctx) != 0)
		goto out;

	altname_thrash_iter_burst(&ctx);

out:
	if (ctx.nl_opened) {
		if (ctx.dummy_added && ctx.dummy_idx > 0)
			(void)build_dellink(&ctx.nl, ctx.dummy_idx);
		nl_close(&ctx.nl);
	}

	return true;
}
