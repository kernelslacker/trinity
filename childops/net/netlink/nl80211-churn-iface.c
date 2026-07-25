/*
 * nl80211-churn-iface.c -- interface churn phase of nl80211_churn.
 *
 * Split from childops/net/netlink/nl80211-churn.c so the STATION iface
 * lifecycle (NEW_INTERFACE + DEL_INTERFACE) and the per-outer-iter
 * setup phase that wraps them build in parallel with the discovery,
 * scan/BSS, and station/key phases.  Pure code motion out of the
 * monolithic TU: no behavior change, no rename.
 *
 * Public entry points (declared in nl80211-churn-internal.h and
 * consumed by the top-level coordinator in nl80211-churn.c):
 *   - new_station_iface(): NL80211_CMD_NEW_INTERFACE + name lookup;
 *   - del_iface_by_index(): NL80211_CMD_DEL_INTERFACE by ifindex;
 *   - cleanup_ifaces(): end-of-child drain of the created-iface ring;
 *   - nl80211_iter_setup(): the per-outer-iter wall-cap gate + name
 *     pick + NEW_INTERFACE that anchors the rest of the phases.
 *
 * The created-iface ring (created_ifindex[] / created_count) is
 * appended to here on a successful nl80211_iter_setup(), cleared
 * slot-by-slot by the teardown phase back in nl80211-churn.c, and
 * drained tail-first at end of grandchild by cleanup_ifaces().
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <net/if.h>
#include <time.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "kernel/nl80211.h"

#include "childops-genl.h"
#include "childops-netlink.h"
#include "name-pool.h"
#include "nl80211-churn-internal.h"
#include "random.h"
#include "shm.h"

/*
 * Issue NL80211_CMD_NEW_INTERFACE iftype=NL80211_IFTYPE_STATION on
 * @phy.  On success returns the new ifindex (looked up by name, since
 * the kernel may or may not echo NL80211_ATTR_IFINDEX in the ack); on
 * failure returns the negated kernel errno or -EIO.
 */
int new_station_iface(struct genl_ctx *ctx, uint32_t phy,
		      const char *ifname)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	size_t off;
	int rc;
	int ifindex;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   NL80211_CMD_NEW_INTERFACE, 0);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), NL80211_ATTR_WIPHY, phy);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NL80211_ATTR_IFNAME, ifname);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	rc = genl_send_recv_retry(ctx, buf, off);
	if (rc != 0)
		return rc;

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex == 0)
		return -EIO;
	return ifindex;
}

int del_iface_by_index(struct genl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   NL80211_CMD_DEL_INTERFACE, 0);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv_retry(ctx, buf, off);
}

/*
 * Walk the per-child created-iface ring and issue a final
 * NL80211_CMD_DEL_INTERFACE for each.  Skips entries already torn down
 * inside the per-iter sequence (the entry has been zeroed).  Ring is
 * cleared on return.
 */
void cleanup_ifaces(struct genl_ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < created_count; i++) {
		int ifx = created_ifindex[i];

		if (ifx <= 0)
			continue;
		if (del_iface_by_index(ctx, ifx) == 0)
			__atomic_add_fetch(&shm->stats.nl80211.iface_destroyed,
					   1, __ATOMIC_RELAXED);
		created_ifindex[i] = 0;
	}
	created_count = 0;
}

/*
 * Phase: gate on the outer wall-clock budget, pick a fresh STATION ifname,
 * and create the iface via NEW_INTERFACE.  Returns 0 on success and fills
 * *ifindex / ifname; returns -1 when the wall cap is hit or NEW_INTERFACE
 * fails (caller bails -- the rest of the phases have nothing to anchor on).
 * Latches ns_unsupported_nl80211 on the kernel-doesn't-have-nl80211 errnos
 * so subsequent outer iters short-circuit cheaply.
 */
int nl80211_iter_setup(struct genl_ctx *ctx, char *ifname,
		       int *ifindex, const struct timespec *t_outer)
{
	int rc;

	if ((unsigned long long)ns_since(t_outer) >= NL80211_WALL_CAP_NS)
		return -1;

	(void)snprintf(ifname, IFNAMSIZ, "twl%u",
		       (unsigned int)(rand32() & 0xffffu));

	rc = new_station_iface(ctx, nl80211_phy0, ifname);
	if (rc < 0) {
		if (errno_is_unsupported(-rc))
			ns_unsupported_nl80211 = true;
		return -1;
	}
	*ifindex = rc;

	/* Kernel confirmed @ifname now names a real STATION iface; publish
	 * it via the NETDEV name pool so sibling childops (and per-syscall
	 * fuzzers drawing this kind) can reach "name a previous syscall
	 * planted" lookup codepaths instead of always-fresh-random near-miss
	 * space. */
	name_pool_record(NAME_KIND_NETDEV, ifname, strlen(ifname));

	__atomic_add_fetch(&shm->stats.nl80211.iface_created,
			   1, __ATOMIC_RELAXED);
	if (created_count < NL80211_IFACE_RING_CAP)
		created_ifindex[created_count++] = *ifindex;
	return 0;
}

#endif  /* __has_include gate */
