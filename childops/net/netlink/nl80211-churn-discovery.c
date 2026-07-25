/*
 * nl80211-churn-discovery.c -- discovery/setup phase of nl80211_churn.
 *
 * Split from childops/net/netlink/nl80211-churn.c so the mac80211_hwsim
 * presence probe (sysfs stat + one-shot modprobe + NL80211_CMD_GET_WIPHY
 * enumerate) can build in parallel with the interface, scan/BSS, and
 * station/key phases.  Pure code motion out of the monolithic TU: no
 * behavior change, no rename.
 *
 * The one public entry point is hwsim_present(), declared in
 * nl80211-churn-internal.h and consumed by the top-level coordinator
 * in nl80211-churn.c (nl80211_churn_in_ns) exactly once per fresh
 * grandchild netns before the first churn iter.  The success path
 * caches the first-wiphy index in the cross-TU nl80211_phy0 slot
 * declared in the internal header.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "kernel/nl80211.h"

#include "childops-genl.h"
#include "childops-util.h"
#include "nl80211-churn-internal.h"

/* Modprobe latch for mac80211_hwsim.  Inherited as false at grandchild
 * fork time and flipped on the first hwsim_present() invocation that
 * finds the sysfs class absent, so a subsequent stat miss inside the
 * same grandchild skips the module-load retry.  Dies with the
 * grandchild on _exit(); each subsequent grandchild rediscovers.  Not
 * cross-TU state -- kept file-static in the only TU that ever reads
 * or writes it. */
static bool modprobe_tried_mac80211_hwsim;

/*
 * Send a genl request and drain a sequence of responses until a
 * NLMSG_DONE/NLMSG_ERROR terminator (or the recv buffer is exhausted).
 * Stays local because the shared childops-genl wrapper is intentionally
 * unicast-single-ack only -- per its docstring, "genl_dump in
 * nl80211-churn.c stays local".  The one in-file caller is the
 * NL80211_CMD_GET_WIPHY enumerate during hwsim_present(); no other
 * nl80211 cmd path needs a dump.
 *
 * Hand-rolls the nlmsghdr / genlmsghdr so it can set NLM_F_DUMP without
 * the wrapper's implicit NLM_F_ACK (the kernel emits a trailing ACK
 * after the dump completes, which the drain below isn't structured to
 * absorb -- leaving it queued would corrupt the next send_recv).
 */
static ssize_t genl_dump(struct genl_ctx *ctx, uint8_t cmd,
			 const unsigned char *attrs, size_t attrs_len,
			 unsigned char *resp, size_t resp_cap)
{
	unsigned char buf[2048];
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnh;
	struct sockaddr_nl sa;
	ssize_t rx;
	size_t total;
	size_t written = 0;
	int loops;

	if (attrs_len > sizeof(buf) - NLMSG_HDRLEN - GENL_HDRLEN)
		return -EIO;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);
	nlh = (struct nlmsghdr *)buf;
	gnh = (struct genlmsghdr *)NLMSG_DATA(nlh);

	total = NLMSG_HDRLEN + GENL_HDRLEN + attrs_len;
	nlh->nlmsg_len   = (uint32_t)total;
	nlh->nlmsg_type  = ctx->family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(&ctx->nl);
	nlh->nlmsg_pid   = 0;
	gnh->cmd     = cmd;
	gnh->version = ctx->version;
	if (attrs_len)
		memcpy((unsigned char *)gnh + GENL_HDRLEN, attrs, attrs_len);

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(ctx->nl.fd, buf, total, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -EIO;

	/* Bound the dump drain at 32 reads -- the controller is the only
	 * caller in this file that uses a dump and only ever returns a
	 * handful of entries on a synthetic hwsim setup. */
	for (loops = 0; loops < 32; loops++) {
		struct nlmsghdr *r;

		if (resp_cap - written < NLMSG_HDRLEN)
			break;
		rx = recv(ctx->nl.fd, resp + written, resp_cap - written, 0);
		if (rx < 0)
			break;
		if ((size_t)rx < NLMSG_HDRLEN)
			break;
		r = (struct nlmsghdr *)(resp + written);
		written += (size_t)rx;
		if (r->nlmsg_type == NLMSG_DONE ||
		    r->nlmsg_type == NLMSG_ERROR)
			break;
	}
	return (ssize_t)written;
}

/*
 * NL80211_CMD_GET_WIPHY enumerate.  Walks the dump payload and counts
 * wiphys; returns the count and writes the first wiphy index seen to
 * @first_phy on success.  A zero count after a successful dump is the
 * "hwsim absent" signal -- the caller latches ns_unsupported_nl80211.
 */
static int enumerate_wiphys(struct genl_ctx *ctx, uint32_t *first_phy)
{
	unsigned char resp[NL80211_NL_RX_BUF];
	ssize_t got;
	size_t consumed;
	int count = 0;

	got = genl_dump(ctx, NL80211_CMD_GET_WIPHY, NULL, 0,
			resp, sizeof(resp));
	if (got < 0)
		return -EIO;

	consumed = 0;
	while (consumed + NLMSG_HDRLEN <= (size_t)got) {
		struct nlmsghdr *r = (struct nlmsghdr *)(resp + consumed);
		size_t mlen;

		if (r->nlmsg_len < NLMSG_HDRLEN)
			break;
		mlen = NLMSG_ALIGN(r->nlmsg_len);
		if (consumed + mlen > (size_t)got)
			break;

		if (r->nlmsg_type == NLMSG_DONE ||
		    r->nlmsg_type == NLMSG_ERROR) {
			break;
		}
		if (r->nlmsg_type == ctx->family_id &&
		    r->nlmsg_len >= NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN) {
			struct genlmsghdr *g =
				(struct genlmsghdr *)NLMSG_DATA(r);
			unsigned char *p = (unsigned char *)g + GENL_HDRLEN;
			size_t left = r->nlmsg_len - NLMSG_HDRLEN -
				      GENL_HDRLEN;

			while (left >= NLA_HDRLEN) {
				struct nlattr nla;
				size_t alen;

				memcpy(&nla, p, sizeof(nla));
				if (nla.nla_len < NLA_HDRLEN ||
				    nla.nla_len > left)
					break;
				alen = NLA_ALIGN(nla.nla_len);
				if (nla.nla_type == NL80211_ATTR_WIPHY &&
				    nla.nla_len >= NLA_HDRLEN +
						   sizeof(uint32_t)) {
					uint32_t idx;

					memcpy(&idx, p + NLA_HDRLEN,
					       sizeof(idx));
					if (count == 0 && first_phy)
						*first_phy = idx;
					count++;
				}
				if (alen > left)
					break;
				p += alen;
				left -= alen;
			}
		}
		consumed += mlen;
	}
	return count;
}

/*
 * Capability gate: presence check for mac80211_hwsim.  Sequence:
 *   - /sys/class/mac80211_hwsim must exist and be a directory.  If not,
 *     fire modprobe (latched once per child) and re-check.
 *   - NL80211_CMD_GET_WIPHY enumerate must report >= 1 phy after the
 *     module has had a chance to register.
 * Return true iff a real hwsim radio is reachable; false sets
 * ns_unsupported_nl80211 on the caller side.
 */
bool hwsim_present(struct genl_ctx *ctx)
{
	struct stat st;
	uint32_t phy = 0;
	int wcount;

	if (stat("/sys/class/mac80211_hwsim", &st) < 0 ||
	    !S_ISDIR(st.st_mode)) {
		if (!modprobe_tried_mac80211_hwsim) {
			modprobe_tried_mac80211_hwsim = true;
			try_modprobe("mac80211_hwsim");
		}
		if (stat("/sys/class/mac80211_hwsim", &st) < 0 ||
		    !S_ISDIR(st.st_mode)) {
			/* sysfs class still absent -- fall through to the
			 * GET_WIPHY enumerate below; some kernels register
			 * hwsim without the class node. */
		}
	}

	wcount = enumerate_wiphys(ctx, &phy);
	if (wcount <= 0)
		return false;

	nl80211_phy0 = phy;
	return true;
}

#endif  /* __has_include gate */
