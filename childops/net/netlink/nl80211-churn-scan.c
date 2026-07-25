/*
 * nl80211-churn-scan.c -- scan/BSS churn phase of nl80211_churn.
 *
 * Split from childops/net/netlink/nl80211-churn.c so the SCAN + regdom
 * codepaths (NL80211_CMD_TRIGGER_SCAN + NEW_SCAN_RESULTS brief-yield +
 * REQ_SET_REG) build in parallel with the discovery, interface, and
 * station/key phases.  Pure code motion out of the monolithic TU: no
 * behavior change, no rename.
 *
 * Public entry points (declared in nl80211-churn-internal.h and
 * consumed by the top-level coordinator in nl80211-churn.c):
 *   - trigger_scan(): NL80211_CMD_TRIGGER_SCAN with 1..3 random SSIDs;
 *   - wait_scan_results(): brief poll+drain for NEW_SCAN_RESULTS;
 *   - set_reg_zz(): NL80211_CMD_REQ_SET_REG alpha2="ZZ" for the
 *     regdom-vs-in-flight wiphy_idx race (CVE-2023-3090).
 *
 * The set_reg_zz() helper conceptually straddles scan/BSS and regdom;
 * it lives here because the coordinator's post-connect race burst
 * (nl80211_iter_races) drives it in the same phase as the second
 * TRIGGER_SCAN, and the two share no other locality.  The SSID
 * builder is file-static because trigger_scan is the only in-tree
 * caller.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/netlink.h>

#include "kernel/nl80211.h"

#include "childops-genl.h"
#include "nl80211-churn-internal.h"
#include "random.h"

/*
 * Build the NL80211_ATTR_SCAN_SSIDS nested attribute payload: 1..3
 * 32-byte random SSIDs.  The kernel accepts the nested-attribute shape
 * "container of NL80211_ATTR_SSID(payload)" where the inner attribute
 * type field is the SSID position index (per the cfg80211 helpers in
 * net/wireless/scan.c).  Random 32-byte payloads exercise the SSID
 * length-validation path that CVE-2022-41674 lives near.
 */
static size_t build_scan_ssids(unsigned char *buf, size_t cap)
{
	unsigned int n = 1U + rnd_modulo_u32(3U);
	size_t off = 0;
	unsigned int i;

	for (i = 0; i < n; i++) {
		unsigned char ssid[32];
		size_t new_off;

		generate_rand_bytes(ssid, sizeof(ssid));
		new_off = nla_put(buf, off, cap,
				  (uint16_t)(i + 1), ssid, sizeof(ssid));
		if (!new_off)
			break;
		off = new_off;
	}
	return off;
}

/*
 * NL80211_CMD_TRIGGER_SCAN on @ifindex with 1-3 random 32-byte SSIDs.
 * Active scan is implied by the presence of NL80211_ATTR_SCAN_SSIDS.
 * Returns 0 on accept, the negated kernel errno on reject, -EIO on
 * local failure.
 */
int trigger_scan(struct genl_ctx *ctx, int ifindex)
{
	unsigned char buf[1536];
	unsigned char ssids_buf[512];
	struct nlmsghdr *nlh;
	size_t off, ssids_len;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   NL80211_CMD_TRIGGER_SCAN, 0);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	if (!off)
		return -EIO;

	ssids_len = build_scan_ssids(ssids_buf, sizeof(ssids_buf));
	if (ssids_len > 0) {
		off = nla_put(buf, off, sizeof(buf),
			      NL80211_ATTR_SCAN_SSIDS, ssids_buf, ssids_len);
		if (!off)
			return -EIO;
	}

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv_retry(ctx, buf, off);
}

/*
 * Brief BUDGETED yield for NL80211_CMD_NEW_SCAN_RESULTS.  poll() with
 * NL80211_TIMEO_MS so the SIGALRM(1s) cap is never threatened.
 * Best-effort: returning false simply means we proceed to CONNECT
 * without an observed scan completion (the kernel's scan-cache may
 * still have entries from prior iters).
 */
bool wait_scan_results(struct genl_ctx *ctx)
{
	struct pollfd pfd;

	pfd.fd     = ctx->nl.fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, NL80211_TIMEO_MS) > 0 && (pfd.revents & POLLIN)) {
		unsigned char buf[NL80211_NL_RX_BUF];
		ssize_t r = recv(ctx->nl.fd, buf, sizeof(buf), MSG_DONTWAIT);

		(void)r;
		return true;
	}
	return false;
}

/*
 * NL80211_CMD_REQ_SET_REG alpha2="ZZ".  ZZ is the IANA-reserved "no
 * regulatory domain selected" alpha2 -- the kernel accepts it as a
 * userspace-initiated regdom request and triggers the reg_process_self_
 * managed_hint / regulatory_hint_user codepath.  This path is what the
 * CVE-2023-3090 wiphy-index race lives in.
 */
int set_reg_zz(struct genl_ctx *ctx)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   NL80211_CMD_REQ_SET_REG, 0);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf),
		      NL80211_ATTR_REG_ALPHA2, "ZZ", 3);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv_retry(ctx, buf, off);
}

#endif  /* __has_include gate */
