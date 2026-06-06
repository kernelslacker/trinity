/*
 * nl80211_churn - cfg80211 state-machine churn under mac80211_hwsim.
 *
 * Random syscall fuzzing essentially never reaches the cfg80211 state-
 * machine asynchronous transitions in net/wireless/nl80211.c,
 * net/wireless/scan.c, and net/wireless/sme.c because those branches only
 * fire when:
 *
 *   - a wiphy backed by a software radio is registered (mac80211_hwsim
 *     provides phy0 with a synthetic IEEE 802.11 PHY that takes scan,
 *     connect, and regdom commands without any real radio);
 *   - an interface of type NL80211_IFTYPE_STATION is created on the wiphy
 *     via NL80211_CMD_NEW_INTERFACE;
 *   - the interface enters scan / connect state and the kernel walks
 *     cfg80211_inform_bss / cfg80211_update_notlisted_nontrans /
 *     cfg80211_scan_done / cfg80211_disconnect under the rdev wiphy_lock;
 *   - a second scan / regdom change / disconnect arrives while the
 *     previous async transition is still in flight.
 *
 * Per BUDGETED + JITTER iteration of the outer churn loop (200 ms wall
 * cap; SIGALRM(1s) inherited from child.c):
 *
 *   1. unshare CLONE_NEWNET (once per child).  Latches ns_unsupported_
 *      nl80211 on EPERM.
 *   2. genl_open("nl80211", ...) -- the shared childops-genl wrapper
 *      opens NETLINK_GENERIC, applies SO_RCVTIMEO, and resolves the
 *      nl80211 family id via CTRL_CMD_GETFAMILY.  -ENOENT latches the
 *      cap-gate (kernel doesn't expose nl80211).
 *   3. capability gate: confirm a mac80211_hwsim radio is reachable.
 *      Probe order: presence of /sys/class/mac80211_hwsim, best-effort
 *      modprobe (latched once per child), NL80211_CMD_GET_WIPHY enumerate
 *      with a 100 ms recv window.  Zero phys -> latch ns_unsupported_
 *      nl80211 and noop_forever for the rest of the child's life.
 *   4. NL80211_CMD_NEW_INTERFACE iftype=NL80211_IFTYPE_STATION on phy0
 *      with a per-iter random ifname.  Records the new ifindex for the
 *      scan / connect / disconnect / del-iface chain and for the cleanup
 *      sweep.
 *   5. NL80211_CMD_TRIGGER_SCAN active-scan with 1-3 random 32-byte
 *      SSIDs in NL80211_ATTR_SCAN_SSIDS.  This drives
 *      cfg80211_inform_bss / cfg80211_update_notlisted_nontrans on the
 *      synthetic mac80211_hwsim BSS table -- the OOB site of
 *      CVE-2022-41674 lives there.
 *   6. brief BUDGETED yield (poll on the netlink socket with a short
 *      timeout) for NL80211_CMD_NEW_SCAN_RESULTS.  Best-effort: the
 *      connect step below fires whether or not we observed completion.
 *   7. NL80211_CMD_CONNECT to one discovered BSSID (or a random SSID
 *      if no scan results were captured).  Drives the SME connect path
 *      that races scan_done.
 *   8. SO_BINDTODEVICE UDP burst (5..32 packets) to 224.0.0.1:9 via the
 *      wlan iface.  Loopback-class -- the netns has no real driver, so
 *      the packet is dropped after the bind/route lookup, but the
 *      bind/route lookup itself walks cfg80211 state for the iface.
 *   9. NL80211_CMD_TRIGGER_SCAN AGAIN -- scan-while-connected race
 *      target.  This is the cfg80211_scan_done UAF window
 *      (CVE-2025-21672): a second scan trigger arriving while the rdev
 *      is mid-connect lets two scan_done callbacks race.
 *  10. NL80211_CMD_REQ_SET_REG alpha2="ZZ" (regdom change).  The wiphy
 *      index race target (CVE-2023-3090): a regdom change racing an
 *      in-flight scan / connect / disconnect can land with the rdev's
 *      wiphy_idx mid-mutation.  Spec calls this NL80211_CMD_SET_REG;
 *      the upstream UAPI command for a userspace-initiated regdom
 *      request is NL80211_CMD_REQ_SET_REG (== 26) and is what the
 *      kernel accepts on NETLINK_GENERIC.
 *  11. NL80211_CMD_DISCONNECT -- races the previous scan completion
 *      and the in-flight regdom change.
 *  12. NL80211_CMD_DEL_INTERFACE -- iface tear-down racing whatever
 *      cfg80211 state-machine work is still draining.
 *
 * Cleanup: cleanup_ifaces() walks the per-child created-iface ring and
 * issues NL80211_CMD_DEL_INTERFACE for each entry.  netns destruction
 * catches anything the per-iter del missed.
 *
 * Brick-safety:
 *   - All wireless mutation lives inside a per-child CLONE_NEWNET; nothing
 *     touches the host's wiphy / regdom / iface state.
 *   - mac80211_hwsim provides a synthetic PHY -- no real radio is
 *     transmitted to and no spectrum is touched.
 *   - All netlink and socket I/O is MSG_DONTWAIT or short SO_RCVTIMEO; the
 *     SIGALRM(1s) cap inherited from child.c bounds anything we miss.
 *   - Per-kind / per-cap latches so a kernel without mac80211_hwsim or
 *     NL80211 pays the EFAIL once and skips the path for the rest of the
 *     child's life.
 *   - Bounded retries (<= 8) on EAGAIN / EBUSY / EINPROGRESS so a sibling
 *     iteration mid-teardown doesn't waste this iteration's config-plane
 *     work.  The shared childops-genl wrapper is single-ack-only by
 *     design; the retry wrapper sits local to this file (see
 *     genl_send_recv_retry).
 *
 * Migration note: the per-cmd builders all route through the shared
 * childops-genl helpers (genl_open / genl_close / genl_msg_put /
 * genl_send_recv) and the shared childops-netlink Type-A nla_put*
 * family.  Two paths intentionally stay local: genl_dump() (multi-
 * message reply walking, scoped out of the shared API by design per
 * include/childops-genl.h) and genl_send_recv_retry() (the
 * EINPROGRESS/EAGAIN/EBUSY retry loop -- nl80211 needs it, devlink and
 * tipc don't, so the shared wrapper stays unicast-single-ack).
 *
 * Header gates: __has_include(<linux/genetlink.h>) /
 * <linux/if_link.h> / <linux/rtnetlink.h>.  NL80211 UAPI integers
 * (NL80211_CMD_*, NL80211_ATTR_*, NL80211_IFTYPE_STATION) are
 * #define-fallback supplied at their stable UAPI integer values when
 * <linux/nl80211.h> is missing on the build host -- the kernel returns
 * -EOPNOTSUPP / -ENOPROTOOPT and the cap-gate latches.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#if __has_include(<linux/nl80211.h>)
#include <linux/nl80211.h>
#endif

#include "child.h"
#include "childops-genl.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/*
 * NL80211 UAPI fallbacks.  Values mirror include/uapi/linux/nl80211.h
 * (mainline since 2.6.x; per-command integers are stable -- documented
 * UAPI).  Supplied for stripped sysroots that omit <linux/nl80211.h>.
 * If a value drifts the kernel returns -EOPNOTSUPP / -EINVAL on the
 * relevant request and the cap-gate latches.
 */
#ifndef NL80211_GENL_NAME
#define NL80211_GENL_NAME		"nl80211"
#endif

#ifndef NL80211_CMD_GET_WIPHY
#define NL80211_CMD_GET_WIPHY		1
#endif
#ifndef NL80211_CMD_NEW_INTERFACE
#define NL80211_CMD_NEW_INTERFACE	7
#endif
#ifndef NL80211_CMD_DEL_INTERFACE
#define NL80211_CMD_DEL_INTERFACE	8
#endif
#ifndef NL80211_CMD_TRIGGER_SCAN
#define NL80211_CMD_TRIGGER_SCAN	33
#endif
#ifndef NL80211_CMD_NEW_SCAN_RESULTS
#define NL80211_CMD_NEW_SCAN_RESULTS	34
#endif
#ifndef NL80211_CMD_CONNECT
#define NL80211_CMD_CONNECT		46
#endif
#ifndef NL80211_CMD_DISCONNECT
#define NL80211_CMD_DISCONNECT		48
#endif
#ifndef NL80211_CMD_REQ_SET_REG
#define NL80211_CMD_REQ_SET_REG		26
#endif

#ifndef NL80211_ATTR_WIPHY
#define NL80211_ATTR_WIPHY		1
#endif
#ifndef NL80211_ATTR_IFINDEX
#define NL80211_ATTR_IFINDEX		3
#endif
#ifndef NL80211_ATTR_IFNAME
#define NL80211_ATTR_IFNAME		4
#endif
#ifndef NL80211_ATTR_IFTYPE
#define NL80211_ATTR_IFTYPE		5
#endif
#ifndef NL80211_ATTR_MAC
#define NL80211_ATTR_MAC		6
#endif
#ifndef NL80211_ATTR_REG_ALPHA2
#define NL80211_ATTR_REG_ALPHA2		33
#endif
#ifndef NL80211_ATTR_SCAN_SSIDS
#define NL80211_ATTR_SCAN_SSIDS		45
#endif
#ifndef NL80211_ATTR_SSID
#define NL80211_ATTR_SSID		52
#endif

#ifndef NL80211_IFTYPE_STATION
#define NL80211_IFTYPE_STATION		2
#endif

/*
 * NL80211 peer-measurement (PMSR) UAPI fallbacks.  Used to drive the
 * net/wireless/pmsr.c FTM request parser.  The FTMS_PER_BURST attribute
 * is the target field: upstream policy is NLA_U8 but the historical
 * getter used nla_get_u32(), so the parser silently consumed three
 * bytes past the policy-validated payload (broken on big-endian, see
 * commit 0f3c0a197309 -- "wifi: nl80211: fix
 * NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST usage").  Sending the attr
 * at both u8 and u32 widths exercises both the post-fix strict policy
 * (u32 form -> -EINVAL) and the pre-fix mis-sized read (u8 form
 * passes; u32 form pre-fix passes a getter that the policy then
 * tightens).
 */
#ifndef NL80211_CMD_PEER_MEASUREMENT_START
#define NL80211_CMD_PEER_MEASUREMENT_START	131
#endif
#ifndef NL80211_ATTR_PEER_MEASUREMENTS
#define NL80211_ATTR_PEER_MEASUREMENTS		273
#endif
#ifndef NL80211_PMSR_ATTR_PEERS
#define NL80211_PMSR_ATTR_PEERS			5
#endif
#ifndef NL80211_PMSR_TYPE_FTM
#define NL80211_PMSR_TYPE_FTM			1
#endif
#ifndef NL80211_PMSR_PEER_ATTR_ADDR
#define NL80211_PMSR_PEER_ATTR_ADDR		1
#endif
#ifndef NL80211_PMSR_PEER_ATTR_REQ
#define NL80211_PMSR_PEER_ATTR_REQ		3
#endif
#ifndef NL80211_PMSR_REQ_ATTR_DATA
#define NL80211_PMSR_REQ_ATTR_DATA		1
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_PREAMBLE
#define NL80211_PMSR_FTM_REQ_ATTR_PREAMBLE	2
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_NUM_BURSTS_EXP
#define NL80211_PMSR_FTM_REQ_ATTR_NUM_BURSTS_EXP	3
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_BURST_PERIOD
#define NL80211_PMSR_FTM_REQ_ATTR_BURST_PERIOD	4
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_BURST_DURATION
#define NL80211_PMSR_FTM_REQ_ATTR_BURST_DURATION	5
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST
#define NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST	6
#endif
#ifndef NL80211_PREAMBLE_DMG
#define NL80211_PREAMBLE_DMG			3
#endif

/*
 * NL80211 admin-gate probe UAPI fallbacks.  Used to confirm the
 * GENL_ADMIN_PERM flag is set on the genl_ops table entry for each
 * cmd id below.  Upstream commit 381cd547bc6e ("wifi: nl80211: gate
 * SET_PMK/DEL_PMK/SET_WIPHY_NETNS behind admin perm check") audited
 * the table and re-flagged the entries that had been missing the
 * flag; a regression that drops the flag again is silent unless
 * something probes from an unprivileged context.
 */
#ifndef NL80211_CMD_SET_WIPHY_NETNS
#define NL80211_CMD_SET_WIPHY_NETNS		78
#endif
#ifndef NL80211_CMD_SET_PMK
#define NL80211_CMD_SET_PMK			122
#endif
#ifndef NL80211_CMD_DEL_PMK
#define NL80211_CMD_DEL_PMK			123
#endif
#ifndef NL80211_ATTR_NETNS_FD
#define NL80211_ATTR_NETNS_FD			219
#endif
#ifndef NL80211_ATTR_PMK
#define NL80211_ATTR_PMK			254
#endif

/* Outer churn-loop budget knobs (per spec). */
#define NL80211_OUTER_BASE		5U
#define NL80211_OUTER_FLOOR		16U
#define NL80211_OUTER_CAP		64U
#define NL80211_WALL_CAP_NS		(200ULL * 1000ULL * 1000ULL)

/* Inner UDP burst (per spec): 5..32 packets per outer iter. */
#define NL80211_BURST_MIN		5U
#define NL80211_BURST_MAX		32U
#define NL80211_BURST_PORT		9	/* discard port */

/* Per-syscall recv window for the netlink ack drain.  100 ms is the
 * "brief BUDGETED yield" the spec calls for between TRIGGER_SCAN and
 * NEW_SCAN_RESULTS; the whole outer iter is wall-bounded by
 * NL80211_WALL_CAP_NS so nothing here can punch through SIGALRM(1s). */
#define NL80211_TIMEO_MS		100
#define NL80211_NL_RX_BUF		8192

/* Bounded retry on the netlink config plane: a sibling iteration mid-
 * teardown can briefly bounce an EAGAIN / EBUSY / EINPROGRESS that the
 * very next attempt clears.  Eight retries comfortably rides through
 * the longest such window observed in tc-qdisc-churn / nftables-churn.
 * The shared childops-genl genl_send_recv is unicast-single-ack only
 * by design (devlink and tipc don't need retry); the retry wrapper
 * stays in this file -- see genl_send_recv_retry below. */
#define NL80211_RETRY_MAX		8

/* Cap on per-child created-iface ring.  Each outer iter creates one
 * STATION iface and (best-effort) tears it down before the next.  Ring
 * exists only to catch the cleanup case where a NEW_INTERFACE landed but
 * the per-iter DEL_INTERFACE was skipped (jump-out / wall cap hit).
 * 64 == NL80211_OUTER_CAP, the worst case if every iter leaks. */
#define NL80211_IFACE_RING_CAP		NL80211_OUTER_CAP

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared -- kernel module / config /
 * netns capability is static for the child's lifetime. */
static bool ns_unsupported_nl80211;
static bool ns_unshared;
static bool ns_setup_failed;
static bool modprobe_tried_mac80211_hwsim;

/* Per-child scratch state.  Family id is resolved per-ctx by genl_open
 * now (was a cached static); only the first-wiphy lookup result needs
 * to survive across invocations so we don't pay the GET_WIPHY enumerate
 * every churn call. */
static uint32_t nl80211_phy0;
static bool nl80211_phy0_cached;

/* Created-iface ring for the cleanup sweep. */
static int created_ifindex[NL80211_IFACE_RING_CAP];
static unsigned int created_count;

static bool errno_is_unsupported(int e)
{
	return e == EPERM || e == ENOSYS || e == EOPNOTSUPP ||
	       e == ENOPROTOOPT || e == EAFNOSUPPORT ||
	       e == EPROTONOSUPPORT || e == ENODEV;
}

static bool errno_is_transient(int e)
{
	return e == EAGAIN || e == EBUSY || e == EINPROGRESS;
}

/*
 * Local wrapper around genl_send_recv() that retries up to
 * NL80211_RETRY_MAX times on EAGAIN/EBUSY/EINPROGRESS.  See the
 * comment on NL80211_RETRY_MAX -- the shared childops-genl wrapper is
 * intentionally unicast-single-ack only; the retry pattern is
 * nl80211-specific (a sibling iteration's mid-teardown briefly bounces
 * the config plane on EINPROGRESS, the very next attempt clears).
 */
static int genl_send_recv_retry(struct genl_ctx *ctx, void *msg, size_t len)
{
	int retries;

	for (retries = 0; retries < NL80211_RETRY_MAX; retries++) {
		int rc = genl_send_recv(ctx, msg, len);

		if (rc != 0 && errno_is_transient(-rc))
			continue;
		return rc;
	}
	return -EAGAIN;
}

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
static bool hwsim_present(struct genl_ctx *ctx)
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

/*
 * Issue NL80211_CMD_NEW_INTERFACE iftype=NL80211_IFTYPE_STATION on
 * @phy.  On success returns the new ifindex (looked up by name, since
 * the kernel may or may not echo NL80211_ATTR_IFINDEX in the ack); on
 * failure returns the negated kernel errno or -EIO.
 */
static int new_station_iface(struct genl_ctx *ctx, uint32_t phy,
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

static void random_bssid(unsigned char mac[6]);

/*
 * NL80211_CMD_PEER_MEASUREMENT_START with an FTM request that emits
 * NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST as either a 1-byte or
 * 4-byte payload, selected by @ftms_as_u32.  Drives
 * net/wireless/pmsr.c::nl80211_pmsr_parse_ftm_req() with both widths
 * so a future regression of the historical NLA_U32-policy /
 * nla_get_u32-getter mismatch (upstream commit 0f3c0a197309) is
 * caught: with the post-fix NLA_U8 policy the kernel must reject the
 * u32 form with -EINVAL, while the u8 form parses cleanly.  No
 * NL80211_CMD_PEER_MEASUREMENT_STOP teardown -- mac80211_hwsim has no
 * actual ranging responder, so the request fails synchronously
 * (typically -EOPNOTSUPP / -EINVAL / -ENOTCONN); kernel cleans up on
 * socket close.  Tolerates any errno.
 */
static int build_pmsr_ftm_req(struct genl_ctx *ctx, uint32_t ifindex,
			      bool ftms_as_u32)
{
	unsigned char buf[1024];
	struct nlmsghdr *nlh;
	size_t off;
	size_t pmsr_off, peers_off, peer1_off, req_off, type_ftm_off, ftm_off;
	unsigned char mac[6];
	uint32_t preamble = (uint32_t)(rand32() % 4U);	/* LEGACY..DMG */
	uint16_t burst_period = (uint16_t)(rand32() & 0xffffu);
	uint8_t num_bursts_exp = (uint8_t)(rand32() & 0xfu);
	uint8_t burst_duration = (uint8_t)(rand32() & 0xfu);

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   NL80211_CMD_PEER_MEASUREMENT_START, 0);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  NL80211_ATTR_IFINDEX, ifindex);
	if (!off)
		return -EIO;

	pmsr_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     NL80211_ATTR_PEER_MEASUREMENTS);
	if (!off)
		return -EIO;
	peers_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NL80211_PMSR_ATTR_PEERS);
	if (!off)
		return -EIO;
	/* Anonymous peer index 1; the kernel ignores the index itself
	 * (NL80211_PMSR_ATTR_PEERS is "indexed by" but the index is
	 * meaningless per the UAPI doc -- it's just a list). */
	peer1_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), 1);
	if (!off)
		return -EIO;

	random_bssid(mac);
	off = nla_put(buf, off, sizeof(buf), NL80211_PMSR_PEER_ATTR_ADDR,
		      mac, sizeof(mac));
	if (!off)
		return -EIO;

	req_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     NL80211_PMSR_PEER_ATTR_REQ);
	if (!off)
		return -EIO;
	type_ftm_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     NL80211_PMSR_REQ_ATTR_DATA);
	if (!off)
		return -EIO;
	ftm_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NL80211_PMSR_TYPE_FTM);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  NL80211_PMSR_FTM_REQ_ATTR_PREAMBLE, preamble);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf),
		      NL80211_PMSR_FTM_REQ_ATTR_BURST_PERIOD,
		      &burst_period, sizeof(burst_period));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf),
		      NL80211_PMSR_FTM_REQ_ATTR_NUM_BURSTS_EXP,
		      &num_bursts_exp, sizeof(num_bursts_exp));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf),
		      NL80211_PMSR_FTM_REQ_ATTR_BURST_DURATION,
		      &burst_duration, sizeof(burst_duration));
	if (!off)
		return -EIO;

	/* The bug-shape attribute.  Two paths:
	 *   - u32 form: 4-byte payload spanning the full u32 range.
	 *     Post-fix kernels reject this on the NLA_U8 strict
	 *     policy (-EINVAL).  Pre-fix kernels read it via
	 *     nla_get_u32() with no width check.
	 *   - u8 form: 1-byte payload 0..255.  Always policy-legal;
	 *     post-fix kernels parse it via nla_get_u8(); pre-fix
	 *     kernels read four bytes via nla_get_u32() and pick up
	 *     three garbage upper bytes from the next attribute /
	 *     padding (the visible symptom on big-endian). */
	if (ftms_as_u32) {
		uint32_t v = rand32();

		off = nla_put_u32(buf, off, sizeof(buf),
				  NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST, v);
		if (!off)
			return -EIO;
	} else {
		uint8_t v = (uint8_t)(rand32() & 0xffu);

		off = nla_put(buf, off, sizeof(buf),
			      NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST,
			      &v, sizeof(v));
		if (!off)
			return -EIO;
	}

	nla_nest_end(buf, ftm_off, off);
	nla_nest_end(buf, type_ftm_off, off);
	nla_nest_end(buf, req_off, off);
	nla_nest_end(buf, peer1_off, off);
	nla_nest_end(buf, peers_off, off);
	nla_nest_end(buf, pmsr_off, off);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv_retry(ctx, buf, off);
}

static int del_iface_by_index(struct genl_ctx *ctx, int ifindex)
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
 * Build the NL80211_ATTR_SCAN_SSIDS nested attribute payload: 1..3
 * 32-byte random SSIDs.  The kernel accepts the nested-attribute shape
 * "container of NL80211_ATTR_SSID(payload)" where the inner attribute
 * type field is the SSID position index (per the cfg80211 helpers in
 * net/wireless/scan.c).  Random 32-byte payloads exercise the SSID
 * length-validation path that CVE-2022-41674 lives near.
 */
static size_t build_scan_ssids(unsigned char *buf, size_t cap)
{
	unsigned int n = 1U + (rand32() % 3U);
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
static int trigger_scan(struct genl_ctx *ctx, int ifindex)
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
static bool wait_scan_results(struct genl_ctx *ctx)
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
 * Generate a random BSSID for NL80211_ATTR_MAC.  The locally-administered
 * bit (LSB of the first byte) is set and the multicast bit cleared so the
 * BSSID is locally-administered unicast -- matches the address space
 * mac80211_hwsim's synthetic BSS table inhabits.
 */
static void random_bssid(unsigned char mac[6])
{
	generate_rand_bytes(mac, 6);
	mac[0] = (mac[0] & 0xfe) | 0x02;
}

/*
 * NL80211_CMD_CONNECT to a random BSSID/SSID pair.  No security suite
 * (open BSS) -- the SME connect path runs identically for security
 * suites; the bug surface lives in cfg80211_connect_result /
 * cfg80211_disconnect, not in the per-suite key install path.
 */
static int connect_iface(struct genl_ctx *ctx, int ifindex)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	unsigned char ssid[32];
	unsigned char mac[6];
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   NL80211_CMD_CONNECT, 0);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
	if (!off)
		return -EIO;

	random_bssid(mac);
	off = nla_put(buf, off, sizeof(buf),
		      NL80211_ATTR_MAC, mac, sizeof(mac));
	if (!off)
		return -EIO;

	generate_rand_bytes(ssid, sizeof(ssid));
	off = nla_put(buf, off, sizeof(buf),
		      NL80211_ATTR_SSID, ssid, sizeof(ssid));
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv_retry(ctx, buf, off);
}

static int disconnect_iface(struct genl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   NL80211_CMD_DISCONNECT, 0);
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
 * NL80211_CMD_REQ_SET_REG alpha2="ZZ".  ZZ is the IANA-reserved "no
 * regulatory domain selected" alpha2 -- the kernel accepts it as a
 * userspace-initiated regdom request and triggers the reg_process_self_
 * managed_hint / regulatory_hint_user codepath.  This path is what the
 * CVE-2023-3090 wiphy-index race lives in.
 */
static int set_reg_zz(struct genl_ctx *ctx)
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

/*
 * Send the inner UDP burst over @ifname.  AF_INET / SOCK_DGRAM bound to
 * the wlan iface via SO_BINDTODEVICE; destination 224.0.0.1:9
 * (loopback-class multicast on the discard port).  Each send walks the
 * iface route lookup which threads through cfg80211 state for the
 * STATION iface.  Wall-bounded by NL80211_WALL_CAP_NS at the outer-
 * iter level so the burst can't punch through the SIGALRM cap.
 */
static void send_inner_burst(const char *ifname, const struct timespec *t_outer)
{
	int s;
	struct sockaddr_in dst;
	unsigned int n = NL80211_BURST_MIN +
			 (rand32() % (NL80211_BURST_MAX - NL80211_BURST_MIN + 1U));
	unsigned int i;

	s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return;
	(void)setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
			 ifname, (socklen_t)(strlen(ifname) + 1));

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(NL80211_BURST_PORT);
	dst.sin_addr.s_addr = htonl(0xE0000001U);	/* 224.0.0.1 */

	for (i = 0; i < n; i++) {
		unsigned char payload[64];
		ssize_t r;

		if ((unsigned long long)ns_since(t_outer) >= NL80211_WALL_CAP_NS)
			break;
		generate_rand_bytes(payload, sizeof(payload));
		r = sendto(s, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (r > 0)
			__atomic_add_fetch(&shm->stats.nl80211_bursts_sent,
					   1, __ATOMIC_RELAXED);
	}
	close(s);
}

/*
 * Walk the per-child created-iface ring and issue a final
 * NL80211_CMD_DEL_INTERFACE for each.  Skips entries already torn down
 * inside the per-iter sequence (the entry has been zeroed).  Ring is
 * cleared on return.
 */
static void cleanup_ifaces(struct genl_ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < created_count; i++) {
		int ifx = created_ifindex[i];

		if (ifx <= 0)
			continue;
		if (del_iface_by_index(ctx, ifx) == 0)
			__atomic_add_fetch(&shm->stats.nl80211_iface_destroyed,
					   1, __ATOMIC_RELAXED);
		created_ifindex[i] = 0;
	}
	created_count = 0;
}

/*
 * Admin-gate detector.  Forks; the child enters an unmapped
 * CLONE_NEWUSER (no uid mapping -> all init_user_ns capabilities are
 * dropped instantly), opens a fresh genl ctx of its own via genl_open
 * (re-resolves the family via CTRL_CMD_GETFAMILY in the cap-dropped
 * context -- still allowed since CTRL is unprivileged), and probes a
 * fixed catalogue of NL80211_CMD_* opcodes that must be admin-gated.
 * netlink_capable(skb, CAP_NET_ADMIN) is the only barrier reachable
 * from this context, so a missing GENL_ADMIN_PERM flag on the genl_ops
 * entry is the regression surface: a unprivileged caller would walk
 * straight into the handler, returning 0 / -EINVAL / etc. instead of
 * the expected -EPERM.  NEW_INTERFACE is included as a positive
 * control: it has been admin-gated since the UAPI was introduced, so
 * an EPERM from it confirms the cap drop took effect for this run.
 * Any non-EPERM response (including 0 success or a non-EPERM errno) is
 * bumped to the unexpected counter; the caller cannot distinguish
 * "kernel let us through" from "cmd unreachable for unrelated reasons"
 * without cross-checking the positive-control delta over many runs.
 *
 * No retry wrapper inside this probe: the admin-gate distinguishes
 * EPERM (expected) from anything else (regression-or-unrelated), and
 * the retry wrapper would hide a transient EBUSY behind the EAGAIN
 * after exhaustion -- which would mislabel as "unexpected".
 */
struct admin_gate_cmd_desc {
	uint8_t cmd;
	bool needs_mac_pmk;
	bool needs_netns_fd;
};

static const struct admin_gate_cmd_desc admin_gate_catalogue[] = {
	{ NL80211_CMD_SET_PMK,         true,  false },
	{ NL80211_CMD_DEL_PMK,         true,  false },
	{ NL80211_CMD_SET_WIPHY_NETNS, false, true  },
	{ NL80211_CMD_NEW_INTERFACE,   false, false },	/* positive control */
};

static void nl80211_admin_gate_probe(uint32_t wiphy_idx)
{
	pid_t pid;

	__atomic_add_fetch(&shm->stats.nl80211_admin_gate_runs,
			   1, __ATOMIC_RELAXED);

	pid = fork();
	if (pid < 0)
		return;

	if (pid == 0) {
		struct genl_ctx cctx;
		struct genl_open_opts opts;
		unsigned int i;

		if (unshare(CLONE_NEWUSER) != 0)
			_exit(0);

		memset(&opts, 0, sizeof(opts));
		opts.family_name  = NL80211_GENL_NAME;
		opts.version      = 1;
		opts.recv_timeo_s = 1;
		if (genl_open(&cctx, &opts) != 0)
			_exit(0);

		for (i = 0; i < sizeof(admin_gate_catalogue) /
				sizeof(admin_gate_catalogue[0]); i++) {
			const struct admin_gate_cmd_desc *d =
				&admin_gate_catalogue[i];
			unsigned char buf[512];
			unsigned char mac[6];
			unsigned char pmk[16];
			int netns_fd = -1;
			struct nlmsghdr *nlh;
			size_t off;
			int rc;

			off = genl_msg_put(buf, 0, sizeof(buf), &cctx,
					   nl_seq_next(&cctx.nl), d->cmd, 0);
			if (!off)
				continue;
			off = nla_put_u32(buf, off, sizeof(buf),
					  NL80211_ATTR_WIPHY, wiphy_idx);
			if (!off)
				continue;
			if (d->needs_mac_pmk) {
				random_bssid(mac);
				off = nla_put(buf, off, sizeof(buf),
					      NL80211_ATTR_MAC,
					      mac, sizeof(mac));
				if (!off)
					continue;
				generate_rand_bytes(pmk, sizeof(pmk));
				off = nla_put(buf, off, sizeof(buf),
					      NL80211_ATTR_PMK,
					      pmk, sizeof(pmk));
				if (!off)
					continue;
			}
			if (d->needs_netns_fd) {
				netns_fd = open("/proc/self/ns/net",
						O_RDONLY | O_CLOEXEC);
				if (netns_fd < 0)
					continue;
				off = nla_put_u32(buf, off, sizeof(buf),
						  NL80211_ATTR_NETNS_FD,
						  (uint32_t)netns_fd);
				if (!off) {
					close(netns_fd);
					continue;
				}
			}

			nlh = (struct nlmsghdr *)buf;
			nlh->nlmsg_len = (uint32_t)off;
			rc = genl_send_recv(&cctx, buf, off);

			if (netns_fd >= 0)
				close(netns_fd);

			if (rc == -EPERM)
				__atomic_add_fetch(&shm->stats.nl80211_admin_gate_eperm_ok,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.nl80211_admin_gate_unexpected,
						   1, __ATOMIC_RELAXED);
		}
		genl_close(&cctx);
		_exit(0);
	}

	(void)waitpid_eintr(pid, NULL, 0);
}

/*
 * Phase: gate on the outer wall-clock budget, pick a fresh STATION ifname,
 * and create the iface via NEW_INTERFACE.  Returns 0 on success and fills
 * *ifindex / ifname; returns -1 when the wall cap is hit or NEW_INTERFACE
 * fails (caller bails -- the rest of the phases have nothing to anchor on).
 * Latches ns_unsupported_nl80211 on the kernel-doesn't-have-nl80211 errnos
 * so subsequent outer iters short-circuit cheaply.
 */
static int nl80211_iter_setup(struct genl_ctx *ctx, char *ifname,
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
	__atomic_add_fetch(&shm->stats.nl80211_iface_created,
			   1, __ATOMIC_RELAXED);
	if (created_count < NL80211_IFACE_RING_CAP)
		created_ifindex[created_count++] = *ifindex;
	return 0;
}

/*
 * Phase: trigger the initial scan, drain its results, drive CONNECT, then
 * send the inner traffic burst that gives the scan/connect/assoc paths
 * something to chew on.  Pure side-effects via shm stats and the
 * ns_unsupported_nl80211 latch -- callers don't branch on the outcome.
 */
static void nl80211_iter_scan_connect(struct genl_ctx *ctx, int ifindex,
				      const char *ifname,
				      const struct timespec *t_outer)
{
	int rc;

	rc = trigger_scan(ctx, ifindex);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211_scan_triggered,
				   1, __ATOMIC_RELAXED);
	else if (errno_is_unsupported(-rc))
		ns_unsupported_nl80211 = true;

	(void)wait_scan_results(ctx);

	rc = connect_iface(ctx, ifindex);
	__atomic_add_fetch(&shm->stats.nl80211_connect_attempted,
			   1, __ATOMIC_RELAXED);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211_connect_succeeded,
				   1, __ATOMIC_RELAXED);
	else if (errno_is_unsupported(-rc))
		ns_unsupported_nl80211 = true;

	send_inner_burst(ifname, t_outer);
}

/*
 * Phase: post-connect race burst.  Re-triggers scan against the now-
 * connected iface (the cfg80211_scan_done UAF window, CVE-2025-21672) and
 * flips the regulatory domain to "ZZ" to race
 * reg_process_self_managed_hint (CVE-2023-3090 wiphy-index race).  Both
 * are best-effort -- the kernel-side races are the point, not the rc.
 */
static void nl80211_iter_races(struct genl_ctx *ctx, int ifindex)
{
	int rc;

	rc = trigger_scan(ctx, ifindex);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211_scan_triggered,
				   1, __ATOMIC_RELAXED);

	rc = set_reg_zz(ctx);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211_regdom_changed,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase: disconnect the iface, then run the two sub-modes guarded by their
 * own ONE_IN gates.  PMSR FTM (ONE_IN(8)) picks a random slot from the
 * created-iface ring and flips FTMS_PER_BURST between u8 and u32 widths
 * (upstream 0f3c0a197309).  Admin-gate probe (ONE_IN(16)) forks a child in
 * an unmapped user namespace to walk cmds that must be admin-gated
 * (upstream 381cd547bc6e); its lower rate budgets the fork+waitpid cost.
 */
static void nl80211_iter_submodes(struct genl_ctx *ctx, int ifindex)
{
	int rc;

	rc = disconnect_iface(ctx, ifindex);
	__atomic_add_fetch(&shm->stats.nl80211_disconnect_attempted,
			   1, __ATOMIC_RELAXED);
	(void)rc;

	if (ONE_IN(8) && created_count > 0) {
		bool as_u32 = ONE_IN(2);
		int slot = (int)(rand32() % created_count);
		int target = created_ifindex[slot];

		if (target > 0) {
			__atomic_add_fetch(&shm->stats.nl80211_pmsr_runs,
					   1, __ATOMIC_RELAXED);
			if (build_pmsr_ftm_req(ctx, (uint32_t)target,
					       as_u32) == 0)
				__atomic_add_fetch(&shm->stats.nl80211_pmsr_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	if (ONE_IN(16))
		nl80211_admin_gate_probe(nl80211_phy0);
}

/*
 * Phase: drive DEL_INTERFACE and reconcile the created-iface ring.  On a
 * successful delete, bumps the destroyed stat and clears the matching ring
 * slot so cleanup_ifaces() at child exit doesn't try to re-delete it.
 * Linear search is fine: the ring is bounded at NL80211_IFACE_RING_CAP
 * (64) and this runs once per outer iter, not per syscall.
 */
static void nl80211_iter_teardown(struct genl_ctx *ctx, int ifindex)
{
	int rc;

	rc = del_iface_by_index(ctx, ifindex);
	if (rc == 0) {
		unsigned int j;

		__atomic_add_fetch(&shm->stats.nl80211_iface_destroyed,
				   1, __ATOMIC_RELAXED);
		for (j = 0; j < created_count; j++) {
			if (created_ifindex[j] == ifindex) {
				created_ifindex[j] = 0;
				break;
			}
		}
	}
}

/*
 * Single outer iteration of the churn loop.  Each iter creates one
 * STATION iface, runs the full scan/connect/burst/scan-again/regdom/
 * disconnect/del-iface chain on it, and tears it down at the end.  The
 * created-iface ring catches the leak case where a NEW_INTERFACE landed
 * but the per-iter DEL_INTERFACE was skipped (jump-out / wall cap hit).
 */
static void iter_one(struct genl_ctx *ctx, unsigned int iter_idx,
		     const struct timespec *t_outer)
{
	char ifname[IFNAMSIZ];
	int ifindex;

	(void)iter_idx;

	if (nl80211_iter_setup(ctx, ifname, &ifindex, t_outer) < 0)
		return;

	nl80211_iter_scan_connect(ctx, ifindex, ifname, t_outer);
	nl80211_iter_races(ctx, ifindex);
	nl80211_iter_submodes(ctx, ifindex);
	nl80211_iter_teardown(ctx, ifindex);
}

bool nl80211_churn(struct childdata *child)
{
	struct genl_ctx ctx;
	struct genl_open_opts opts;
	bool ctx_open = false;
	struct timespec t_outer;
	unsigned int outer_iters, i;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.nl80211_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_nl80211)
		return true;

	if (ns_setup_failed) {
		__atomic_add_fetch(&shm->stats.nl80211_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			if (errno == EPERM)
				ns_unsupported_nl80211 = true;
			ns_setup_failed = true;
			__atomic_add_fetch(&shm->stats.nl80211_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
	}

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = NL80211_GENL_NAME;
	opts.version      = 1;
	/* SO_RCVTIMEO has 1 s granularity at the kernel API; the
	 * NL80211_TIMEO_MS (100 ms) brief-yield bound is enforced by the
	 * per-iter wall cap and the SIGALRM(1s) child cap, not by the
	 * socket timeout. */
	opts.recv_timeo_s = 1;

	rc = genl_open(&ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT || errno_is_unsupported(-rc))
			ns_unsupported_nl80211 = true;
		__atomic_add_fetch(&shm->stats.nl80211_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	ctx_open = true;

	if (!nl80211_phy0_cached) {
		if (!hwsim_present(&ctx)) {
			ns_unsupported_nl80211 = true;
			__atomic_add_fetch(&shm->stats.nl80211_setup_failed,
					   1, __ATOMIC_RELAXED);
			goto out;
		}
		nl80211_phy0_cached = true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec  = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_NL80211_CHURN,
			       JITTER_RANGE(NL80211_OUTER_BASE));
	if (outer_iters < NL80211_OUTER_FLOOR)
		outer_iters = NL80211_OUTER_FLOOR;
	if (outer_iters > NL80211_OUTER_CAP)
		outer_iters = NL80211_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >=
		    NL80211_WALL_CAP_NS)
			break;
		iter_one(&ctx, i, &t_outer);
		if (ns_unsupported_nl80211)
			break;
	}

	cleanup_ifaces(&ctx);

out:
	if (ctx_open)
		genl_close(&ctx);
	return true;
}

#else  /* missing one of <linux/genetlink.h> / <linux/if_link.h> / <linux/rtnetlink.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool nl80211_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.nl80211_runs, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.nl80211_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
