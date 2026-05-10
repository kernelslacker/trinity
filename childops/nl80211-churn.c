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
 *   2. open AF_NETLINK socket NETLINK_GENERIC; resolve nl80211 family
 *      via CTRL_CMD_GETFAMILY.  Failure latches the cap-gate.
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
 *     work.
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
#include <sys/time.h>
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
 * the longest such window observed in tc-qdisc-churn / nftables-churn. */
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

/* Per-child scratch state. */
static uint16_t nl80211_family;		/* dynamic genl family id */
static uint32_t nl80211_phy0;		/* first wiphy index seen */
static bool nl80211_family_resolved;	/* family + phy0 cached */

/* Created-iface ring for the cleanup sweep. */
static int created_ifindex[NL80211_IFACE_RING_CAP];
static unsigned int created_count;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

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

/* Append a netlink attribute to @buf at offset *off, padding to
 * NLA_ALIGNTO.  Returns false on overflow. */
static bool nla_put(unsigned char *buf, size_t cap, size_t *off,
		    uint16_t type, const void *data, uint16_t len)
{
	struct nlattr nla;
	size_t pad_len = NLA_ALIGN(len);
	size_t need = NLA_HDRLEN + pad_len;

	if (*off + need > cap)
		return false;
	nla.nla_type = type;
	nla.nla_len  = (uint16_t)(NLA_HDRLEN + len);
	memcpy(buf + *off, &nla, sizeof(nla));
	if (len)
		memcpy(buf + *off + NLA_HDRLEN, data, len);
	if (pad_len > len)
		memset(buf + *off + NLA_HDRLEN + len, 0, pad_len - len);
	*off += need;
	return true;
}

static bool nla_put_str(unsigned char *buf, size_t cap, size_t *off,
			uint16_t type, const char *s)
{
	return nla_put(buf, cap, off, type, s, (uint16_t)(strlen(s) + 1));
}

static bool nla_put_u32(unsigned char *buf, size_t cap, size_t *off,
			uint16_t type, uint32_t v)
{
	return nla_put(buf, cap, off, type, &v, sizeof(v));
}

/*
 * Send a genetlink request and read one response (best-effort).
 * Returns 0 on success, the negated kernel errno on a NLMSG_ERROR
 * rejection, or -EIO on local sendto/recv failure.  Response is written
 * to @resp / *@resp_len when a payload comes back.  Bounded retry on
 * transient errors so a sibling iteration mid-teardown doesn't waste
 * this iteration's config-plane work.
 */
static int genl_send_recv(int nlfd, uint16_t family, uint8_t cmd,
			  uint8_t version, const unsigned char *attrs,
			  size_t attrs_len, unsigned char *resp,
			  size_t resp_cap, size_t *resp_len)
{
	unsigned char buf[2048];
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnh;
	struct sockaddr_nl sa;
	ssize_t rx;
	size_t total;
	int retries;

	if (attrs_len > sizeof(buf) - NLMSG_HDRLEN - GENL_HDRLEN)
		return -EIO;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	gnh = (struct genlmsghdr *)NLMSG_DATA(nlh);

	total = NLMSG_HDRLEN + GENL_HDRLEN + attrs_len;
	nlh->nlmsg_len   = (uint32_t)total;
	nlh->nlmsg_type  = family;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	nlh->nlmsg_pid   = 0;
	gnh->cmd     = cmd;
	gnh->version = version;
	if (attrs_len)
		memcpy((unsigned char *)gnh + GENL_HDRLEN, attrs, attrs_len);

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	for (retries = 0; retries < NL80211_RETRY_MAX; retries++) {
		if (sendto(nlfd, buf, total, 0,
			   (struct sockaddr *)&sa, sizeof(sa)) < 0)
			return -EIO;

		rx = recv(nlfd, resp, resp_cap, 0);
		if (rx < 0)
			return -EIO;

		*resp_len = (size_t)rx;
		if ((size_t)rx >= NLMSG_HDRLEN) {
			struct nlmsghdr *r = (struct nlmsghdr *)resp;

			if (r->nlmsg_type == NLMSG_ERROR &&
			    (size_t)rx >= NLMSG_HDRLEN + sizeof(struct nlmsgerr)) {
				struct nlmsgerr *e =
					(struct nlmsgerr *)NLMSG_DATA(r);
				int err = e->error;

				if (err == 0)
					return 0;
				if (errno_is_transient(-err))
					continue;
				return err;
			}
		}
		return 0;
	}
	return -EAGAIN;
}

/* Send a genetlink request and dump a sequence of responses until a
 * NLMSG_DONE / NLMSG_ERROR terminator (or the recv buffer is exhausted).
 * Drains into @resp; returns the bytes written.  -EIO on local failure. */
static ssize_t genl_dump(int nlfd, uint16_t family, uint8_t cmd,
			 uint8_t version, const unsigned char *attrs,
			 size_t attrs_len, unsigned char *resp, size_t resp_cap)
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

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	gnh = (struct genlmsghdr *)NLMSG_DATA(nlh);

	total = NLMSG_HDRLEN + GENL_HDRLEN + attrs_len;
	nlh->nlmsg_len   = (uint32_t)total;
	nlh->nlmsg_type  = family;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = next_seq();
	nlh->nlmsg_pid   = 0;
	gnh->cmd     = cmd;
	gnh->version = version;
	if (attrs_len)
		memcpy((unsigned char *)gnh + GENL_HDRLEN, attrs, attrs_len);

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(nlfd, buf, total, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -EIO;

	/* Bound the dump drain at 32 reads -- the controller is the only
	 * caller in this file that uses a dump and only ever returns a
	 * handful of entries on a synthetic hwsim setup. */
	for (loops = 0; loops < 32; loops++) {
		struct nlmsghdr *r;

		if (resp_cap - written < NLMSG_HDRLEN)
			break;
		rx = recv(nlfd, resp + written, resp_cap - written, 0);
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
 * Resolve the dynamic genetlink family id for "nl80211" via
 * CTRL_CMD_GETFAMILY.  Returns 0 on success and writes the id to @out.
 * Negative return means the controller didn't know the family or the
 * netlink layer rejected the request -- caller latches the cap-gate.
 */
static int resolve_nl80211_family(int nlfd, uint16_t *out)
{
	unsigned char attrs[64];
	unsigned char resp[NL80211_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;
	int rc;
	struct nlmsghdr *r;
	struct genlmsghdr *g;
	unsigned char *p;
	size_t remaining;

	if (!nla_put_str(attrs, sizeof(attrs), &off,
			 CTRL_ATTR_FAMILY_NAME, NL80211_GENL_NAME))
		return -EIO;

	rc = genl_send_recv(nlfd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1,
			    attrs, off, resp, sizeof(resp), &resp_len);
	if (rc != 0)
		return rc;

	if (resp_len < NLMSG_HDRLEN + GENL_HDRLEN)
		return -EIO;
	r = (struct nlmsghdr *)resp;
	if (r->nlmsg_type == NLMSG_ERROR)
		return -EIO;

	g = (struct genlmsghdr *)NLMSG_DATA(r);
	p = (unsigned char *)g + GENL_HDRLEN;
	remaining = resp_len - NLMSG_HDRLEN - GENL_HDRLEN;

	while (remaining >= NLA_HDRLEN) {
		struct nlattr nla;
		size_t alen;

		memcpy(&nla, p, sizeof(nla));
		if (nla.nla_len < NLA_HDRLEN || nla.nla_len > remaining)
			break;
		alen = NLA_ALIGN(nla.nla_len);
		if (nla.nla_type == CTRL_ATTR_FAMILY_ID &&
		    nla.nla_len >= NLA_HDRLEN + sizeof(uint16_t)) {
			uint16_t id;

			memcpy(&id, p + NLA_HDRLEN, sizeof(id));
			*out = id;
			return 0;
		}
		if (alen > remaining)
			break;
		p += alen;
		remaining -= alen;
	}
	return -EIO;
}

/*
 * NL80211_CMD_GET_WIPHY enumerate.  Walks the dump payload and counts
 * wiphys; returns the count and writes the first wiphy index seen to
 * @first_phy on success.  A zero count after a successful dump is the
 * "hwsim absent" signal -- the caller latches ns_unsupported_nl80211.
 */
static int enumerate_wiphys(int nlfd, uint32_t *first_phy)
{
	unsigned char resp[NL80211_NL_RX_BUF];
	ssize_t got;
	size_t consumed;
	int count = 0;

	got = genl_dump(nlfd, nl80211_family, NL80211_CMD_GET_WIPHY, 1,
			NULL, 0, resp, sizeof(resp));
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
		if (r->nlmsg_type == nl80211_family &&
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
 * Best-effort modprobe.  fork+execvp; child redirects stdio to /dev/null
 * so module-load chatter doesn't pollute trinity output.  Ignore the
 * exit status -- modprobe failures (no module, no permission, no
 * /sbin/modprobe, lockdown=integrity) are exactly the cases the hwsim
 * probe will catch on the wiphy enumerate immediately after.
 */
static void try_modprobe(const char *mod)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);

		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execlp("modprobe", "modprobe", "-q", mod, (char *)NULL);
		_exit(127);
	}
	(void)waitpid(pid, &status, 0);
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
static bool hwsim_present(int nlfd)
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

	wcount = enumerate_wiphys(nlfd, &phy);
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
static int new_station_iface(int nlfd, uint32_t phy, const char *ifname)
{
	unsigned char attrs[256];
	unsigned char resp[NL80211_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;
	int rc;
	int ifindex;

	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 NL80211_ATTR_WIPHY, phy))
		return -EIO;
	if (!nla_put_str(attrs, sizeof(attrs), &off,
			 NL80211_ATTR_IFNAME, ifname))
		return -EIO;
	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION))
		return -EIO;

	rc = genl_send_recv(nlfd, nl80211_family,
			    NL80211_CMD_NEW_INTERFACE, 1,
			    attrs, off, resp, sizeof(resp), &resp_len);
	if (rc != 0)
		return rc;

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex == 0)
		return -EIO;
	return ifindex;
}

static void random_bssid(unsigned char mac[6]);

/*
 * Open a nested netlink attribute container at the current write
 * cursor.  Reserves NLA_HDRLEN bytes for the header; the actual nla_len
 * is patched in by nla_nest_end() once all child attributes have been
 * appended.  Returns false on overflow.
 */
struct nla_nest {
	size_t header_off;
};

static bool nla_nest_start(unsigned char *buf, size_t cap, size_t *off,
			   uint16_t type, struct nla_nest *n)
{
	struct nlattr nla;

	if (*off + NLA_HDRLEN > cap)
		return false;
	n->header_off = *off;
	nla.nla_type = type;
	nla.nla_len  = 0;
	memcpy(buf + *off, &nla, sizeof(nla));
	*off += NLA_HDRLEN;
	return true;
}

/*
 * Close a nested attribute opened by nla_nest_start().  Writes the
 * unpadded nla_len field at the recorded header offset and pads the
 * write cursor up to NLA_ALIGNTO so the next sibling starts on a
 * 4-byte boundary.  Returns false on overflow / 64K oversize.
 */
static bool nla_nest_end(unsigned char *buf, size_t cap, size_t *off,
			 const struct nla_nest *n)
{
	size_t len = *off - n->header_off;
	size_t pad;
	struct nlattr *nla;

	if (len > UINT16_MAX)
		return false;
	pad = NLA_ALIGN(len) - len;
	if (*off + pad > cap)
		return false;
	if (pad)
		memset(buf + *off, 0, pad);
	*off += pad;
	nla = (struct nlattr *)(buf + n->header_off);
	nla->nla_len = (uint16_t)len;
	return true;
}

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
static int build_pmsr_ftm_req(int nlfd, uint32_t ifindex, bool ftms_as_u32)
{
	unsigned char attrs[1024];
	unsigned char resp[NL80211_NL_RX_BUF];
	struct nla_nest pmsr, peers, peer1, req, type_ftm;
	size_t off = 0;
	size_t resp_len = 0;
	unsigned char mac[6];
	uint32_t preamble = (uint32_t)(rand32() % 4U);	/* LEGACY..DMG */
	uint16_t burst_period = (uint16_t)(rand32() & 0xffffu);
	uint8_t num_bursts_exp = (uint8_t)(rand32() & 0xfu);
	uint8_t burst_duration = (uint8_t)(rand32() & 0xfu);

	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 NL80211_ATTR_IFINDEX, ifindex))
		return -EIO;

	if (!nla_nest_start(attrs, sizeof(attrs), &off,
			    NL80211_ATTR_PEER_MEASUREMENTS, &pmsr))
		return -EIO;
	if (!nla_nest_start(attrs, sizeof(attrs), &off,
			    NL80211_PMSR_ATTR_PEERS, &peers))
		return -EIO;
	/* Anonymous peer index 1; the kernel ignores the index itself
	 * (NL80211_PMSR_ATTR_PEERS is "indexed by" but the index is
	 * meaningless per the UAPI doc -- it's just a list). */
	if (!nla_nest_start(attrs, sizeof(attrs), &off, 1, &peer1))
		return -EIO;

	random_bssid(mac);
	if (!nla_put(attrs, sizeof(attrs), &off,
		     NL80211_PMSR_PEER_ATTR_ADDR, mac, sizeof(mac)))
		return -EIO;

	if (!nla_nest_start(attrs, sizeof(attrs), &off,
			    NL80211_PMSR_PEER_ATTR_REQ, &req))
		return -EIO;
	if (!nla_nest_start(attrs, sizeof(attrs), &off,
			    NL80211_PMSR_REQ_ATTR_DATA, &type_ftm))
		return -EIO;
	{
		struct nla_nest ftm;

		if (!nla_nest_start(attrs, sizeof(attrs), &off,
				    NL80211_PMSR_TYPE_FTM, &ftm))
			return -EIO;

		if (!nla_put_u32(attrs, sizeof(attrs), &off,
				 NL80211_PMSR_FTM_REQ_ATTR_PREAMBLE,
				 preamble))
			return -EIO;
		if (!nla_put(attrs, sizeof(attrs), &off,
			     NL80211_PMSR_FTM_REQ_ATTR_BURST_PERIOD,
			     &burst_period, sizeof(burst_period)))
			return -EIO;
		if (!nla_put(attrs, sizeof(attrs), &off,
			     NL80211_PMSR_FTM_REQ_ATTR_NUM_BURSTS_EXP,
			     &num_bursts_exp, sizeof(num_bursts_exp)))
			return -EIO;
		if (!nla_put(attrs, sizeof(attrs), &off,
			     NL80211_PMSR_FTM_REQ_ATTR_BURST_DURATION,
			     &burst_duration, sizeof(burst_duration)))
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

			if (!nla_put_u32(attrs, sizeof(attrs), &off,
					 NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST,
					 v))
				return -EIO;
		} else {
			uint8_t v = (uint8_t)(rand32() & 0xffu);

			if (!nla_put(attrs, sizeof(attrs), &off,
				     NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST,
				     &v, sizeof(v)))
				return -EIO;
		}

		if (!nla_nest_end(attrs, sizeof(attrs), &off, &ftm))
			return -EIO;
	}
	if (!nla_nest_end(attrs, sizeof(attrs), &off, &type_ftm))
		return -EIO;
	if (!nla_nest_end(attrs, sizeof(attrs), &off, &req))
		return -EIO;
	if (!nla_nest_end(attrs, sizeof(attrs), &off, &peer1))
		return -EIO;
	if (!nla_nest_end(attrs, sizeof(attrs), &off, &peers))
		return -EIO;
	if (!nla_nest_end(attrs, sizeof(attrs), &off, &pmsr))
		return -EIO;

	return genl_send_recv(nlfd, nl80211_family,
			      NL80211_CMD_PEER_MEASUREMENT_START, 1,
			      attrs, off, resp, sizeof(resp), &resp_len);
}

static int del_iface_by_index(int nlfd, int ifindex)
{
	unsigned char attrs[64];
	unsigned char resp[NL80211_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;

	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 NL80211_ATTR_IFINDEX, (uint32_t)ifindex))
		return -EIO;

	return genl_send_recv(nlfd, nl80211_family,
			      NL80211_CMD_DEL_INTERFACE, 1,
			      attrs, off, resp, sizeof(resp), &resp_len);
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

		generate_rand_bytes(ssid, sizeof(ssid));
		if (!nla_put(buf, cap, &off,
			     (uint16_t)(i + 1), ssid, sizeof(ssid)))
			break;
	}
	return off;
}

/*
 * NL80211_CMD_TRIGGER_SCAN on @ifindex with 1-3 random 32-byte SSIDs.
 * Active scan is implied by the presence of NL80211_ATTR_SCAN_SSIDS.
 * Returns 0 on accept, the negated kernel errno on reject, -EIO on
 * local failure.
 */
static int trigger_scan(int nlfd, int ifindex)
{
	unsigned char attrs[1024];
	unsigned char ssids_buf[512];
	unsigned char resp[NL80211_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;
	size_t ssids_len;

	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 NL80211_ATTR_IFINDEX, (uint32_t)ifindex))
		return -EIO;

	ssids_len = build_scan_ssids(ssids_buf, sizeof(ssids_buf));
	if (ssids_len > 0) {
		if (!nla_put(attrs, sizeof(attrs), &off,
			     NL80211_ATTR_SCAN_SSIDS,
			     ssids_buf, (uint16_t)ssids_len))
			return -EIO;
	}

	return genl_send_recv(nlfd, nl80211_family,
			      NL80211_CMD_TRIGGER_SCAN, 1,
			      attrs, off, resp, sizeof(resp), &resp_len);
}

/*
 * Brief BUDGETED yield for NL80211_CMD_NEW_SCAN_RESULTS.  poll() with
 * NL80211_TIMEO_MS so the SIGALRM(1s) cap is never threatened.
 * Best-effort: returning false simply means we proceed to CONNECT
 * without an observed scan completion (the kernel's scan-cache may
 * still have entries from prior iters).
 */
static bool wait_scan_results(int nlfd)
{
	struct pollfd pfd;

	pfd.fd     = nlfd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, NL80211_TIMEO_MS) > 0 && (pfd.revents & POLLIN)) {
		unsigned char buf[NL80211_NL_RX_BUF];
		ssize_t r = recv(nlfd, buf, sizeof(buf), MSG_DONTWAIT);

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
static int connect_iface(int nlfd, int ifindex)
{
	unsigned char attrs[256];
	unsigned char resp[NL80211_NL_RX_BUF];
	unsigned char ssid[32];
	unsigned char mac[6];
	size_t off = 0;
	size_t resp_len = 0;

	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 NL80211_ATTR_IFINDEX, (uint32_t)ifindex))
		return -EIO;

	random_bssid(mac);
	if (!nla_put(attrs, sizeof(attrs), &off,
		     NL80211_ATTR_MAC, mac, sizeof(mac)))
		return -EIO;

	generate_rand_bytes(ssid, sizeof(ssid));
	if (!nla_put(attrs, sizeof(attrs), &off,
		     NL80211_ATTR_SSID, ssid, sizeof(ssid)))
		return -EIO;

	return genl_send_recv(nlfd, nl80211_family,
			      NL80211_CMD_CONNECT, 1,
			      attrs, off, resp, sizeof(resp), &resp_len);
}

static int disconnect_iface(int nlfd, int ifindex)
{
	unsigned char attrs[64];
	unsigned char resp[NL80211_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;

	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 NL80211_ATTR_IFINDEX, (uint32_t)ifindex))
		return -EIO;

	return genl_send_recv(nlfd, nl80211_family,
			      NL80211_CMD_DISCONNECT, 1,
			      attrs, off, resp, sizeof(resp), &resp_len);
}

/*
 * NL80211_CMD_REQ_SET_REG alpha2="ZZ".  ZZ is the IANA-reserved "no
 * regulatory domain selected" alpha2 -- the kernel accepts it as a
 * userspace-initiated regdom request and triggers the reg_process_self_
 * managed_hint / regulatory_hint_user codepath.  This path is what the
 * CVE-2023-3090 wiphy-index race lives in.
 */
static int set_reg_zz(int nlfd)
{
	unsigned char attrs[16];
	unsigned char resp[NL80211_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;

	if (!nla_put(attrs, sizeof(attrs), &off,
		     NL80211_ATTR_REG_ALPHA2, "ZZ", 3))
		return -EIO;

	return genl_send_recv(nlfd, nl80211_family,
			      NL80211_CMD_REQ_SET_REG, 1,
			      attrs, off, resp, sizeof(resp), &resp_len);
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
 * Open + bind the per-child NETLINK_GENERIC socket with a short
 * SO_RCVTIMEO so a wedged kernel can't push us past SIGALRM(1s).
 * Caller closes when done.
 */
static int open_genl_socket(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int s;

	s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (s < 0)
		return -1;

	tv.tv_sec  = 0;
	tv.tv_usec = NL80211_TIMEO_MS * 1000;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(s);
		return -1;
	}
	return s;
}

/*
 * Walk the per-child created-iface ring and issue a final
 * NL80211_CMD_DEL_INTERFACE for each.  Skips entries already torn down
 * inside the per-iter sequence (the entry has been zeroed).  Ring is
 * cleared on return.
 */
static void cleanup_ifaces(int nlfd)
{
	unsigned int i;

	for (i = 0; i < created_count; i++) {
		int ifx = created_ifindex[i];

		if (ifx <= 0)
			continue;
		if (del_iface_by_index(nlfd, ifx) == 0)
			__atomic_add_fetch(&shm->stats.nl80211_iface_destroyed,
					   1, __ATOMIC_RELAXED);
		created_ifindex[i] = 0;
	}
	created_count = 0;
}

/*
 * Single outer iteration of the churn loop.  Each iter creates one
 * STATION iface, runs the full scan/connect/burst/scan-again/regdom/
 * disconnect/del-iface chain on it, and tears it down at the end.  The
 * created-iface ring catches the leak case where a NEW_INTERFACE landed
 * but the per-iter DEL_INTERFACE was skipped (jump-out / wall cap hit).
 */
static void iter_one(int nlfd, unsigned int iter_idx,
		     const struct timespec *t_outer)
{
	char ifname[IFNAMSIZ];
	int ifindex;
	int rc;

	(void)iter_idx;

	if ((unsigned long long)ns_since(t_outer) >= NL80211_WALL_CAP_NS)
		return;

	(void)snprintf(ifname, sizeof(ifname), "twl%u",
		       (unsigned int)(rand32() & 0xffffu));

	rc = new_station_iface(nlfd, nl80211_phy0, ifname);
	if (rc < 0) {
		if (errno_is_unsupported(-rc))
			ns_unsupported_nl80211 = true;
		return;
	}
	ifindex = rc;
	__atomic_add_fetch(&shm->stats.nl80211_iface_created,
			   1, __ATOMIC_RELAXED);
	if (created_count < NL80211_IFACE_RING_CAP)
		created_ifindex[created_count++] = ifindex;

	rc = trigger_scan(nlfd, ifindex);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211_scan_triggered,
				   1, __ATOMIC_RELAXED);
	else if (errno_is_unsupported(-rc))
		ns_unsupported_nl80211 = true;

	(void)wait_scan_results(nlfd);

	rc = connect_iface(nlfd, ifindex);
	__atomic_add_fetch(&shm->stats.nl80211_connect_attempted,
			   1, __ATOMIC_RELAXED);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211_connect_succeeded,
				   1, __ATOMIC_RELAXED);
	else if (errno_is_unsupported(-rc))
		ns_unsupported_nl80211 = true;

	send_inner_burst(ifname, t_outer);

	/* Scan-while-connected race target.  The cfg80211_scan_done UAF
	 * window (CVE-2025-21672) lives here. */
	rc = trigger_scan(nlfd, ifindex);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211_scan_triggered,
				   1, __ATOMIC_RELAXED);

	/* Regdom change race target.  CVE-2023-3090 wiphy-index race
	 * lives in the reg_process_self_managed_hint path. */
	rc = set_reg_zz(nlfd);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211_regdom_changed,
				   1, __ATOMIC_RELAXED);

	rc = disconnect_iface(nlfd, ifindex);
	__atomic_add_fetch(&shm->stats.nl80211_disconnect_attempted,
			   1, __ATOMIC_RELAXED);
	(void)rc;

	/* PMSR FTM request sub-mode.  Low rate (ONE_IN(8)) so it doesn't
	 * crowd out the scan/connect coverage above; flips the FTMS_PER_BURST
	 * attribute width every other invocation to exercise both the u8
	 * and u32 forms documented in upstream commit 0f3c0a197309. */
	if (ONE_IN(8) && created_count > 0) {
		bool as_u32 = ONE_IN(2);
		int slot = (int)(rand32() % created_count);
		int target = created_ifindex[slot];

		if (target > 0) {
			__atomic_add_fetch(&shm->stats.nl80211_pmsr_runs,
					   1, __ATOMIC_RELAXED);
			if (build_pmsr_ftm_req(nlfd, (uint32_t)target,
					       as_u32) == 0)
				__atomic_add_fetch(&shm->stats.nl80211_pmsr_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	rc = del_iface_by_index(nlfd, ifindex);
	if (rc == 0) {
		unsigned int j;

		__atomic_add_fetch(&shm->stats.nl80211_iface_destroyed,
				   1, __ATOMIC_RELAXED);
		/* Mark the ring entry so cleanup_ifaces() doesn't try
		 * to redelete it.  Linear search is fine: the ring is
		 * bounded at 64 and cleanup happens once per child-op
		 * invocation, not per syscall. */
		for (j = 0; j < created_count; j++) {
			if (created_ifindex[j] == ifindex) {
				created_ifindex[j] = 0;
				break;
			}
		}
	}
}

bool nl80211_churn(struct childdata *child)
{
	struct timespec t_outer;
	int nlfd = -1;
	unsigned int outer_iters, i;

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

	nlfd = open_genl_socket();
	if (nlfd < 0) {
		if (errno_is_unsupported(errno))
			ns_unsupported_nl80211 = true;
		__atomic_add_fetch(&shm->stats.nl80211_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!nl80211_family_resolved) {
		uint16_t fid = 0;
		int rc = resolve_nl80211_family(nlfd, &fid);

		if (rc != 0 || fid == 0) {
			ns_unsupported_nl80211 = true;
			__atomic_add_fetch(&shm->stats.nl80211_setup_failed,
					   1, __ATOMIC_RELAXED);
			goto out;
		}
		nl80211_family = fid;

		if (!hwsim_present(nlfd)) {
			ns_unsupported_nl80211 = true;
			__atomic_add_fetch(&shm->stats.nl80211_setup_failed,
					   1, __ATOMIC_RELAXED);
			goto out;
		}
		nl80211_family_resolved = true;
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
		iter_one(nlfd, i, &t_outer);
		if (ns_unsupported_nl80211)
			break;
	}

	cleanup_ifaces(nlfd);

out:
	if (nlfd >= 0)
		close(nlfd);
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
