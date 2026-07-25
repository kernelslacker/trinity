/*
 * nl80211-churn-station.c -- station/key phase of nl80211_churn.
 *
 * Split from childops/net/netlink/nl80211-churn.c so the SME
 * connect/disconnect helpers, the FTM PMSR builder that walks the
 * NLA_U8-vs-NLA_U32 regression surface, and the admin-gate detector
 * that probes the CAP_NET_ADMIN barrier build in parallel with the
 * discovery, interface, and scan/BSS phases.  Pure code motion out
 * of the monolithic TU: no behavior change, no rename.
 *
 * Public entry points (declared in nl80211-churn-internal.h and
 * consumed by the top-level coordinator in nl80211-churn.c):
 *   - connect_iface(): NL80211_CMD_CONNECT to a random BSSID/SSID;
 *   - disconnect_iface(): NL80211_CMD_DISCONNECT by ifindex;
 *   - build_pmsr_ftm_req(): FTM PMSR with FTMS_PER_BURST as u8 or u32;
 *   - nl80211_admin_gate_probe(): fork+unmapped-userns admin-gate probe.
 *
 * random_bssid() and the admin-gate command catalogue stay file-static
 * -- the only callers in the tree are the four public entry points
 * above, all housed in this TU.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "kernel/nl80211.h"

#include "childops-genl.h"
#include "childops-util.h"
#include "nl80211-churn-internal.h"
#include "random.h"
#include "shm.h"

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
int build_pmsr_ftm_req(struct genl_ctx *ctx, uint32_t ifindex,
		       bool ftms_as_u32)
{
	unsigned char buf[1024];
	struct nlmsghdr *nlh;
	size_t off;
	size_t pmsr_off, peers_off, peer1_off, req_off, type_ftm_off, ftm_off;
	unsigned char mac[6];
	uint32_t preamble = rnd_modulo_u32(4U);	/* LEGACY..DMG */
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
int connect_iface(struct genl_ctx *ctx, int ifindex)
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

int disconnect_iface(struct genl_ctx *ctx, int ifindex)
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

void nl80211_admin_gate_probe(uint32_t wiphy_idx)
{
	pid_t pid;

	__atomic_add_fetch(&shm->stats.nl80211.admin_gate_runs,
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
				__atomic_add_fetch(&shm->stats.nl80211.admin_gate_eperm_ok,
						   1, __ATOMIC_RELAXED);
			else
				__atomic_add_fetch(&shm->stats.nl80211.admin_gate_unexpected,
						   1, __ATOMIC_RELAXED);
		}
		genl_close(&cctx);
		_exit(0);
	}

	(void)waitpid_eintr(pid, NULL, 0);
}

#endif  /* __has_include gate */
