#ifndef _TRINITY_STATS_SUBSYS_NL80211_H
#define _TRINITY_STATS_SUBSYS_NL80211_H

/*
 * nl80211_churn childop counters.  Drives cfg80211 state-machine
 * fuzz under a mac80211_hwsim test radio inside CLONE_NEWNET.
 * Race surface targeted by CVE-2022-41674 (cfg80211_update_notlisted_
 * nontrans OOB), CVE-2023-3090 (nl80211 wiphy index race), and
 * CVE-2025-21672 (cfg80211_scan_done UAF).  See childops/net/netlink/
 * nl80211-churn.c.  The surrounding struct stats_s composes an instance
 * of struct nl80211_stats as its "nl80211" member.
 */
struct nl80211_stats {
	unsigned long runs;			/* total nl80211_churn invocations */
	unsigned long setup_failed;		/* unshare / netlink open / family resolve / hwsim absent */
	unsigned long scan_triggered;		/* NL80211_CMD_TRIGGER_SCAN accepted */
	unsigned long connect_attempted;	/* NL80211_CMD_CONNECT issued */
	unsigned long connect_succeeded;	/* NL80211_CMD_CONNECT accepted (no kernel rejection) */
	unsigned long disconnect_attempted;	/* NL80211_CMD_DISCONNECT issued */
	unsigned long regdom_changed;		/* NL80211_CMD_SET_REG accepted */
	unsigned long iface_created;		/* NL80211_CMD_NEW_INTERFACE accepted */
	unsigned long iface_destroyed;		/* NL80211_CMD_DEL_INTERFACE accepted */
	unsigned long bursts_sent;		/* loopback UDP sendto on wlan iface returned >0 */
	unsigned long pmsr_runs;		/* NL80211_CMD_PEER_MEASUREMENT_START FTM request issued */
	unsigned long pmsr_ok;			/* NL80211_CMD_PEER_MEASUREMENT_START accepted */
	unsigned long admin_gate_runs;		/* admin-gate probe forked + ran (per upstream 381cd547bc6e audit) */
	unsigned long admin_gate_eperm_ok;	/* probed cmd correctly returned -EPERM under dropped caps */
	unsigned long admin_gate_unexpected;	/* probed cmd returned non-EPERM (regression or unreachable) */
};

#endif	/* _TRINITY_STATS_SUBSYS_NL80211_H */
