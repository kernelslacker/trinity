/*
 * nl80211-churn-internal.h
 *
 * Shared declarations split out of childops/net/netlink/nl80211-churn.c so
 * that the discovery/setup, interface, scan/BSS, and station/key phases
 * of nl80211_churn can each live in their own translation unit and
 * compile in parallel with the rest of the module.  This header is
 * private to the sibling TUs that make up nl80211-churn -- do not
 * include it from anywhere else.
 *
 * Contents:
 *   - the shared support includes so every sibling TU sees an identical
 *     view of the nl80211 world (the __has_include gate lives in the
 *     including .c files -- this header is only pulled in from the
 *     gated arm and never on the fallback-stub arm);
 *   - cross-TU macro budgets that the phases must keep in lock-step
 *     (outer-loop budget knobs, inner UDP burst floor/cap, retry cap,
 *     netlink recv-window sizes, per-child iface ring cap);
 *   - the shared per-child state promoted from file-static in the
 *     original monolithic nl80211-churn.c to external linkage so the
 *     split phases can read/write it (ns_unsupported_nl80211 latch,
 *     nl80211_phy0 discovery cache, created_ifindex ring);
 *   - two small errno predicates and the genl_send_recv_retry wrapper
 *     as static inline so each sibling TU can call them at the same
 *     cost the original file-local functions had, without incurring
 *     any cross-TU indirect call or a duplicate definition.
 *   - forward declarations for the per-phase entry points, deliberately
 *     widened from file-static to external linkage so the top-level
 *     coordinator in nl80211-churn.c can drive them across the TU
 *     boundary.
 */

#ifndef CHILDOPS_NL80211_CHURN_INTERNAL_H
#define CHILDOPS_NL80211_CHURN_INTERNAL_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/netlink.h>

#include "kernel/nl80211.h"

#include "childops-genl.h"

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

/*
 * Cross-TU state promoted from file-static in the monolithic
 * nl80211-churn.c.  See the lifecycle comments at the definitions in
 * the corresponding phase TUs for the latching rules.
 *
 *   ns_unsupported_nl80211: per-grandchild latched gate.  Inherited as
 *     false at grandchild fork time (the persistent child never writes
 *     it -- the in-ns callback runs exclusively in transient
 *     grandchildren) and flipped on the first config-absent rejection
 *     from any phase probe.
 *   nl80211_get_phy0() / nl80211_set_phy0(): first-wiphy index cached
 *     by hwsim_present in shm (shm->nl80211_phy0); consumed by the
 *     iface + admin-gate paths so we don't pay the GET_WIPHY
 *     enumerate every churn call.  The cache write and the paired
 *     nl80211_phy0_cached gate live in shm because the write sites
 *     sit inside the userns_run_in_ns() grandchild -- process-local
 *     statics would die with the grandchild on _exit().
 *   created_ifindex[] / created_count: per-child created-iface ring
 *     written by the iface-setup phase and drained by the teardown +
 *     end-of-child cleanup sweep.
 */
extern bool ns_unsupported_nl80211;
extern int created_ifindex[NL80211_IFACE_RING_CAP];
extern unsigned int created_count;

uint32_t nl80211_get_phy0(void);
void nl80211_set_phy0(uint32_t phy);

static inline bool errno_is_unsupported(int e)
{
	return e == EPERM || e == ENOSYS || e == EOPNOTSUPP ||
	       e == ENOPROTOOPT || e == EAFNOSUPPORT ||
	       e == EPROTONOSUPPORT || e == ENODEV;
}

static inline bool errno_is_transient(int e)
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
 *
 * Kept static inline in the shared header so every phase TU calls it
 * at the same cost the original file-local definition had, without
 * incurring any cross-TU indirect call or a duplicate definition.
 */
static inline int genl_send_recv_retry(struct genl_ctx *ctx, void *msg, size_t len)
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
 * Cross-TU phase entry points.  Each declaration widens its
 * definition's linkage from file-static (in the pre-carve monolithic
 * TU) to external so the top-level coordinator in nl80211-churn.c can
 * call it across the TU boundary.  See the definition site for the
 * per-function contract.
 */

/* Discovery/setup phase -- nl80211-churn-discovery.c */
bool hwsim_present(struct genl_ctx *ctx, unsigned long *direct_calls);

/* Interface churn phase -- nl80211-churn-iface.c.  struct timespec is
 * forward-referenced in the nl80211_iter_setup() signature so this
 * header does not need to pull in <time.h> transitively. */
struct timespec;
int new_station_iface(struct genl_ctx *ctx, uint32_t phy, const char *ifname,
		      unsigned long *direct_calls);
int del_iface_by_index(struct genl_ctx *ctx, int ifindex,
		       unsigned long *direct_calls);
void cleanup_ifaces(struct genl_ctx *ctx, unsigned long *direct_calls);
int nl80211_iter_setup(struct genl_ctx *ctx, char *ifname,
		       int *ifindex, const struct timespec *t_outer,
		       unsigned long *direct_calls);

/* Scan/BSS churn phase -- nl80211-churn-scan.c */
int trigger_scan(struct genl_ctx *ctx, int ifindex, unsigned long *direct_calls);
bool wait_scan_results(struct genl_ctx *ctx, unsigned long *direct_calls);
int set_reg_zz(struct genl_ctx *ctx, unsigned long *direct_calls);

/* Station/key phase -- nl80211-churn-station.c */
int connect_iface(struct genl_ctx *ctx, int ifindex, unsigned long *direct_calls);
int disconnect_iface(struct genl_ctx *ctx, int ifindex, unsigned long *direct_calls);
int build_pmsr_ftm_req(struct genl_ctx *ctx, uint32_t ifindex, bool ftms_as_u32,
		       unsigned long *direct_calls);
void nl80211_admin_gate_probe(uint32_t wiphy_idx, unsigned long *direct_calls);

#endif /* CHILDOPS_NL80211_CHURN_INTERNAL_H */
