/*
 * child-canary-policy.c -- Static policy tables and eligibility helpers
 * for the dormant-childop canary queue.
 *
 * Owns the operator-visible input to the picker order: config-blocked
 * terminals, risky-defer skip set, pid-heavy drain set, and the op ->
 * setup-failure reason hint table.  These are the only
 * places the queue's classification of an op is source-declared; every
 * other TU reads them via child-canary-internal.h.
 */
#include <stdbool.h>
#include <time.h>

#include "child-api.h"
#include "child-canary-internal.h"
#include "params.h"
#include "trinity.h"
#include "utils.h"

/* --------------------------------------------------------------------
 * Skip sets and classification tables.  These are the operator-visible
 * inputs to the queue's picker order.
 *
 * The picker's first-pass order is a per-run random shuffle of every
 * eligible op, built in canary_queue_init() -- there is no static
 * priority seed list, so nothing here goes stale as ops are added or
 * removed.  config_blocked is permanent (CONFIG_BLOCKED state at
 * startup, never picked).  risky_defer is left in DORMANT but the
 * picker silently skips it -- these ops need isolation (root-only /
 * inner-fork / SR-IOV / driver prereq) that the queue does not
 * provide.
 * -------------------------------------------------------------------- */

const enum child_op_type canary_config_blocked[] = {
	CHILD_OP_NUMA_MIGRATION,
	CHILD_OP_TIPC_LINK_CHURN,
	CHILD_OP_SCTP_ASSOC_CHURN,
	CHILD_OP_NL80211_CHURN,
	CHILD_OP_UBLK_LIFECYCLE,
	CHILD_OP_ATM_VCC_CHURN,
	CHILD_OP_IP6GRE_BOND_LAPB_STACK,
};
const unsigned int canary_config_blocked_count = ARRAY_SIZE(canary_config_blocked);

/* Pid-heavy ops the picker temporarily evicts while the parent fork
 * loop is in the drain window (see fork_pressure_drain_active() in
 * main/loop.c).  Membership criteria: the op either fork()s short-lived
 * helper workers internally (and bumps a *_fork_failed counter when
 * that inner fork fails -- those five are the same set surfaced in
 * main/loop.c's bail-time subworker fork-fail dump) or its primary purpose
 * is hammering the pid/pidfd allocator (pidfd_storm).  fork_storm
 * is double-gated: it is already in canary_risky_defer below, but is
 * listed here for completeness so a future risky-defer reshuffle
 * cannot quietly let it through the drain. */
static const enum child_op_type canary_pid_heavy_ops[] = {
	CHILD_OP_FORK_STORM,
	CHILD_OP_PIDFD_STORM,
	CHILD_OP_QRTR_BIND_RACE,
	CHILD_OP_PFKEY_SPD_WALK,
	CHILD_OP_L2TP_IFNAME_RACE,
	CHILD_OP_STATMOUNT_IDMAP_OVERFLOW,
	CHILD_OP_SYSFS_STRING_RACE,
};

const enum child_op_type canary_risky_defer[] = {
	CHILD_OP_FORK_STORM,
	CHILD_OP_CPU_HOTPLUG_RIDER,
	CHILD_OP_VDSO_MREMAP_RACE,
	CHILD_OP_BARRIER_RACER,
	CHILD_OP_MOUNT_CHURN,
	CHILD_OP_UFFD_CHURN,
	CHILD_OP_DEVLINK_PORT_CHURN,
	CHILD_OP_RTNL_VF_BROADCAST_GETLINK,
	CHILD_OP_TTY_LDISC_CHURN,
};
const unsigned int canary_risky_defer_count = ARRAY_SIZE(canary_risky_defer);

/* Table-membership helper kept local to the canary picker.  The picker
 * currently uses inline state-bit checks instead, so there is no live
 * caller; keep it declared but marked unused until the picker grows a
 * second table walk. */
static bool op_is_in_table(enum child_op_type op,
			   const enum child_op_type *tbl,
			   unsigned int n) __attribute__((unused));
static bool op_is_in_table(enum child_op_type op,
			   const enum child_op_type *tbl,
			   unsigned int n)
{
	unsigned int i;
	for (i = 0; i < n; i++)
		if (tbl[i] == op)
			return true;
	return false;
}

/* Drain-mode predicate: skip pid-heavy ops in the canary picker while
 * the parent fork loop is in its post-threshold recovery window.  The
 * arming side lives in main/loop.c (fork_children); here we just consult
 * the published deadline.  Three short-circuits keep the hot path
 * cheap on the default (--fork-pressure-drain off) run: the flag
 * check, the deadline-is-zero check, and the small-array membership
 * walk only runs once the first two say yes.
 *
 * Active CANARYING is not interrupted -- this only filters NEW picks
 * from pick_next_canary().  Letting the in-flight window close
 * naturally avoids polluting the op's window counters with a forced
 * mid-window kill, and the slot's contribution to pid pressure is
 * already bounded by the existing window-iter budget. */
bool fork_pressure_should_suppress(enum child_op_type op)
{
	unsigned long until;
	struct timespec ts;
	unsigned int i;

	if (!fork_pressure_drain)
		return false;
	until = fork_pressure_drain_active();
	if (until == 0)
		return false;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	if ((unsigned long)ts.tv_sec >= until)
		return false;

	for (i = 0; i < ARRAY_SIZE(canary_pid_heavy_ops); i++)
		if (canary_pid_heavy_ops[i] == op)
			return true;
	return false;
}

/* --------------------------------------------------------------------
 * Setup-failure reason table.  Maps each op known to require a specific
 * host feature to the reason bucket its setup path would fail under.
 * The table is deliberately conservative: only ops for which the failure
 * mode is clear from the op's dispatch shape (missing module for a
 * protocol-family op, missing FS for a mount fuzzer, etc.) are listed.
 * Ops not in the table get SETUP_FAIL_REASON_UNKNOWN and still auto-
 * block after CANARY_SETUP_BROKEN_AUTOBLOCK_N windows -- the reason
 * label is observability, not gating.
 * -------------------------------------------------------------------- */

struct canary_setup_reason_hint {
	enum child_op_type op;
	enum canary_setup_fail_reason reason;
};

static const struct canary_setup_reason_hint canary_setup_reason_hints[] = {
	/* Ops in the startup CONFIG_BLOCKED set: each entry mirrors the
	 * feature its setup path probes for. */
	{ CHILD_OP_NUMA_MIGRATION,		SETUP_FAIL_REASON_NS_UNSUPPORTED },
	{ CHILD_OP_TIPC_LINK_CHURN,		SETUP_FAIL_REASON_MODULE_MISSING },
	{ CHILD_OP_SCTP_ASSOC_CHURN,		SETUP_FAIL_REASON_MODULE_MISSING },
	{ CHILD_OP_NL80211_CHURN,		SETUP_FAIL_REASON_MODULE_MISSING },
	{ CHILD_OP_UBLK_LIFECYCLE,		SETUP_FAIL_REASON_MODULE_MISSING },
	{ CHILD_OP_ATM_VCC_CHURN,		SETUP_FAIL_REASON_MODULE_MISSING },
	{ CHILD_OP_IP6GRE_BOND_LAPB_STACK,	SETUP_FAIL_REASON_MODULE_MISSING },
	/* Ops observed in the 11/11-run 100%-setup-fail tally.  The queue
	 * will now auto-transition these into CONFIG_BLOCKED after
	 * CANARY_SETUP_BROKEN_AUTOBLOCK_N windows; the reason label lets
	 * the operator triage without cross-referencing sources. */
	{ CHILD_OP_IP6ERSPAN_NETNS_MIGRATE,	SETUP_FAIL_REASON_MODULE_MISSING },
	{ CHILD_OP_BPF_CGROUP_ATTACH,		SETUP_FAIL_REASON_CAP_MISSING },
	{ CHILD_OP_AFXDP_CHURN,			SETUP_FAIL_REASON_DEVICE_MISSING },
	{ CHILD_OP_HFS_MOUNT_FUZZ,		SETUP_FAIL_REASON_FS_UNSUPPORTED },
};

const char *canary_setup_fail_reason_name(enum canary_setup_fail_reason r)
{
	switch (r) {
	case SETUP_FAIL_REASON_UNKNOWN:			return "unknown";
	case SETUP_FAIL_REASON_CAP_MISSING:		return "cap-missing";
	case SETUP_FAIL_REASON_MODULE_MISSING:		return "module-missing";
	case SETUP_FAIL_REASON_SYSCTL_DISABLED:		return "sysctl-disabled";
	case SETUP_FAIL_REASON_MOUNT_UNAVAILABLE:	return "mount-unavailable";
	case SETUP_FAIL_REASON_NS_UNSUPPORTED:		return "ns-unsupported";
	case SETUP_FAIL_REASON_DEVICE_MISSING:		return "device-missing";
	case SETUP_FAIL_REASON_SCRATCH_UNAVAILABLE:	return "scratch-unavailable";
	case SETUP_FAIL_REASON_FS_UNSUPPORTED:		return "fs-unsupported";
	case SETUP_FAIL_REASON_QUOTA_HIT:		return "quota-hit";
	}
	return "unknown";
}

enum canary_setup_fail_reason
canary_setup_fail_reason_for_op(enum child_op_type op)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(canary_setup_reason_hints); i++)
		if (canary_setup_reason_hints[i].op == op)
			return canary_setup_reason_hints[i].reason;
	return SETUP_FAIL_REASON_UNKNOWN;
}

const char *canary_blocked_reason_name(enum canary_blocked_reason r)
{
	switch (r) {
	case CANARY_BLOCKED_REASON_NONE:			return "none";
	case CANARY_BLOCKED_REASON_CONFIG_ABSENT:		return "config-absent";
	case CANARY_BLOCKED_REASON_SETUP_BROKEN:		return "setup-broken";
	case CANARY_BLOCKED_REASON_NO_OUTER_BRACKET:		return "no-outer-bracket";
	}
	return "unknown";
}
