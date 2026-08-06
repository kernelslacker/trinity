/*
 * Alt-op picker, dedicated-child rotation, and the dormant-op gate
 * that drives the canary queue's observability.  Split out of the
 * former child-altop.c so make -j can compile the picker/dormancy
 * tables concurrently with the alt_op_name/op_dispatch metadata
 * (child-altop-table.c), the adaptive-budget/decay ring
 * (child-altop-budget.c), and the outcome/score dump
 * (child-altop-score.c).
 *
 * pick_op_type sheds its `static` linkage at the TU split --
 * child_process() in child.c calls it on the hot per-iteration path.
 * See include/child-internal.h for the extern declarations.
 */


#include <string.h>
#include "child.h"
#include "child-internal.h"
#include "params.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
#include "kernel/mount.h"
#include "kernel/if_packet.h"
/*
 * Startup snapshot of the dormant-op gate consulted by init_altop_dispatch()
 * to build the dense enabled_altops[] vector.  Mutated at runtime by the
 * parent's queue transition path (enter_canarying / close_window_and_decide);
 * to check what's CURRENTLY active, read the periodic `canary queue:` log
 * lines and see canary_queue_init() in child-canary-state.c, not this table.
 *
 * Slot ordering matches pick_op_type_table[]; both are generated from
 * include/childop.def in the same walk, so the two arrays land in
 * lockstep by construction and cannot drift.  The _Static_asserts below
 * still pin ARRAY_SIZE equality and count against NR_CHILD_OP_TYPES-1
 * as a belt-and-braces check against any future macro change.
 *
 * Per-op dormant_default values live on the CHILDOP() row in
 * include/childop.def -- adding a new altop is a single-line edit
 * there, no touch to this array or to pick_op_type_table[] required.
 * That collapses the four-way append conflict (enum + prototypes +
 * these two arrays) that concurrent altop drafts used to hit down to
 * the def-file row itself.  The sentinel row (CHILD_OP_SYSCALL) is
 * skipped by redefining CHILDOP_SENTINEL to nothing before the
 * #include, so the slot count stays at NR_CHILD_OP_TYPES - 1.
 */
static int dormant_op_disabled[] = {
#define CHILDOP_SENTINEL(enum_name, name_string)	/* skip -- picker has no slot for CHILD_OP_SYSCALL */
#define CHILDOP(enum_name, name_string, dispatch_fn, uses_outer_bracket, dormant_default) \
	dormant_default,
#include "childop.def"
#undef CHILDOP
#undef CHILDOP_SENTINEL
};

/*
 * Round-robin rotation for dedicated alt-op children.  The slow,
 * pressure-style ops are listed first (mmap_lifecycle, mprotect_split,
 * mlock_pressure, inode_spewer) because those are the paths the design
 * brief explicitly calls out as too expensive to mix into the syscall
 * hot loop even at 1%.  fork/futex/signal/pipe/flock storms come next,
 * then the cgroup/mount/uffd/io_uring churners, and finally the heavier
 * subsystem fuzzers (perf, tracefs, bpf, fault-injector, recipes).  The
 * dispatch in child_process() already has cases for every entry below,
 * so a dedicated child stamped with any of these op types runs straight
 * through the existing per-op function on every iteration.
 *
 * Bypasses the dormant_op_disabled[] gate by design: random pickers stay
 * gated until each op has been load-tested, but a child reserved for a
 * specific op runs it deliberately.
 */
static const enum child_op_type alt_op_rotation[] = {
	CHILD_OP_MMAP_LIFECYCLE,
	CHILD_OP_MPROTECT_SPLIT,
	CHILD_OP_VMA_SPLIT_STORM,
	CHILD_OP_MADVISE_CYCLER,
	CHILD_OP_NUMA_MIGRATION,
	CHILD_OP_MLOCK_PRESSURE,
	CHILD_OP_INODE_SPEWER,
	CHILD_OP_FORK_STORM,
	CHILD_OP_CPU_HOTPLUG_RIDER,
	CHILD_OP_PIDFD_STORM,
	CHILD_OP_PROCESS_MRELEASE_RACE,
	CHILD_OP_FUTEX_STORM,
	CHILD_OP_SIGNAL_STORM,
	CHILD_OP_PIPE_THRASH,
	CHILD_OP_FLOCK_THRASH,
	CHILD_OP_XATTR_THRASH,
	CHILD_OP_CGROUP_CHURN,
	CHILD_OP_MOUNT_CHURN,
	CHILD_OP_UFFD_CHURN,
	CHILD_OP_IOURING_FLOOD,
	CHILD_OP_CLOSE_RACER,
	CHILD_OP_EPOLL_VOLATILITY,
	CHILD_OP_EPOLL_NEST_RACE,
	CHILD_OP_KEYRING_SPAM,
	CHILD_OP_VDSO_MREMAP_RACE,
	CHILD_OP_MREMAP_MERGE_MATRIX,
	CHILD_OP_MEMORY_PRESSURE,
	CHILD_OP_SLAB_CACHE_THRASH,
	CHILD_OP_TLS_ROTATE,
	CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING,
	CHILD_OP_PACKET_FANOUT_THRASH,
	CHILD_OP_ETH_EMITTER,
	CHILD_OP_PKT_BUILDER_PROBE,
	CHILD_OP_USERNS_FUZZER,
	CHILD_OP_SCHED_CYCLER,
	CHILD_OP_BARRIER_RACER,
	CHILD_OP_GENETLINK_FUZZER,
	CHILD_OP_PERF_CHAINS,
	CHILD_OP_TRACEFS_FUZZER,
	CHILD_OP_BPF_LIFECYCLE,
	CHILD_OP_FAULT_INJECTOR,
	CHILD_OP_RECIPE_RUNNER,
	CHILD_OP_IOURING_RECIPES,
	CHILD_OP_FD_STRESS,
	CHILD_OP_REFCOUNT_AUDITOR,
	CHILD_OP_FS_LIFECYCLE,
	CHILD_OP_PROCFS_WRITER,
	CHILD_OP_SOCKET_FAMILY_CHAIN,
	CHILD_OP_IOURING_NET_MULTISHOT,
	CHILD_OP_TCP_AO_ROTATE,
	CHILD_OP_VRF_FIB_CHURN,
	CHILD_OP_NETLINK_MONITOR_RACE,
	CHILD_OP_TIPC_LINK_CHURN,
	CHILD_OP_TLS_ULP_CHURN,
	CHILD_OP_VXLAN_ENCAP_CHURN,
	CHILD_OP_IP_GRE_CHURN,
	CHILD_OP_BRIDGE_FDB_STP,
	CHILD_OP_NFTABLES_CHURN,
	CHILD_OP_TC_QDISC_CHURN,
	CHILD_OP_XFRM_CHURN,
	CHILD_OP_ESP_CRAFTED_RX,
	CHILD_OP_BPF_CGROUP_ATTACH,
	CHILD_OP_SCTP_ASSOC_CHURN,
	CHILD_OP_SCTP_CHUNK_RX,
	CHILD_OP_MPTCP_PM_CHURN,
	CHILD_OP_NL80211_CHURN,
	CHILD_OP_NAT_T_CHURN,
	CHILD_OP_SOCK_DIAG_WALKER,
	CHILD_OP_ALTNAME_THRASH,
	CHILD_OP_OVS_TUNNEL_VPORT_CHURN,
	CHILD_OP_TTY_LDISC_CHURN,
	CHILD_OP_UMOUNT_RACE,
	CHILD_OP_SIT_PROTO41_RX,
	CHILD_OP_IPV6_RPL_CLONE_FIDELITY,
	CHILD_OP_SOCKMAP_CORK_RACE,
};
#define NR_ALT_OP_ROTATION	ARRAY_SIZE(alt_op_rotation)

void assign_dedicated_alt_op(struct childdata *child, int childno)
{
	if (alt_op_children == 0 || childno < 0)
		return;
	if ((unsigned int)childno >= alt_op_children)
		return;

	/* Canary slots are carved from the FRONT of the alt-op pool: the
	 * first canary_slots slots get the canary queue's currently-
	 * canarying op stamped here at spawn time, instead of the
	 * alt_op_rotation[] entry they would otherwise use.  The
	 * remaining alt-op slots continue with the rotation, shifted past
	 * the canary carve so the rotation walk stays stable.  When the
	 * queue is disabled (--no-canary-queue or canary_slots=0), or
	 * before the first canarying op has been selected,
	 * canary_slot_active() returns false and the rotation handles
	 * every slot from index 0 as it did pre-queue. */
	if (canary_slot_active(childno)) {
		child->op_type = canary_active_op();
		return;
	}

	unsigned int rotation_idx = (unsigned int)childno;
	if (canary_slots > 0 && rotation_idx >= canary_slots)
		rotation_idx -= canary_slots;
	child->op_type = alt_op_rotation[rotation_idx % NR_ALT_OP_ROTATION];
}

void log_alt_op_config(void)
{
	char buf[512];
	size_t off = 0;
	unsigned int i;
	unsigned int show;

	if (alt_op_children == 0)
		return;

	/* Show the head of the rotation at -v so the assignment for the
	 * first few slots is eyeballable.  Cap at 5 (or fewer if
	 * alt_op_children itself is smaller) and append an ellipsis when
	 * there are more rotation entries left. */
	show = alt_op_children < 5 ? alt_op_children : 5;
	if (show > NR_ALT_OP_ROTATION)
		show = NR_ALT_OP_ROTATION;

	for (i = 0; i < show; i++) {
		int n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
				 off ? ", " : "",
				 alt_op_name(alt_op_rotation[i]));
		if (n <= 0 || (size_t)n >= sizeof(buf) - off)
			break;
		off += (size_t)n;
	}
	if (show < NR_ALT_OP_ROTATION && off < sizeof(buf) - 1)
		(void) snprintf(buf + off, sizeof(buf) - off, ", ...");

	output(1, "alt-op children: %u reserved, rotation = %s\n",
		alt_op_children, buf);
}

/*
 * Slot -> alt-op mapping.  Same indexing as dormant_op_disabled[]: slot N
 * is enabled iff dormant_op_disabled[N] == 0.  Slot ordering follows
 * the childop.def row order (minus the CHILD_OP_SYSCALL sentinel row);
 * both arrays are generated from the same file in the same walk, so
 * pick_op_type_table[i] and dormant_op_disabled[i] describe the same op
 * for every i by construction.
 *
 * The old file-static designator layout kept an explicit `[N] = op`
 * designator per row so parallel altop drafts would conflict on the
 * same append line -- codegen out of childop.def moves that conflict
 * up into the .def file's row list, where the same "conflict on
 * append" property still holds but a new altop is now a single-line
 * edit instead of four.  The _Static_asserts below still guard the
 * total slot count and the sentinel-vs-picker relationship.
 */
static const enum child_op_type pick_op_type_table[] = {
#define CHILDOP_SENTINEL(enum_name, name_string)	/* skip -- picker has no slot for CHILD_OP_SYSCALL */
#define CHILDOP(enum_name, name_string, dispatch_fn, uses_outer_bracket, dormant_default) \
	enum_name,
#include "childop.def"
#undef CHILDOP
#undef CHILDOP_SENTINEL
};
_Static_assert(ARRAY_SIZE(pick_op_type_table) == ARRAY_SIZE(dormant_op_disabled),
	"pick_op_type_table and dormant_op_disabled must have matching slot counts");
/* One slot per non-sentinel child_op_type.  Adding a new CHILD_OP_* without
 * also adding its slot to pick_op_type_table[] (and dormant_op_disabled[])
 * leaves the op invisible to the random picker + canary queue; fail the
 * build instead of silently dropping coverage. */
_Static_assert(ARRAY_SIZE(pick_op_type_table) == NR_CHILD_OP_TYPES - 1,
	"pick_op_type_table missing a slot for a CHILD_OP_* enum value");

/*
 * Reverse of pick_op_type_table[]: given a child_op_type, find the
 * slot index in dormant_op_disabled[] whose pick_op_type_table[]
 * entry points to that op.  Returns -1 if no slot matches (slot-53
 * sentinel for CHILD_OP_SYSCALL would return -1 in current builds;
 * the canary queue never asks for that mapping).  Linear scan over
 * ~100 entries; called once per state transition, never on the hot
 * path.
 *
 * Exists so child-canary-state.c can flip the gate for a specific op
 * without taking a direct reference to pick_op_type_table[] / the
 * dormant_op_disabled[] storage.  Keeps both arrays file-static.
 */
int dormant_op_slot_for(enum child_op_type op)
{
	unsigned int i;

	if (op == CHILD_OP_SYSCALL || op >= NR_CHILD_OP_TYPES)
		return -1;
	for (i = 0; i < ARRAY_SIZE(pick_op_type_table); i++) {
		if (pick_op_type_table[i] == op)
			return (int)i;
	}
	return -1;
}

/*
 * Mutate the dormant-op gate for `op` and rebuild the dense vector.
 * Called from the canary queue's promote / demote transitions.
 * Single store on the parent path (the parent is the sole writer);
 * children re-read the rebuilt enabled_altops[] on their next pick.
 * See the design note in init_altop_dispatch() about the deliberately
 * non-atomic rebuild -- both gate states are safe to dispatch on.
 *
 * Phase 1 propagation contract: both dormant_op_disabled[] and
 * enabled_altops[] are parent-private after fork() (COW), so the
 * "children re-read" above means children spawned AFTER this call,
 * not children already running.  Already-forked random children
 * continue to consult their fork-time snapshot until the slot turns
 * over.  Dedicated canary slots are re-stamped on respawn and so see
 * the new state immediately on the next spawn cycle.  See the header
 * block in child-canary-state.c for the full scope statement; the shm-
 * published variant is Phase 2 work.
 */
void dormant_op_set(enum child_op_type op, bool dormant)
{
	int slot = dormant_op_slot_for(op);

	if (slot < 0)
		return;
	dormant_op_disabled[slot] = dormant ? 1 : 0;
	init_altop_dispatch();
}

/*
 * Read-only view used by the canary queue's startup pass: it walks
 * the dormant gate to figure out which ops are already promoted
 * (gate == 0) at startup so the queue's PROMOTED state matches what
 * the dispatcher will actually pick from t=0.
 */
bool dormant_op_is_active(enum child_op_type op)
{
	int slot = dormant_op_slot_for(op);

	if (slot < 0)
		return false;
	return dormant_op_disabled[slot] == 0;
}

/*
 * Dense vector of currently-enabled alt-ops, derived from
 * dormant_op_disabled[] + pick_op_type_table[] by init_altop_dispatch().
 *
 * The previous implementation re-rolled into the full 71-slot space and
 * rejected dormant slots inline, which collapsed the EFFECTIVE altop rate
 * well below the nominal 5% (effective ≈ 5% × enabled/71).  Picking from
 * the dense vector keeps effective ≈ nominal regardless of how many slots
 * are gated off, while keeping dormant_op_disabled[] as the source of truth.
 *
 * Sized at NR_CHILD_OP_TYPES (one slot per enum value, more than enough to
 * hold every non-sentinel slot in pick_op_type_table[]).
 */
static enum child_op_type enabled_altops[NR_CHILD_OP_TYPES];
static unsigned int enabled_altop_count;

/*
 * Walk dormant_op_disabled[] + pick_op_type_table[] in parallel and
 * populate enabled_altops[] / enabled_altop_count.  Skips dormant slots
 * and the slot-53 sentinel hole.  Logs the resulting dispatch config so
 * the operator can see at -v what the effective altop mix actually is.
 *
 * Called once from main_loop before fork_children; the dormant gates
 * are compile-time constants so a single startup pass suffices.
 * dormant_op_set() re-invokes this so runtime flips stay accurate.
 */
void init_altop_dispatch(void)
{
	char buf[1024];
	size_t off = 0;
	unsigned int i;
	unsigned int count = 0;
	bool truncated = false;

	for (i = 0; i < ARRAY_SIZE(pick_op_type_table); i++) {
		enum child_op_type op = pick_op_type_table[i];
		int n;

		if (dormant_op_disabled[i])
			continue;
		if (op == CHILD_OP_SYSCALL)	/* slot-53 sentinel */
			continue;

		enabled_altops[count++] = op;

		if (truncated)
			continue;

		n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
			off ? ", " : "", alt_op_name(op));
		if (n <= 0 || (size_t)n >= sizeof(buf) - off) {
			/* Drop the partial write and stop appending --
			 * keep walking the table so enabled_altops[]
			 * still gets every non-dormant op. */
			buf[off] = '\0';
			truncated = true;
			continue;
		}
		off += (size_t)n;
	}
	if (truncated && off + sizeof(", ...") <= sizeof(buf))
		(void) snprintf(buf + off, sizeof(buf) - off, ", ...");
	enabled_altop_count = count;

	if (count == 0) {
		output(1, "altop dispatch: nominal=5%% effective=0%% (all altops dormant, falling back to syscall)\n");
		return;
	}

	output(1, "altop dispatch: nominal=5%% effective=5%% (%u enabled altops: %s)\n",
		count, buf);
}

enum child_op_type pick_op_type(void)
{
	unsigned int threshold = 95;
	unsigned int r;

	/* Phase 2 plateau intervention: when the classifier has the
	 * fleet in the childop_dominant regime (alt-op-driven edges
	 * out-running generic-syscall edges by PHC_CHILDOP_DOMINANT_
	 * RATIO), raise the non-dedicated-child alt-op share from 5%
	 * to 25% for the plateau duration.  Leans into the channel
	 * that's actually discovering edges instead of letting the
	 * 95% generic-syscall mass dilute its yield.
	 *
	 * Dedicated alt-op children (alt_op_children + canary slots)
	 * skip this picker entirely via the use_dedicated_op hoist in
	 * child_process(), so the canary queue's measurement window is
	 * untouched -- the burst only retargets the non-dedicated
	 * child pool.
	 *
	 * Gate is a derived predicate over shm->plateau_current_
	 * hypothesis (NOT a latched flag); deactivates automatically
	 * when the tick driver writes NONE on plateau clear or when
	 * the classifier transitions to a different hypothesis.
	 *
	 * The counter bump tracks predicate-active picker invocations
	 * (not picks that resolved to an alt-op).  We want to validate
	 * "did the burst predicate fire while childop_dominant was
	 * live?"; the realised alt-op yield can be cross-checked via
	 * the existing childop_invocations[] delta during plateau
	 * windows.
	 */
	if (__atomic_load_n(&shm->plateau_current_hypothesis,
			    __ATOMIC_RELAXED) ==
	    (int)PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT) {
		threshold = 75;
		__atomic_fetch_add(
			&shm->stats.childop.burst_alt_picks_window,
			1UL, __ATOMIC_RELAXED);
	}

	r = rnd_modulo_u32(100);

	if (r < threshold || enabled_altop_count == 0)
		return CHILD_OP_SYSCALL;

	return enabled_altops[rnd_modulo_u32(enabled_altop_count)];
}

