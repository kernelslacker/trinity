/*
 * Startup and respawn side of the dormant-childop canary queue:
 * canary_queue_init() builds the priority list and stages the first
 * canary; canary_queue_on_child_respawn() is the second stage of the
 * two-stage commit that flips canary_active_op_cell (see
 * child-canary-internal.h).
 */
#include <stdbool.h>
#include <string.h>

#include "child.h"
#include "child-canary-internal.h"
#include "params.h"
#include "trinity.h"
#include "utils.h"

/* Backing storage for the default priority list: a per-epoch random
 * permutation of every canary-eligible op, rebuilt on each
 * canary_queue_init().  Replaces the old static priority-seed list so
 * the first-pass evaluation order differs every run and no hand-kept
 * list can go stale.  --canary-seed overrides this via
 * canary_seed_override_widened[] instead. */
static enum child_op_type canary_priority_shuffle[NR_CHILD_OP_TYPES];

void canary_queue_init(void)
{
	unsigned int i;
	enum child_op_type seed;
	unsigned int dormant_eligible = 0;
	unsigned int config_blocked = 0;

	memset(canary_ops, 0, sizeof(canary_ops));
	memset(canary_op_setup_broken, 0, sizeof(canary_op_setup_broken));
	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		canary_ops[i].op = (enum child_op_type)i;
		canary_ops[i].name = alt_op_name((enum child_op_type)i);
		canary_ops[i].state = CANARY_STATE_DORMANT;
	}

	/* CONFIG_BLOCKED set: terminal, never picked.  Also stamp the
	 * static reason hint so the startup enumeration and any later
	 * canary_queue_summary() consumer can report a label instead of
	 * a bare "config-blocked" state. */
	for (i = 0; i < canary_config_blocked_count; i++) {
		enum child_op_type op = canary_config_blocked[i];
		if (op < NR_CHILD_OP_TYPES) {
			canary_ops[op].state = CANARY_STATE_CONFIG_BLOCKED;
			canary_ops[op].blocked_reason =
				CANARY_BLOCKED_REASON_CONFIG_ABSENT;
			canary_ops[op].setup_fail_reason =
				canary_setup_fail_reason_for_op(op);
		}
	}

	/* Risky-defer set: stay DORMANT but the picker skips them via
	 * the phase1_ineligible flag.  These ops need isolation that the
	 * queue does not provide. */
	for (i = 0; i < canary_risky_defer_count; i++) {
		enum child_op_type op = canary_risky_defer[i];
		if (op < NR_CHILD_OP_TYPES)
			canary_ops[op].phase1_ineligible = true;
	}

	/* Synthetic PROMOTED state for every op currently active in the
	 * dormant gate, so the queue's summary count agrees with reality
	 * at t=0.  CHILD_OP_SYSCALL is not an alt-op and is skipped. */
	for (i = (unsigned int)CHILD_OP_SYSCALL + 1; i < NR_CHILD_OP_TYPES; i++) {
		if (dormant_op_is_active((enum child_op_type)i)) {
			canary_ops[i].state = CANARY_STATE_PROMOTED;
			canary_ops[i].total_promotions = 1;
		}
	}

	/* Counters for the startup banner. */
	for (i = (unsigned int)CHILD_OP_SYSCALL + 1; i < NR_CHILD_OP_TYPES; i++) {
		switch (canary_ops[i].state) {
		case CANARY_STATE_CONFIG_BLOCKED:
			config_blocked++;
			break;
		case CANARY_STATE_DORMANT:
			if (!canary_ops[i].phase1_ineligible)
				dormant_eligible++;
			break;
		default:
			break;
		}
	}

	/* Priority list: operator override if --canary-seed was passed,
	 * otherwise a fresh random permutation of every eligible op so
	 * each run evaluates a different first-pass order. */
	if (canary_seed_override_count > 0) {
		for (i = 0; i < canary_seed_override_count; i++)
			canary_seed_override_widened[i] =
				(enum child_op_type)canary_seed_override[i];
		canary_priority_list = canary_seed_override_widened;
		canary_priority_list_count = canary_seed_override_count;
	} else {
		unsigned int n = 0, k;

		/* Collect the ops the picker would actually consider --
		 * skip SYSCALL, config-blocked terminals, risky-defer and
		 * already-active (PROMOTED) ops -- then Fisher-Yates the
		 * set into a uniform permutation. */
		for (i = (unsigned int)CHILD_OP_SYSCALL + 1;
		     i < NR_CHILD_OP_TYPES; i++) {
			if (canary_ops[i].state == CANARY_STATE_CONFIG_BLOCKED)
				continue;
			if (canary_ops[i].phase1_ineligible)
				continue;
			if (canary_ops[i].state == CANARY_STATE_PROMOTED)
				continue;
			canary_priority_shuffle[n++] = (enum child_op_type)i;
		}
		for (k = n; k > 1; k--) {
			unsigned int j = rnd_modulo_u32(k);
			enum child_op_type tmp =
				canary_priority_shuffle[k - 1];
			canary_priority_shuffle[k - 1] =
				canary_priority_shuffle[j];
			canary_priority_shuffle[j] = tmp;
		}
		canary_priority_list = canary_priority_shuffle;
		canary_priority_list_count = n;
	}

	canary_priority_cursor = 0;
	canary_fifo_cursor = CHILD_OP_SYSCALL;
	canary_active_op_cell = CHILD_OP_SYSCALL;
	canary_pending_op = CHILD_OP_SYSCALL;
	canary_active_op_set = false;
	canary_pending_op_set = false;
	canary_slots_parked = false;
	canary_promotion_ring_count = 0;
	canary_promotion_ring_head = 0;
	canary_last_summary = monotonic_seconds();
	canary_last_plateau = false;

	/* Gate the live state on the operator flags AND on having at
	 * least one slot to canary on.  Both kill switches map to the
	 * same disabled-no-op behaviour.
	 *
	 * -c <syscall>, -r <num>, and -g <group> scope the run to a
	 * specific syscall set for isolation / bisection.  The canary
	 * queue would otherwise stage dormant alt-op childops onto its
	 * dedicated slots and execute them (entering canarying windows
	 * and promoting/demoting based on edges/crashes), bypassing the
	 * syscall-table gate exactly like the picker-leak and
	 * periodic-work paths that the child_process() / periodic_work()
	 * gates already cover.  Stay dormant so the targeted-syscall
	 * signal is not contaminated by canary-discovered edges / crashes
	 * getting mis-credited to the target syscall. */
	canary_queue_live = (!canary_queue_disabled) && (canary_slots > 0) &&
		!do_specific_syscall && !random_selection &&
		desired_group == GROUP_NONE;

	if (!canary_queue_live) {
		if (canary_queue_disabled) {
			output(0, "canary queue: disabled (--no-canary-queue); dormant_op_disabled[] used as static gate\n");
		} else if (do_specific_syscall || random_selection ||
			   desired_group != GROUP_NONE) {
			output(0, "canary queue: disabled (targeted-syscall mode -c/-r/-g); dormant_op_disabled[] used as static gate\n");
		} else {
			/* canary_slots == 0 -- either explicit
			 * --canary-slots=0 or alt_op_children=0 collapsed
			 * the auto-derived value to zero.  The boot log
			 * above this line shows which. */
			output(0, "canary queue: disabled (canary_slots=0); dormant_op_disabled[] used as static gate\n");
		}
		return;
	}

	output(0, "canary queue: enabled, slots=%u, window=%u iters, priority_ops=%u, dormant_eligible=%u, config_blocked=%u\n",
		canary_slots, window_iters_resolved(),
		canary_priority_list_count, dormant_eligible, config_blocked);

	/* Startup CONFIG_BLOCKED table: enumerate each blocked op with the
	 * missing host-feature reason so an operator reading the boot log
	 * can tell which host features are absent without cross-
	 * referencing the hint table in source.  Emitted only in enabled
	 * mode -- the disabled bailout above already says the static gate
	 * is in use, and per-op detail is not actionable there. */
	for (i = (unsigned int)CHILD_OP_SYSCALL + 1; i < NR_CHILD_OP_TYPES; i++) {
		if (canary_ops[i].state != CANARY_STATE_CONFIG_BLOCKED)
			continue;
		output(0, "canary queue: config-blocked op %s (subreason: %s, hint: %s)\n",
			canary_ops[i].name,
			canary_blocked_reason_name(
				canary_ops[i].blocked_reason),
			canary_setup_fail_reason_name(
				canary_ops[i].setup_fail_reason));
	}

	/* Pick the first op and enter CANARYING immediately so the
	 * fleet starts working it as soon as fork_children() runs. */
	if (pick_next_canary(&seed))
		enter_canarying(seed);

	/* Silence compiler about input tables when build configs avoid
	 * the picker (none today, but keeps the warning surface clean). */
	(void)canary_config_blocked;
	(void)canary_risky_defer;
}

void canary_queue_on_child_respawn(int childno)
{
	if (!canary_queue_live)
		return;
	if (canary_slots == 0 || childno < 0)
		return;
	if ((unsigned int)childno >= canary_slots)
		return;
	if (!canary_pending_op_set)
		return;

	/* Commit the staged op as the active op.  The two-stage commit
	 * means the new op only becomes the slot's running op once a
	 * child has actually been forked with it stamped -- straggler
	 * iterations of the OLD op (the previous canary, asked to die
	 * via kill_pid) do not pollute the new op's counters.
	 *
	 * The caller (spawn_child) invokes us BEFORE
	 * assign_dedicated_alt_op() so the dedicated stamp sees the
	 * just-committed active op rather than the previous canary; if
	 * we committed after the stamp, the freshly-spawned child would
	 * have the old op stamped while the queue tracked the new op.
	 *
	 * Clear canary_pending_op_set once committed so that stale
	 * pending state cannot influence later canary_active_op() reads
	 * (e.g. the picker-exhausted path in canary_queue_tick() then
	 * sees a clean slate). */
	canary_active_op_cell = canary_pending_op;
	canary_active_op_set = true;
	canary_pending_op_set = false;
}
