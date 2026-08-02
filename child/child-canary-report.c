/*
 * child-canary-report.c -- Reporting, per-tick summaries, and public
 * queries into the dormant-childop canary queue's active op.
 *
 * Owns:
 *   - the recently-promoted ring rendered by the 60-s summary line,
 *   - the summary's own throttle timestamp,
 *   - the crash-and-respawn observation surface (canary_queue_on_crash),
 *   - the read-only public queries (canary_slot_active, canary_active_op,
 *     canary_op_is_promoted) that live-time consumers (spawn_child,
 *     assign_dedicated_alt_op) call on every fork.
 *
 * State transitions (enter / leave / commit-respawn) live in
 * child-canary-state.c; this TU only observes.
 */
#include <dlfcn.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "child-api.h"
#include "child-canary-internal.h"
#include "child.h"
#include "params.h"
#include "pc_format.h"
#include "shm.h"
#include "trinity.h"

/* Queue-summary cadence (60 s; spec verbatim).  Per-window-progress
 * lines are emitted from the ~1 s tick path with no extra rate-limit
 * (one line per tick while CANARYING). */
#define CANARY_SUMMARY_INTERVAL_SEC	60

/* Recently-promoted op names, ring of last CANARY_PROMOTION_RING_SIZE
 * entries.  Rendered by the 60-s summary line when at least one
 * promotion has occurred. */
enum child_op_type canary_promotion_ring[CANARY_PROMOTION_RING_SIZE];
unsigned int canary_promotion_ring_count = 0;
unsigned int canary_promotion_ring_head = 0;

/* Cached time of last summary emit; the summary self-rate-limits. */
time_t canary_last_summary = 0;

void push_promotion(enum child_op_type op)
{
	canary_promotion_ring[canary_promotion_ring_head] = op;
	canary_promotion_ring_head =
		(canary_promotion_ring_head + 1) % CANARY_PROMOTION_RING_SIZE;
	if (canary_promotion_ring_count < CANARY_PROMOTION_RING_SIZE)
		canary_promotion_ring_count++;
}

void canary_queue_summary(void)
{
	unsigned int dormant = 0, canarying = 0, promoted = 0;
	unsigned int demoted = 0, blocked = 0;
	unsigned int blocked_config = 0, blocked_broken = 0, blocked_nobracket = 0;
	unsigned int total = 0;
	unsigned int i;
	time_t now;

	if (!canary_queue_live)
		return;

	now = monotonic_seconds();
	if (now - canary_last_summary < CANARY_SUMMARY_INTERVAL_SEC)
		return;
	canary_last_summary = now;

	for (i = (unsigned int)CHILD_OP_SYSCALL + 1; i < NR_CHILD_OP_TYPES; i++) {
		total++;
		switch (canary_ops[i].state) {
		case CANARY_STATE_DORMANT:		dormant++; break;
		case CANARY_STATE_CANARYING:		canarying++; break;
		case CANARY_STATE_PROMOTED:		promoted++; break;
		case CANARY_STATE_DEMOTED:		demoted++; break;
		case CANARY_STATE_CONFIG_BLOCKED:
			blocked++;
			switch (canary_ops[i].blocked_reason) {
			case CANARY_BLOCKED_REASON_CONFIG_ABSENT:
				blocked_config++; break;
			case CANARY_BLOCKED_REASON_SETUP_BROKEN:
				blocked_broken++; break;
			case CANARY_BLOCKED_REASON_NO_OUTER_BRACKET:
				blocked_nobracket++; break;
			case CANARY_BLOCKED_REASON_NONE:
				/* Should never happen -- every CONFIG_BLOCKED
				 * assignment sets a reason.  Fall through so an
				 * unset field still counts in the total blocked
				 * tally, just not in any subreason bucket. */
				break;
			}
			break;
		}
	}

	output(0, "canary queue: %u dormant, %u canarying, %u promoted, %u demoted, %u config-blocked [config-absent=%u setup-broken=%u no-outer-bracket=%u] (total=%u)\n",
		dormant, canarying, promoted, demoted, blocked,
		blocked_config, blocked_broken, blocked_nobracket, total);

	/* When the fleet has any non-dedicated random children (i.e.
	 * max_children > alt_op_children), those children's snapshots
	 * of the dormant gate are fork-time COW copies and do not pick
	 * up promotion/demotion until they respawn.  Flag it in the
	 * periodic summary so the operator can read the queue state
	 * without assuming instant propagation. */
	if (max_children > alt_op_children)
		output(0, "canary queue: state propagates on respawn (non-dedicated random children carry fork-time gate snapshots)\n");

	if (canary_promotion_ring_count > 0) {
		char buf[512];
		size_t off = 0;
		unsigned int j, start;

		start = (canary_promotion_ring_head +
			 CANARY_PROMOTION_RING_SIZE -
			 canary_promotion_ring_count) %
			CANARY_PROMOTION_RING_SIZE;
		for (j = 0; j < canary_promotion_ring_count; j++) {
			enum child_op_type op =
				canary_promotion_ring[(start + j) %
						      CANARY_PROMOTION_RING_SIZE];
			int n = snprintf(buf + off, sizeof(buf) - off,
				"%s%s", off ? ", " : "", alt_op_name(op));
			if (n <= 0 || (size_t)n >= sizeof(buf) - off)
				break;
			off += (size_t)n;
		}
		output(0, "canary queue: last %u promotions: %s\n",
			canary_promotion_ring_count, buf);
	}
}

/*
 * Round a captured PC to the base of the enclosing function so two crashes
 * that land two instructions apart in the same function collapse into one
 * signature bucket rather than two, but crashes in distinct functions stay
 * distinct.  dladdr()'s dli_saddr is the address of the nearest enclosing
 * symbol; when it misses (PC outside any known object, or an inlined helper
 * with no exported symbol), fall back to the raw PC so the signature key is
 * still stable across identical crashes.  Parent context, no signal-safety
 * constraint here -- the beacon was stamped async-signal-safe in the child,
 * we just consume it. */
static void *normalize_fault_ip(void *pc)
{
	Dl_info info;

	if (pc == NULL)
		return NULL;
	if (dladdr(pc, &info) != 0 && info.dli_saddr != NULL)
		return info.dli_saddr;
	return pc;
}

/*
 * Fold one just-observed crash into canary_ops[op].window_crash_sigs[].  Key
 * is {signo, sig_code, normalized fault_ip}: distinct kernel-vs-userspace-
 * sourced SIGSEGVs (SEGV_MAPERR/si_code=1 vs SEGV_ACCERR/si_code=2 vs
 * user-sent si_code<=0) and crashes at different PCs land in separate
 * buckets so the per-window log line can render "17 SIGSEGV/code=2 + 13
 * SIGSEGV/code=1 + 3 SIGSEGV/code=128" rather than collapsing all three
 * shapes into a single 33-count row.
 *
 * On table full, distinct signatures beyond ARRAY_SIZE(window_crash_sigs)
 * are counted in window_crash_sigs_overflow so the render helper can
 * disclose the drop rather than silently masking it.  This is REPORTING
 * FIDELITY ONLY: the demote-threshold decision still keys off the scalar
 * window_crashes total bumped by the caller.
 */
static void canary_crash_sig_fold(enum child_op_type op, int32_t signo,
				  int32_t sig_code, void *fault_ip)
{
	struct canary_op_state *s = &canary_ops[op];
	void *ip_norm = normalize_fault_ip(fault_ip);
	unsigned int i;

	for (i = 0; i < s->window_crash_sigs_count; i++) {
		if (s->window_crash_sigs[i].signo == signo &&
		    s->window_crash_sigs[i].sig_code == sig_code &&
		    s->window_crash_sigs[i].fault_ip_norm == ip_norm) {
			s->window_crash_sigs[i].count++;
			return;
		}
	}

	if (s->window_crash_sigs_count >=
	    sizeof(s->window_crash_sigs) / sizeof(s->window_crash_sigs[0])) {
		s->window_crash_sigs_overflow++;
		return;
	}

	i = s->window_crash_sigs_count++;
	s->window_crash_sigs[i].signo = signo;
	s->window_crash_sigs[i].sig_code = sig_code;
	s->window_crash_sigs[i].fault_ip_norm = ip_norm;
	s->window_crash_sigs[i].count = 1;
}

static const char *signame_short(int32_t signo)
{
	switch (signo) {
	case SIGSEGV:	return "SIGSEGV";
	case SIGBUS:	return "SIGBUS";
	case SIGILL:	return "SIGILL";
	case SIGABRT:	return "SIGABRT";
	default:	return "SIG?";
	}
}

const char *canary_crash_sig_render(enum child_op_type op, char *buf, size_t buflen)
{
	struct canary_op_state *s;
	size_t off = 0;
	unsigned int i;

	if (buf == NULL || buflen == 0)
		return buf;
	buf[0] = '\0';
	if ((unsigned int)op >= NR_CHILD_OP_TYPES)
		return buf;

	s = &canary_ops[op];
	if (s->window_crash_sigs_count == 0 && s->window_crash_sigs_overflow == 0)
		return buf;

	for (i = 0; i < s->window_crash_sigs_count; i++) {
		char pcbuf[96];
		int n;

		(void)pc_to_string(s->window_crash_sigs[i].fault_ip_norm,
				   pcbuf, sizeof(pcbuf));
		n = snprintf(buf + off, buflen - off,
			     "%sx%u/%s/code=%d/pc=%s",
			     off ? " " : "",
			     s->window_crash_sigs[i].count,
			     signame_short(s->window_crash_sigs[i].signo),
			     (int)s->window_crash_sigs[i].sig_code,
			     pcbuf);
		if (n <= 0 || (size_t)n >= buflen - off)
			break;
		off += (size_t)n;
	}

	if (s->window_crash_sigs_overflow > 0) {
		int n = snprintf(buf + off, buflen - off, "%s+%u overflow",
				 off ? " " : "",
				 s->window_crash_sigs_overflow);
		if (n > 0 && (size_t)n < buflen - off)
			off += (size_t)n;
	}

	return buf;
}

void canary_queue_on_crash(int childno, int signo)
{
	enum child_op_type op;
	struct childdata *child;
	struct child_fault_beacon *beacon;
	int32_t sig_code = 0;
	void *fault_ip = NULL;

	if (!canary_queue_live)
		return;
	if (canary_slots == 0 || childno < 0)
		return;
	if ((unsigned int)childno >= canary_slots)
		return;
	if (signo != SIGSEGV && signo != SIGBUS &&
	    signo != SIGILL && signo != SIGABRT)
		return;

	/* The op identity is read from the dying child's slot.  In a
	 * canary slot, child->op_type is the op the parent stamped in
	 * assign_dedicated_alt_op() at fork time.  Children are not
	 * supposed to mutate it for canary slots (use_dedicated_op is
	 * true there and pick_op_type() is skipped).  Defensive: skip
	 * crashes where the op is not the active canary op (e.g. the
	 * crash landed on the pre-transition op before the kill_pid
	 * respawn took). */
	if (!canary_active_op_set)
		return;
	op = canary_active_op_cell;
	if (op >= NR_CHILD_OP_TYPES)
		return;
	if (canary_ops[op].state != CANARY_STATE_CANARYING)
		return;
	if (children == NULL || children[childno] == NULL)
		return;
	child = children[childno];
	if (child->op_type != op)
		return;

	canary_ops[op].window_crashes++;

	/* Extended reporting: pull sig_code and fault_ip out of the child's
	 * signal-time fault beacon and fold them into the per-signature
	 * table so the demote/promote log line can break the count down by
	 * distinct crash shape.  Acquire-load on .written pairs with the
	 * child_fault_handler release-store so the other beacon fields are
	 * observed post-stamp, not torn.  A zero .written means the child
	 * died before reaching the beacon stamp (e.g. SIGKILL from parent,
	 * or a re-fault inside the handler before the store landed); in
	 * that case we fall back to signal-only bucketing (sig_code=0,
	 * fault_ip=NULL) so the crash still shows up in the breakdown
	 * rather than silently dropping. */
	beacon = &child->fault_beacon;
	if (__atomic_load_n(&beacon->written, __ATOMIC_ACQUIRE) != 0U) {
		sig_code = beacon->sig_code;
		fault_ip = beacon->fault_ip;
	}
	canary_crash_sig_fold(op, (int32_t)signo, sig_code, fault_ip);
}

bool canary_slot_active(int childno)
{
	if (!canary_queue_live)
		return false;
	if (canary_slots == 0 || childno < 0)
		return false;
	if ((unsigned int)childno >= canary_slots)
		return false;
	/* Before the first canary respawn lands we have no committed
	 * op yet -- stamp the pending op so the first fork picks up
	 * the queue's first pick rather than starting on a stale
	 * alt_op_rotation[] entry.  After that, the active cell is
	 * the source of truth.  When parked (picker exhausted), still
	 * claim the slot so the canary branch of assign_dedicated_alt_op
	 * runs and canary_active_op() returns CHILD_OP_SYSCALL --
	 * otherwise the slot would fall back to alt_op_rotation[] and
	 * pick up an arbitrary alt-op instead of the inert default. */
	return canary_active_op_set || canary_pending_op_set ||
	       canary_slots_parked;
}

enum child_op_type canary_active_op(void)
{
	if (canary_active_op_set)
		return canary_active_op_cell;
	if (canary_pending_op_set)
		return canary_pending_op;
	/* Parked: stamp the slot with the default syscall op so the
	 * child runs the normal pick_op_type() path until the queue
	 * stages a new pending op. */
	return CHILD_OP_SYSCALL;
}

bool canary_op_is_promoted(enum child_op_type op)
{
	if (!canary_queue_live)
		return false;
	if ((unsigned int)op >= NR_CHILD_OP_TYPES)
		return false;
	return canary_ops[op].state == CANARY_STATE_PROMOTED;
}
