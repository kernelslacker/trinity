/*
 * eBPF program generator for fuzzing the kernel's BPF verifier and JIT.
 *
 * Three tiers of generation:
 *   Tier 1 (valid): Programs the verifier should accept — forward-only jumps,
 *     register liveness, bounded stack access, valid helper calls, proper exit.
 *   Tier 2 (boundary): Programs that probe verifier edge cases — near-limit
 *     complexity, unchecked map lookups, ALU overflow, pointer arithmetic.
 *   Tier 3 (chaos): Random corruption — invalid opcodes, backward jumps,
 *     OOB registers, malformed 128-bit loads.
 */
#include <stdint.h>
#include <linux/bpf.h>

#include "bpf.h"
#include "debug.h"
#include "params.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"	// MAX_LOGLEVEL
#include "utils.h"
#include "rnd.h"

#include "ebpf-internal.h"

#ifdef USE_BPF

/*
 * Map-fd injection probability.  Most generated programs stay scalar-
 * only; this is the chance that any program prepends an LD_MAP_FD
 * loading a real bpf-map fd from trinity's object pool.  Picked low so
 * scalar-only programs still dominate coverage; the tier-2 dedicated
 * map-exercise sub-strategy below forces map-fd loading independently
 * when that coverage path is wanted.  Not env-tunable on purpose; the
 * weight bakes into the build.
 */
#define MAP_FD_WEIGHT_PCT	5

/*
 * Chance that tier 2 forces the dedicated map-exercise sub-strategy,
 * which prepends an LD_MAP_FD regardless of the base rate above.  The
 * arm only fires when get_rand_bpf_fd() returns a live map fd; empty
 * pools fall back to scalar-only generation.
 */
#define TIER2_FORCE_MAP_FD_DENOM	4

/*
 * Decide whether this program should prepend an LD_MAP_FD, and if so
 * pull a live fd from trinity's bpf-map object pool.
 *
 * Returns the fd (>= 0) when substitution should fire, or -1 to skip.
 * Empty pool (get_rand_bpf_fd() == -1) collapses to the skip path so
 * the caller falls back to scalar-only generation for that program.
 *
 * Two independent triggers feed into the substitution decision:
 *   - Base rate: MAP_FD_WEIGHT_PCT chance on every program regardless
 *     of tier, so map-fd loads sprinkle across the whole population.
 *   - Tier 2 dedicated sub-strategy: 1/TIER2_FORCE_MAP_FD_DENOM of
 *     tier 2 programs force substitution to thicken map-path coverage
 *     beyond what the 5% base rate alone produces.
 *
 * Both triggers share the same empty-pool guard, so a build with no
 * maps available silently degrades both paths to scalar-only.
 *
 * Tier 3 is excluded outright: gen_tier3 ignores the prepended map
 * register, so substituting there would burn two instruction slots on
 * a load no generated code ever reads.
 */
static int pick_map_fd_for_program(int tier_id)
{
	bool force = (tier_id == 2 && ONE_IN(TIER2_FORCE_MAP_FD_DENOM));
	bool base = (rnd_modulo_u32(100) < MAP_FD_WEIGHT_PCT);
	int fd;

	if (tier_id == 3)
		return -1;

	if (!force && !base)
		return -1;

	fd = get_rand_bpf_fd();
	if (fd < 0)
		return -1;

	return fd;
}

/*
 * Emit an LD_MAP_FD pseudo-insn pair at the head of the buffer,
 * loading the supplied map fd into a randomly chosen R1-R9 register.
 * Costs 2 slots (BPF_LD | BPF_DW | BPF_IMM is a 128-bit immediate).
 * Caller has already verified the fd is live and the buffer has room.
 *
 * Returns the dst register so the typed-helper emitter can thread it
 * through reg_state and satisfy ARG_MAP_PTR slots without emitting
 * another 2-slot LD_MAP_FD mid-body.
 */
static int emit_ld_map_fd_prologue(struct bpf_insn *insns, int map_fd)
{
	int dst = BPF_REG_1 + rnd_modulo_u32(9);	/* R1..R9 */
	struct bpf_insn pair[] = { EBPF_LD_MAP_FD(dst, map_fd) };

	insns[0] = pair[0];
	insns[1] = pair[1];
	return dst;
}

/*
 * Fill-into-buffer core: pick a tier and emit instructions into a
 * caller-supplied buffer.  The caller owns allocation; we just write.
 *
 * max_insns caps how many slots the buffer can hold.  Each tier's own
 * MAX is further clamped by max_insns so a short buffer cannot overrun.
 * *insn_count is set to the number of instructions actually emitted.
 *
 * Distribution: ~50% Tier 1 (valid), ~25% Tier 2 (boundary),
 * ~25% Tier 3 (chaos).  Two consumers share this core: the live
 * BPF_PROG_LOAD path (via the ebpf_gen_program() allocating wrapper
 * below) and the schema-mutation FT_BPF_PROGRAM tag, which allocates
 * its own sub-buffer and delegates fill here.
 *
 * Programs may optionally prepend an LD_MAP_FD loading a
 * real bpf-map fd from the object pool — see pick_map_fd_for_program()
 * for the trigger rules.  The prepend consumes two slots at the head
 * of the buffer; the chosen tier then fills the remainder via a
 * pointer/length slice, so the tier code stays oblivious to the
 * substitution and the verifier sees a single self-consistent program.
 */
void ebpf_gen_program_into(struct bpf_insn *insns, int max_insns,
			   int *insn_count, unsigned int prog_type)
{
	struct helper_set hs;
	int tier_max, len, tier_id;
	int tier = rnd_modulo_u32(100);
	int prepend = 0;
	int prepend_map_reg = -1;
	int map_fd;

	if (tier < 50) {
		tier_max = TIER1_MAX_INSNS;
		tier_id = 1;
	} else if (tier < 75) {
		tier_max = TIER2_MAX_INSNS;
		tier_id = 2;
	} else {
		tier_max = TIER3_MAX_INSNS;
		tier_id = 3;
	}
	if (tier_max > max_insns)
		tier_max = max_insns;

	/*
	 * Prepend an LD_MAP_FD pair when the substitution decision fires
	 * and the buffer can still fit a meaningful tier body after the
	 * 2-slot reservation.  The lower bound matches TIER3_MIN_INSNS so
	 * even the smallest legal tier has space to emit something.
	 */
	map_fd = pick_map_fd_for_program(tier_id);
	if (map_fd >= 0 && tier_max >= TIER3_MIN_INSNS + 2) {
		prepend_map_reg = emit_ld_map_fd_prologue(insns, map_fd);
		prepend = 2;
		tier_max -= 2;
		__atomic_add_fetch(&shm->stats.ebpf_gen.map_fd_substituted, 1,
				   __ATOMIC_RELAXED);
	}

	hs = get_helpers_for_prog_type(prog_type);

	if (tier_id == 1)
		len = gen_tier1(insns + prepend, tier_max, hs,
				prepend_map_reg);
	else if (tier_id == 2)
		len = gen_tier2(insns + prepend, tier_max, hs,
				prepend_map_reg);
	else
		len = gen_tier3(insns + prepend, tier_max);

	*insn_count = len + prepend;

	if (verbosity >= MAX_LOGLEVEL)
		debugf("ebpf: generated tier %d program, %d insns%s\n",
		       tier_id, *insn_count,
		       prepend ? " (map-fd prepend)" : "");
}

/*
 * Allocating wrapper: hand out a fresh zmalloc_tracked() insn buffer
 * sized for the largest tier and delegate fill to the core.  The post
 * handler in syscalls/bpf.c routes release through deferred_free_enqueue
 * under an alloc_track_lookup() ownership gate -- a shape-only gate on
 * attr->insns lets a sibling-scribbled value that aliases another
 * site's currently-inflight pointer slip through to plain free(), and
 * because plain free() does not update inflight_hash, the original
 * site's later TTL-expiry would re-free the same chunk.  Tracking the
 * allocation here is what lets the post-handler ownership gate prove
 * the pointer is ours before handing it to the deferred-free ring.
 */
struct bpf_insn *ebpf_gen_program(int *insn_count, unsigned int prog_type)
{
	struct bpf_insn *insns;

	insns = zmalloc_tracked(TIER3_MAX_INSNS * sizeof(struct bpf_insn));
	ebpf_gen_program_into(insns, TIER3_MAX_INSNS, insn_count, prog_type);
	return insns;
}

#endif /* USE_BPF */
