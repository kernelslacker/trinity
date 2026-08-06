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
 * site's tracked pointer slip through to plain free(), racing the
 * original site's TTL-expiry drain and double-freeing the chunk.  Tracking the
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
