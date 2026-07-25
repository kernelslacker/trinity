/*
 * Map-fd substitution and LD_MAP_FD prologue emitter for the eBPF
 * program generator.  Split out of net/bpf/ebpf.c so the substitution
 * decision (which is a small, self-contained policy the tiers do not
 * need to understand) lives alongside the pseudo-insn pair emitter it
 * feeds.
 */
#include <stdint.h>
#include <linux/bpf.h>

#include "bpf.h"
#include "random.h"
#include "rnd.h"

#include "ebpf-internal.h"

#ifdef USE_BPF

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
int pick_map_fd_for_program(int tier_id)
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
int emit_ld_map_fd_prologue(struct bpf_insn *insns, int map_fd)
{
	int dst = BPF_REG_1 + rnd_modulo_u32(9);	/* R1..R9 */
	struct bpf_insn pair[] = { EBPF_LD_MAP_FD(dst, map_fd) };

	insns[0] = pair[0];
	insns[1] = pair[1];
	return dst;
}

#endif /* USE_BPF */
