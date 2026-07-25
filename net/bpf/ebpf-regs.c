/*
 * Register liveness helpers and stack-offset picker for the eBPF
 * program generator.  Split out of net/bpf/ebpf.c so tier1/tier2
 * emitters can share this liveness bookkeeping without hauling in the
 * whole generator TU.
 */
#include <stdint.h>
#include <linux/bpf.h>

#include "bpf.h"
#include "random.h"
#include "rnd.h"

#include "ebpf-internal.h"

#ifdef USE_BPF

void reg_init(struct reg_state *rs, int prepend_map_reg)
{
	/* r1 = context pointer, r10 = frame pointer (read-only) */
	rs->live = (1 << BPF_REG_1) | (1 << BPF_REG_10);
	rs->map_reg = -1;
	rs->r0_or_null = false;
	rs->r0_writable = false;
	if (prepend_map_reg >= 0) {
		rs->live |= (1 << prepend_map_reg);
		rs->map_reg = prepend_map_reg;
	}
}

void reg_set(struct reg_state *rs, int reg)
{
	rs->live |= (1 << reg);
	/* Overwriting the tracked map reg drops the PTR_TO_MAP tag. */
	if (reg == rs->map_reg)
		rs->map_reg = -1;
	/* Any write to R0 invalidates the or-null marker. */
	if (reg == BPF_REG_0) {
		rs->r0_or_null = false;
		rs->r0_writable = false;
	}
}

void reg_clear_caller_saved(struct reg_state *rs)
{
	/* After a call, r0 has the return value, r1-r5 are clobbered */
	rs->live &= ~((1 << BPF_REG_1) | (1 << BPF_REG_2) |
		       (1 << BPF_REG_3) | (1 << BPF_REG_4) |
		       (1 << BPF_REG_5));
	rs->live |= (1 << BPF_REG_0);
	if (rs->map_reg >= BPF_REG_1 && rs->map_reg <= BPF_REG_5)
		rs->map_reg = -1;
	/* Caller re-arms r0_or_null for or-null-returning helpers. */
	rs->r0_or_null = false;
	rs->r0_writable = false;
}

int reg_pick_live(struct reg_state *rs)
{
	int candidates[MAX_BPF_REG];
	int n = 0;

	for (int i = 0; i < BPF_REG_10; i++) {
		if (rs->live & (1 << i))
			candidates[n++] = i;
	}
	if (n == 0)
		return BPF_REG_1;	/* shouldn't happen, but safe fallback */
	return candidates[rnd_modulo_u32(n)];
}

/* Pick a writable destination register (r0-r9, not r10) */
int reg_pick_dst(void)
{
	return rnd_modulo_u32(BPF_REG_10);
}

/* Random stack offset, 8-byte aligned, negative from r10 */
int rand_stack_offset(void)
{
	int slot = (rnd_modulo_u32(EBPF_STACK_SLOTS)) + 1;
	return -(slot * 8);
}

#endif /* USE_BPF */
