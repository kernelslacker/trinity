/*
 * Tier 2 boundary-probing sub-strategies and gen_tier2() dispatch for
 * the eBPF program generator.
 *
 * Tier 2 (boundary): structurally valid programs that push verifier
 * limits — spill/fill storms, long ALU chains, jump ladders, mixed
 * ALU32/ALU64, JMP32 variations, and a dedicated helper-call probe.
 * Split out of net/bpf/ebpf.c as its own translation unit; shares the
 * tier1 helper-call and map-value-deref emitters via ebpf-internal.h.
 */
#include <stdint.h>
#include <linux/bpf.h>

#include "bpf.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

#include "ebpf-internal.h"

#ifdef USE_BPF

/*
 * Tier 2: Generate boundary-probing eBPF programs.
 *
 * These programs are structurally valid but push verifier limits:
 * deep jump chains, pointer arithmetic near bounds, unchecked map
 * lookups, ALU ops that overflow, register spill/fill patterns.
 */
/*
 * Spill/fill storm: rapidly store and reload registers
 * from the stack to exercise register allocator paths.
 */
static int gen_tier2_spill_fill(struct bpf_insn *insns, int pos, int body_len,
				struct reg_state *rs)
{
	for (int i = 2; i <= 9 && pos < body_len; i++) {
		insns[pos++] = EBPF_MOV64_IMM(i, rnd_u32());
		reg_set(rs, i);
	}
	while (pos < body_len - 1) {
		int reg = 2 + (rnd_modulo_u32(8));
		int off = rand_stack_offset();
		if (!(rs->live & (1 << reg))) {
			insns[pos++] = EBPF_MOV64_IMM(reg, 0);
			reg_set(rs, reg);
			if (pos >= body_len - 1)
				break;
		}
		insns[pos++] = EBPF_STX_MEM(BPF_DW, BPF_REG_10, reg, off);
		if (pos >= body_len - 1)
			break;
		int dst = 2 + (rnd_modulo_u32(8));
		insns[pos++] = EBPF_LDX_MEM(BPF_DW, dst, BPF_REG_10, off);
		reg_set(rs, dst);
	}
	return pos;
}

/*
 * ALU chain: long sequence of arithmetic to build up
 * complex scalar ranges the verifier must track.
 */
static int gen_tier2_alu_chain(struct bpf_insn *insns, int pos, int body_len,
			       struct reg_state *rs)
{
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_2, 1);
	reg_set(rs, BPF_REG_2);
	while (pos < body_len) {
		int op = RAND_ARRAY(alu_ops);
		int imm;

		if (op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)
			imm = rnd_modulo_u32(64);
		else
			imm = (int)rnd_u32();

		if (ONE_IN(3))
			insns[pos++] = EBPF_ALU64_REG(op, BPF_REG_2, BPF_REG_2);
		else
			insns[pos++] = EBPF_ALU64_IMM(op, BPF_REG_2, imm);
	}
	return pos;
}

/*
 * Jump ladder: chain of forward conditional jumps to
 * exercise verifier's path exploration.
 */
static int gen_tier2_jump_ladder(struct bpf_insn *insns, int pos, int body_len,
				 struct reg_state *rs)
{
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_2, rnd_modulo_u32(1000));
	reg_set(rs, BPF_REG_2);
	while (pos < body_len - 3) {
		int remaining = body_len - pos;
		int skip = 1 + (rnd_modulo_u32(3));
		int op = RAND_ARRAY(jmp_ops);

		if (skip > remaining - 3)
			skip = 1;
		insns[pos++] = EBPF_JMP_IMM(op, BPF_REG_2, rnd_modulo_u32(1000), skip);
		for (int j = 0; j < skip && pos < body_len; j++) {
			insns[pos++] = EBPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1);
		}
	}
	return pos;
}

/*
 * Mixed ALU32/ALU64: interleave 32-bit and 64-bit ops
 * to exercise zero-extension and sign-extension tracking.
 */
static int gen_tier2_mixed_alu(struct bpf_insn *insns, int pos, int body_len,
			       struct reg_state *rs)
{
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_3, 0x7fffffff);
	reg_set(rs, BPF_REG_3);
	while (pos < body_len) {
		if (ONE_IN(2))
			insns[pos++] = EBPF_ALU32_IMM(BPF_ADD, BPF_REG_3,
						      rnd_modulo_u32(256));
		else
			insns[pos++] = EBPF_ALU64_IMM(BPF_ADD, BPF_REG_3,
						      rnd_modulo_u32(256));
	}
	return pos;
}

/*
 * JMP32 variations: exercise 32-bit comparison paths
 * which have separate verifier logic.
 */
static int gen_tier2_jmp32(struct bpf_insn *insns, int pos, int body_len,
			   struct reg_state *rs)
{
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_4, rnd_u32());
	reg_set(rs, BPF_REG_4);
	while (pos < body_len - 2) {
		insns[pos++] = EBPF_JMP32_IMM(RAND_ARRAY(jmp_ops),
					       BPF_REG_4,
					       rnd_modulo_u32(1000), 1);
		insns[pos++] = EBPF_ALU32_IMM(BPF_ADD, BPF_REG_4, 1);
	}
	return pos;
}

/*
 * Dedicated helper-call probe: force at least
 * one arg-bearing helper call so the map/scalar arg paths
 * see traffic outside the tier1 8% lottery.  Filler ALU
 * operates on R6 (callee-saved) so it survives the per-
 * call caller-saved clobber and stays a scalar — using
 * R0 here would mix scalar-returning and pointer-or-null-
 * returning helpers, mostly verifier-rejecting the body.
 * The picker may still bail when no helper in this prog-
 * type's table is satisfiable in the current reg state;
 * the trailing ALU pad keeps body_len intact either way.
 */
static int gen_tier2_helper_call(struct bpf_insn *insns, int pos, int body_len,
				 struct reg_state *rs, struct helper_set hs)
{
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_6, 0);
	reg_set(rs, BPF_REG_6);
	while (pos < body_len) {
		int old_pos = pos;

		pos = emit_tier1_helper_call(insns, pos, body_len, rs, hs);
		if (pos == old_pos)
			break;
		/*
		 * If the call left a PTR_OR_NULL
		 * in R0, roll the deref idiom now -- the next
		 * iteration's helper call will clobber R0 and shut
		 * the window for good.  Same 3% weight as gen_tier1
		 * even though every iteration here can deref; the
		 * lower rate matches the spec's "spread across the
		 * body" intent and keeps the storm filler weight
		 * dominant.
		 */
		if (rs->r0_or_null &&
		    body_len - pos >= 2 &&
		    rnd_modulo_u32(100) < MAP_VAL_DEREF_WEIGHT_PCT)
			pos = emit_tier1_map_val_deref(insns, pos, rs);
		if (pos >= body_len)
			break;
		insns[pos++] = EBPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1);
	}
	while (pos < body_len)
		insns[pos++] = EBPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1);
	return pos;
}

int gen_tier2(struct bpf_insn *insns, int max_insns,
	      struct helper_set hs, int prepend_map_reg)
{
	struct reg_state rs;
	int pos = 0;
	int body_len;
	int strategy = rnd_modulo_u32(TIER2_STRATEGY_COUNT);

	reg_init(&rs, prepend_map_reg);

	/* Always start with r0 = 0 */
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	reg_set(&rs, BPF_REG_0);

	if (max_insns <= TIER2_MIN_INSNS + 2)
		body_len = pos + 1;
	else
		body_len = TIER2_MIN_INSNS + (rnd_modulo_u32(max_insns - TIER2_MIN_INSNS - 2));
	if (body_len > max_insns - 2)
		body_len = max_insns - 2;

	switch (strategy) {
	case 0:
		pos = gen_tier2_spill_fill(insns, pos, body_len, &rs);
		break;
	case 1:
		pos = gen_tier2_alu_chain(insns, pos, body_len, &rs);
		break;
	case 2:
		pos = gen_tier2_jump_ladder(insns, pos, body_len, &rs);
		break;
	case 3:
		pos = gen_tier2_mixed_alu(insns, pos, body_len, &rs);
		break;
	case 4:
		pos = gen_tier2_jmp32(insns, pos, body_len, &rs);
		break;
	case TIER2_STRATEGY_HELPER_CALL:
		pos = gen_tier2_helper_call(insns, pos, body_len, &rs, hs);
		break;
	}

	/* Epilogue */
	if (!(rs.live & (1 << BPF_REG_0)))
		insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	insns[pos++] = EBPF_EXIT();

	return pos;
}

#endif /* USE_BPF */
