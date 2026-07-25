/*
 * Tier 3 chaos generator for the eBPF program generator.
 *
 * Tier 3 (chaos): random corruption — invalid opcodes, backward
 * jumps, OOB registers, malformed 128-bit loads, atomic-imm family
 * probes.  No attempt at validity — pure chaos designed to crash,
 * confuse, or find bugs in the verifier itself.  Split out of
 * net/bpf/ebpf.c as its own translation unit.
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
 * Atomic-op imm encodings (BPF_STX | size | BPF_ATOMIC + imm).  The
 * original chaos generator drew from BPF_ADD..BPF_XOR (× optional
 * BPF_FETCH); extend to the full ISA family so the verifier's atomic
 * arm walks every op, not just the four add-shaped ones.
 *
 *   BPF_ADD/AND/OR/XOR                        — 0x00 base op
 *   BPF_ADD/AND/OR/XOR | BPF_FETCH            — 0x01 fetch variant
 *   BPF_XCHG   = 0xe0 | BPF_FETCH             — atomic exchange
 *   BPF_CMPXCHG= 0xf0 | BPF_FETCH             — compare-and-write
 *   BPF_LOAD_ACQ = 0x100 (v6.15)              — load-acquire
 *   BPF_STORE_REL = 0x110 (v6.15)             — store-release
 */
static const int atomic_imm_ops[] = {
	BPF_ADD,
	BPF_AND,
	BPF_OR,
	BPF_XOR,
	BPF_ADD | BPF_FETCH,
	BPF_AND | BPF_FETCH,
	BPF_OR  | BPF_FETCH,
	BPF_XOR | BPF_FETCH,
	BPF_XCHG,
	BPF_CMPXCHG,
	BPF_LOAD_ACQ,
	BPF_STORE_REL,
};

/*
 * Tier 3: Generate chaotic eBPF programs.
 *
 * These are designed to crash, confuse, or find bugs in the verifier
 * itself. No attempt at validity — pure chaos.
 */
int gen_tier3(struct bpf_insn *insns, int max_insns)
{
	int len;

	if (max_insns <= TIER3_MIN_INSNS)
		len = TIER3_MIN_INSNS;
	else
		len = TIER3_MIN_INSNS + (rnd_modulo_u32(max_insns - TIER3_MIN_INSNS));

	for (int i = 0; i < len - 1; i++) {
		int choice = rnd_modulo_u32(100);

		if (choice < 30) {
			/* Completely random instruction */
			insns[i].code = (uint8_t)rnd_u32();
			insns[i].dst_reg = rnd_modulo_u32(16);
			insns[i].src_reg = rnd_modulo_u32(16);
			insns[i].off = (int16_t)rnd_u32();
			insns[i].imm = (int32_t)rnd_u32();

		} else if (choice < 45) {
			/* Valid opcode but invalid register (>= MAX_BPF_REG) */
			int op = RAND_ARRAY(alu_ops);
			insns[i] = EBPF_ALU64_REG(op, rnd_modulo_u32(16), rnd_modulo_u32(16));

		} else if (choice < 55) {
			/* Backward jump (verifier should reject) */
			int back = -(1 + (rnd_modulo_u32(i + 1)));
			insns[i] = EBPF_JMP_IMM(BPF_JA, 0, 0, back);

		} else if (choice < 65) {
			/* Jump way past end of program */
			insns[i] = EBPF_JMP_IMM(BPF_JA, 0, 0, 1000 + (rnd_modulo_u32(5000)));

		} else if (choice < 72) {
			/* Call non-existent helper */
			insns[i] = EBPF_CALL(EBPF_MAX_HELPER_ID + 1 + (rnd_modulo_u32(1000)));

		} else if (choice < 80) {
			/* OOB stack access */
			int off = -(EBPF_STACK_SIZE + 8 + (rnd_modulo_u32(4096)));
			insns[i] = EBPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, off);

		} else if (choice < 84) {
			/* Load from wild pointer (r0 uninitialized or garbage) */
			insns[i] = EBPF_LDX_MEM(RAND_ARRAY(mem_sizes),
						 rnd_modulo_u32(BPF_REG_10),
						 rnd_modulo_u32(BPF_REG_10),
						 (int16_t)rnd_u32());

		} else if (choice < 88) {
			/* Atomic op with bad src/dst, covering the full
			 * BPF_ADD..BPF_STORE_REL imm family (XCHG /
			 * CMPXCHG / LOAD_ACQ / STORE_REL added) so the
			 * verifier's atomic dispatch walks every arm. */
			insns[i].code = BPF_STX | BPF_DW | BPF_ATOMIC;
			insns[i].dst_reg = rnd_modulo_u32(16);
			insns[i].src_reg = rnd_modulo_u32(16);
			insns[i].off = (int16_t)rnd_u32();
			insns[i].imm = RAND_ARRAY(atomic_imm_ops);

		} else if (choice < 92) {
			/* BPF_MEMSX sign-extending load (mode 0x80).
			 * Kernel accepts BPF_B/H/W sizes; DW is rejected
			 * so the reject arm sees traffic too. */
			int sz_choice = rnd_modulo_u32(4);
			insns[i].code = BPF_LDX | (uint8_t)(sz_choice << 3) | BPF_MEMSX;
			insns[i].dst_reg = rnd_modulo_u32(BPF_REG_10);
			insns[i].src_reg = rnd_modulo_u32(BPF_REG_10);
			insns[i].off = (int16_t)rnd_u32();
			insns[i].imm = 0;

		} else if (choice < 96) {
			/* BPF_JCOND (0xe0): src_reg is the condition
			 * (BPF_MAY_GOTO = 0); off is the branch delta.
			 * Verifier arm gated by prog_may_goto in
			 * kernel/bpf/verifier.c. */
			insns[i].code = BPF_JMP | BPF_JCOND;
			insns[i].dst_reg = 0;
			insns[i].src_reg = BPF_MAY_GOTO;
			insns[i].off = (int16_t)(rnd_modulo_u32(64) - 32);
			insns[i].imm = 0;

		} else {
			/* Malformed 128-bit load: first half only */
			insns[i].code = BPF_LD | BPF_DW | BPF_IMM;
			insns[i].dst_reg = rnd_modulo_u32(BPF_REG_10);
			insns[i].src_reg = rnd_modulo_u32(4);
			insns[i].off = 0;
			insns[i].imm = (int32_t)rnd_u32();
			/* Don't emit the second half — malformed */
		}
	}

	/* Last instruction: sometimes exit, sometimes not */
	if (ONE_IN(3))
		insns[len - 1] = EBPF_EXIT();
	else {
		insns[len - 1].code = (uint8_t)rnd_u32();
		insns[len - 1].dst_reg = rnd_modulo_u32(16);
		insns[len - 1].src_reg = rnd_modulo_u32(16);
		insns[len - 1].off = (int16_t)rnd_u32();
		insns[len - 1].imm = (int32_t)rnd_u32();
	}

	return len;
}

#endif /* USE_BPF */
