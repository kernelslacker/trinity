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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <linux/bpf.h>

#include "bpf.h"
#include "debug.h"
#include "params.h"
#include "random.h"
#include "trinity.h"	// MAX_LOGLEVEL
#include "utils.h"

#ifdef USE_BPF

/* Stack frame: 512 bytes max, 8-byte aligned slots */
#define EBPF_STACK_SIZE		512
#define EBPF_STACK_SLOTS	(EBPF_STACK_SIZE / 8)

/* Program size limits */
#define TIER1_MIN_INSNS		5
#define TIER1_MAX_INSNS		64
#define TIER2_MIN_INSNS		16
#define TIER2_MAX_INSNS		256
#define TIER3_MIN_INSNS		2
#define TIER3_MAX_INSNS		512

/*
 * Per-prog-type helper function tables.
 *
 * Only helpers that need zero arguments or simple scalar args are
 * included — calling helpers that require specific pointer types
 * (map values, skb pointers, etc.) without proper setup would just
 * get rejected by the verifier anyway.
 */
static const int helpers_universal[] = {
	BPF_FUNC_ktime_get_ns,
	BPF_FUNC_get_prandom_u32,
	BPF_FUNC_get_smp_processor_id,
	BPF_FUNC_get_current_pid_tgid,
	BPF_FUNC_get_current_uid_gid,
	BPF_FUNC_get_numa_node_id,
	BPF_FUNC_ktime_get_boot_ns,
	BPF_FUNC_ktime_get_coarse_ns,
	BPF_FUNC_jiffies64,
	BPF_FUNC_ktime_get_tai_ns,
};

/* Tracing types: kprobe, tracepoint, perf_event, raw_tracepoint */
static const int helpers_tracing[] = {
	BPF_FUNC_ktime_get_ns,
	BPF_FUNC_get_prandom_u32,
	BPF_FUNC_get_smp_processor_id,
	BPF_FUNC_get_current_pid_tgid,
	BPF_FUNC_get_current_uid_gid,
	BPF_FUNC_get_numa_node_id,
	BPF_FUNC_ktime_get_boot_ns,
	BPF_FUNC_get_current_task,
	BPF_FUNC_get_current_cgroup_id,
	BPF_FUNC_get_func_ip,
};

/* Networking types: socket_filter, sched_cls, sched_act, xdp, lwt, etc. */
static const int helpers_networking[] = {
	BPF_FUNC_ktime_get_ns,
	BPF_FUNC_get_prandom_u32,
	BPF_FUNC_get_smp_processor_id,
	BPF_FUNC_get_current_pid_tgid,
	BPF_FUNC_get_current_uid_gid,
	BPF_FUNC_get_numa_node_id,
	BPF_FUNC_ktime_get_boot_ns,
	BPF_FUNC_get_hash_recalc,
	BPF_FUNC_get_route_realm,
	BPF_FUNC_csum_update,
};

/* Cgroup types */
static const int helpers_cgroup[] = {
	BPF_FUNC_ktime_get_ns,
	BPF_FUNC_get_prandom_u32,
	BPF_FUNC_get_smp_processor_id,
	BPF_FUNC_get_current_pid_tgid,
	BPF_FUNC_get_current_uid_gid,
	BPF_FUNC_get_numa_node_id,
	BPF_FUNC_ktime_get_boot_ns,
	BPF_FUNC_get_current_cgroup_id,
	BPF_FUNC_get_local_storage,
};

struct helper_set {
	const int *helpers;
	int count;
};

#define HELPER_SET(arr) { .helpers = (arr), .count = ARRAY_SIZE(arr) }

static struct helper_set get_helpers_for_prog_type(unsigned int prog_type)
{
	switch (prog_type) {
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_LSM:
		return (struct helper_set) HELPER_SET(helpers_tracing);

	case BPF_PROG_TYPE_SOCKET_FILTER:
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
	case BPF_PROG_TYPE_XDP:
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_XMIT:
	case BPF_PROG_TYPE_LWT_SEG6LOCAL:
	case BPF_PROG_TYPE_SK_SKB:
	case BPF_PROG_TYPE_SK_MSG:
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
	case BPF_PROG_TYPE_SK_REUSEPORT:
	case BPF_PROG_TYPE_SK_LOOKUP:
	case BPF_PROG_TYPE_NETFILTER:
	case BPF_PROG_TYPE_SOCK_OPS:
		return (struct helper_set) HELPER_SET(helpers_networking);

	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		return (struct helper_set) HELPER_SET(helpers_cgroup);

	default:
		return (struct helper_set) HELPER_SET(helpers_universal);
	}
}

/*
 * Register liveness bitmap. Tracks which registers hold known-valid values
 * so we only read from initialized registers.
 */
struct reg_state {
	uint16_t live;		/* bitmask: 1 << reg if initialized */
};

static void reg_init(struct reg_state *rs)
{
	/* r1 = context pointer, r10 = frame pointer (read-only) */
	rs->live = (1 << BPF_REG_1) | (1 << BPF_REG_10);
}

static void reg_set(struct reg_state *rs, int reg)
{
	rs->live |= (1 << reg);
}

static void reg_clear_caller_saved(struct reg_state *rs)
{
	/* After a call, r0 has the return value, r1-r5 are clobbered */
	rs->live &= ~((1 << BPF_REG_1) | (1 << BPF_REG_2) |
		       (1 << BPF_REG_3) | (1 << BPF_REG_4) |
		       (1 << BPF_REG_5));
	rs->live |= (1 << BPF_REG_0);
}

static int reg_pick_live(struct reg_state *rs)
{
	int candidates[MAX_BPF_REG];
	int n = 0;

	for (int i = 0; i < BPF_REG_10; i++) {
		if (rs->live & (1 << i))
			candidates[n++] = i;
	}
	if (n == 0)
		return BPF_REG_1;	/* shouldn't happen, but safe fallback */
	return candidates[rand() % n];
}

/* Pick a writable destination register (r0-r9, not r10) */
static int reg_pick_dst(void)
{
	return rand() % BPF_REG_10;
}

/* Random stack offset, 8-byte aligned, negative from r10 */
static int rand_stack_offset(void)
{
	int slot = (rand() % EBPF_STACK_SLOTS) + 1;
	return -(slot * 8);
}

/* ALU ops safe for the verifier (no div/mod by potential zero from reg) */
static const int alu_ops[] = {
	BPF_ADD, BPF_SUB, BPF_MUL, BPF_OR, BPF_AND,
	BPF_LSH, BPF_RSH, BPF_XOR, BPF_MOV, BPF_ARSH,
};

/* Jump comparison ops (used with forward-only offsets) */
static const int jmp_ops[] = {
	BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET, BPF_JNE,
	BPF_JSGT, BPF_JSGE, BPF_JLT, BPF_JLE, BPF_JSLT, BPF_JSLE,
};

/* Memory access sizes */
static const int mem_sizes[] = { BPF_B, BPF_H, BPF_W, BPF_DW };

/*
 * Tier 1: Generate a valid eBPF program.
 *
 * Strategy: emit a sequence of random operations that the verifier can
 * statically validate. All jumps are forward-only, all register reads
 * come from initialized registers, stack access is bounded.
 */
static int gen_tier1(struct bpf_insn *insns, int max_insns,
		     struct helper_set hs)
{
	struct reg_state rs;
	int pos = 0;
	int body_len;

	reg_init(&rs);

	/* Prologue: r0 = 0 (safe default return value) */
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	reg_set(&rs, BPF_REG_0);

	/* Initialize a few registers with small constants for variety */
	if (ONE_IN(2)) {
		int reg = 2 + (rand() % 4);	/* r2-r5 */
		insns[pos++] = EBPF_MOV64_IMM(reg, rand() % 256);
		reg_set(&rs, reg);
	}

	/* Body: random operations */
	body_len = TIER1_MIN_INSNS + (rand() % (max_insns - TIER1_MIN_INSNS - 2));
	if (body_len > max_insns - 2)
		body_len = max_insns - 2;

	while (pos < body_len) {
		int remaining = body_len - pos;
		int choice = rand() % 100;

		if (choice < 40) {
			/* ALU64 with immediate */
			int dst = reg_pick_dst();
			int op = RAND_ARRAY(alu_ops);
			int imm = (int)(rand() % 65536) - 32768;

			/* MOV always initializes, others need dst to be live */
			if (op != BPF_MOV && !(rs.live & (1 << dst))) {
				insns[pos++] = EBPF_MOV64_IMM(dst, rand() % 100);
				reg_set(&rs, dst);
				if (pos >= body_len)
					break;
			}
			/* Avoid shift by >= 64 */
			if (op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)
				imm = rand() % 64;
			insns[pos++] = EBPF_ALU64_IMM(op, dst, imm);
			reg_set(&rs, dst);

		} else if (choice < 55) {
			/* ALU64 reg-to-reg */
			int dst = reg_pick_dst();
			int src = reg_pick_live(&rs);
			int op = RAND_ARRAY(alu_ops);

			if (op != BPF_MOV && !(rs.live & (1 << dst))) {
				insns[pos++] = EBPF_MOV64_IMM(dst, 1);
				reg_set(&rs, dst);
				if (pos >= body_len)
					break;
			}
			insns[pos++] = EBPF_ALU64_REG(op, dst, src);
			reg_set(&rs, dst);

		} else if (choice < 65) {
			/* ALU32 with immediate */
			int dst = reg_pick_dst();
			int imm = rand() % 256;

			insns[pos++] = EBPF_ALU32_IMM(BPF_MOV, dst, imm);
			reg_set(&rs, dst);

		} else if (choice < 75) {
			/* Stack store + load */
			int reg = reg_pick_live(&rs);
			int off = rand_stack_offset();

			insns[pos++] = EBPF_STX_MEM(BPF_DW, BPF_REG_10, reg, off);
			if (pos >= body_len)
				break;

			if (ONE_IN(2)) {
				int dst = reg_pick_dst();
				insns[pos++] = EBPF_LDX_MEM(BPF_DW, dst, BPF_REG_10, off);
				reg_set(&rs, dst);
			}

		} else if (choice < 82 && remaining >= 3) {
			/* Forward conditional jump (skip 1-3 insns) */
			int src = reg_pick_live(&rs);
			int op = RAND_ARRAY(jmp_ops);
			int max_skip = remaining - 2;

			if (max_skip > 3)
				max_skip = 3;
			if (max_skip < 1)
				break;

			int skip = 1 + (rand() % max_skip);
			insns[pos++] = EBPF_JMP_IMM(op, src, rand() % 100, skip);

			/* Fill skipped slots with safe NOPs (mov rX, rX) */
			for (int j = 0; j < skip && pos < body_len; j++) {
				int r = reg_pick_live(&rs);
				insns[pos++] = EBPF_MOV64_REG(r, r);
			}

		} else if (choice < 87) {
			/* Store immediate to stack */
			int off = rand_stack_offset();
			int sz = RAND_ARRAY(mem_sizes);
			int val = rand() % 256;

			insns[pos++] = EBPF_ST_MEM(sz, BPF_REG_10, off, val);

		} else if (choice < 92) {
			/* MOV64 reg-to-reg (register copy) */
			int dst = reg_pick_dst();
			int src = reg_pick_live(&rs);
			insns[pos++] = EBPF_MOV64_REG(dst, src);
			reg_set(&rs, dst);

		} else if (choice < 97 && remaining >= 2) {
			/* Helper call from prog-type-appropriate set */
			int func = hs.helpers[rand() % hs.count];
			insns[pos++] = EBPF_CALL(func);
			reg_clear_caller_saved(&rs);

		} else {
			/* Endianness conversion */
			int dst = reg_pick_live(&rs);
			int sizes[] = { 16, 32, 64 };
			insns[pos++] = EBPF_ENDIAN(BPF_K, dst, RAND_ARRAY(sizes));
		}
	}

	/* Epilogue: ensure r0 is set and exit */
	if (!(rs.live & (1 << BPF_REG_0)))
		insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	insns[pos++] = EBPF_EXIT();

	return pos;
}

/*
 * Tier 2: Generate boundary-probing eBPF programs.
 *
 * These programs are structurally valid but push verifier limits:
 * deep jump chains, pointer arithmetic near bounds, unchecked map
 * lookups, ALU ops that overflow, register spill/fill patterns.
 */
static int gen_tier2(struct bpf_insn *insns, int max_insns)
{
	struct reg_state rs;
	int pos = 0;
	int body_len;
	int strategy = rand() % 5;

	reg_init(&rs);

	/* Always start with r0 = 0 */
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	reg_set(&rs, BPF_REG_0);

	body_len = TIER2_MIN_INSNS + (rand() % (max_insns - TIER2_MIN_INSNS - 2));
	if (body_len > max_insns - 2)
		body_len = max_insns - 2;

	switch (strategy) {
	case 0:
		/*
		 * Spill/fill storm: rapidly store and reload registers
		 * from the stack to exercise register allocator paths.
		 */
		for (int i = 2; i <= 9 && pos < body_len; i++) {
			insns[pos++] = EBPF_MOV64_IMM(i, rand());
			reg_set(&rs, i);
		}
		while (pos < body_len - 1) {
			int reg = 2 + (rand() % 8);
			int off = rand_stack_offset();
			if (!(rs.live & (1 << reg))) {
				insns[pos++] = EBPF_MOV64_IMM(reg, 0);
				reg_set(&rs, reg);
				if (pos >= body_len - 1)
					break;
			}
			insns[pos++] = EBPF_STX_MEM(BPF_DW, BPF_REG_10, reg, off);
			if (pos >= body_len - 1)
				break;
			int dst = 2 + (rand() % 8);
			insns[pos++] = EBPF_LDX_MEM(BPF_DW, dst, BPF_REG_10, off);
			reg_set(&rs, dst);
		}
		break;

	case 1:
		/*
		 * ALU chain: long sequence of arithmetic to build up
		 * complex scalar ranges the verifier must track.
		 */
		insns[pos++] = EBPF_MOV64_IMM(BPF_REG_2, 1);
		reg_set(&rs, BPF_REG_2);
		while (pos < body_len) {
			int op = RAND_ARRAY(alu_ops);
			int imm;

			if (op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)
				imm = rand() % 64;
			else
				imm = (int)rand();

			if (ONE_IN(3))
				insns[pos++] = EBPF_ALU64_REG(op, BPF_REG_2, BPF_REG_2);
			else
				insns[pos++] = EBPF_ALU64_IMM(op, BPF_REG_2, imm);
		}
		break;

	case 2:
		/*
		 * Jump ladder: chain of forward conditional jumps to
		 * exercise verifier's path exploration.
		 */
		insns[pos++] = EBPF_MOV64_IMM(BPF_REG_2, rand() % 1000);
		reg_set(&rs, BPF_REG_2);
		while (pos < body_len - 3) {
			int remaining = body_len - pos;
			int skip = 1 + (rand() % 3);
			int op = RAND_ARRAY(jmp_ops);

			if (skip > remaining - 3)
				skip = 1;
			insns[pos++] = EBPF_JMP_IMM(op, BPF_REG_2, rand() % 1000, skip);
			for (int j = 0; j < skip && pos < body_len; j++) {
				insns[pos++] = EBPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1);
			}
		}
		break;

	case 3:
		/*
		 * Mixed ALU32/ALU64: interleave 32-bit and 64-bit ops
		 * to exercise zero-extension and sign-extension tracking.
		 */
		insns[pos++] = EBPF_MOV64_IMM(BPF_REG_3, 0x7fffffff);
		reg_set(&rs, BPF_REG_3);
		while (pos < body_len) {
			if (ONE_IN(2))
				insns[pos++] = EBPF_ALU32_IMM(BPF_ADD, BPF_REG_3,
							      rand() % 256);
			else
				insns[pos++] = EBPF_ALU64_IMM(BPF_ADD, BPF_REG_3,
							      rand() % 256);
		}
		break;

	case 4:
		/*
		 * JMP32 variations: exercise 32-bit comparison paths
		 * which have separate verifier logic.
		 */
		insns[pos++] = EBPF_MOV64_IMM(BPF_REG_4, rand());
		reg_set(&rs, BPF_REG_4);
		while (pos < body_len - 2) {
			int remaining = body_len - pos;
			int skip = 1;

			if (skip > remaining - 2)
				break;
			insns[pos++] = EBPF_JMP32_IMM(RAND_ARRAY(jmp_ops),
						       BPF_REG_4,
						       rand() % 1000, skip);
			insns[pos++] = EBPF_ALU32_IMM(BPF_ADD, BPF_REG_4, 1);
		}
		break;
	}

	/* Epilogue */
	if (!(rs.live & (1 << BPF_REG_0)))
		insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	insns[pos++] = EBPF_EXIT();

	return pos;
}

/*
 * Tier 3: Generate chaotic eBPF programs.
 *
 * These are designed to crash, confuse, or find bugs in the verifier
 * itself. No attempt at validity — pure chaos.
 */
static int gen_tier3(struct bpf_insn *insns, int max_insns)
{
	int len = TIER3_MIN_INSNS + (rand() % (max_insns - TIER3_MIN_INSNS));

	for (int i = 0; i < len - 1; i++) {
		int choice = rand() % 100;

		if (choice < 30) {
			/* Completely random instruction */
			insns[i].code = (uint8_t)rand();
			insns[i].dst_reg = rand() % 16;
			insns[i].src_reg = rand() % 16;
			insns[i].off = (int16_t)rand();
			insns[i].imm = (int32_t)rand();

		} else if (choice < 45) {
			/* Valid opcode but invalid register (>= MAX_BPF_REG) */
			int op = RAND_ARRAY(alu_ops);
			insns[i] = EBPF_ALU64_REG(op, rand() % 16, rand() % 16);

		} else if (choice < 55) {
			/* Backward jump (verifier should reject) */
			int back = -(1 + (rand() % (i + 1)));
			insns[i] = EBPF_JMP_IMM(BPF_JA, 0, 0, back);

		} else if (choice < 65) {
			/* Jump way past end of program */
			insns[i] = EBPF_JMP_IMM(BPF_JA, 0, 0, 1000 + (rand() % 5000));

		} else if (choice < 72) {
			/* Call non-existent helper */
			insns[i] = EBPF_CALL(EBPF_MAX_HELPER_ID + 1 + (rand() % 1000));

		} else if (choice < 80) {
			/* OOB stack access */
			int off = -(EBPF_STACK_SIZE + 8 + (rand() % 4096));
			insns[i] = EBPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, off);

		} else if (choice < 88) {
			/* Load from wild pointer (r0 uninitialized or garbage) */
			insns[i] = EBPF_LDX_MEM(RAND_ARRAY(mem_sizes),
						 rand() % BPF_REG_10,
						 rand() % BPF_REG_10,
						 (int16_t)rand());

		} else if (choice < 94) {
			/* Atomic op with bad src/dst */
			insns[i].code = BPF_STX | BPF_DW | BPF_ATOMIC;
			insns[i].dst_reg = rand() % 16;
			insns[i].src_reg = rand() % 16;
			insns[i].off = (int16_t)rand();
			insns[i].imm = BPF_ADD + (rand() % 4) * BPF_FETCH;

		} else {
			/* Malformed 128-bit load: first half only */
			insns[i].code = BPF_LD | BPF_DW | BPF_IMM;
			insns[i].dst_reg = rand() % BPF_REG_10;
			insns[i].src_reg = rand() % 4;
			insns[i].off = 0;
			insns[i].imm = (int32_t)rand();
			/* Don't emit the second half — malformed */
		}
	}

	/* Last instruction: sometimes exit, sometimes not */
	if (ONE_IN(3))
		insns[len - 1] = EBPF_EXIT();
	else {
		insns[len - 1].code = (uint8_t)rand();
		insns[len - 1].dst_reg = rand() % 16;
		insns[len - 1].src_reg = rand() % 16;
		insns[len - 1].off = (int16_t)rand();
		insns[len - 1].imm = (int32_t)rand();
	}

	return len;
}

/*
 * Main entry point: generate an eBPF program.
 *
 * Returns a malloc'd array of struct bpf_insn. Caller must free.
 * *insn_count is set to the number of instructions.
 *
 * Distribution: ~50% Tier 1 (valid), ~25% Tier 2 (boundary), ~25% Tier 3 (chaos)
 */
struct bpf_insn *ebpf_gen_program(int *insn_count, unsigned int prog_type)
{
	struct bpf_insn *insns;
	struct helper_set hs;
	int max_insns, len;
	int tier = rand() % 100;

	if (tier < 50) {
		max_insns = TIER1_MAX_INSNS;
	} else if (tier < 75) {
		max_insns = TIER2_MAX_INSNS;
	} else {
		max_insns = TIER3_MAX_INSNS;
	}

	insns = zmalloc(max_insns * sizeof(struct bpf_insn));
	hs = get_helpers_for_prog_type(prog_type);

	if (tier < 50)
		len = gen_tier1(insns, max_insns, hs);
	else if (tier < 75)
		len = gen_tier2(insns, max_insns);
	else
		len = gen_tier3(insns, max_insns);

	*insn_count = len;

	if (quiet_level >= MAX_LOGLEVEL)
		debugf("ebpf: generated tier %d program, %d insns\n",
		       tier < 50 ? 1 : (tier < 75 ? 2 : 3), len);

	return insns;
}

#endif /* USE_BPF */
