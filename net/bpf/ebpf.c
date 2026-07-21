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
 * Lottery weight for emitting an arg-bearing helper call inside tier 1's
 * main dispatch.  Picked a touch under the map-fd weight so call-storms
 * don't crowd out scalar coverage — the tier 2 dedicated sub-strategy
 * below provides a second, deterministic source.
 */
#define HELPER_CALL_WEIGHT_PCT		8

/*
 * Lottery weight for emitting the NULL-check + deref idiom after any
 * PTR_OR_NULL-returning helper leaves R0 holding a possibly-NULL
 * pointer.  Lower than HELPER_CALL_WEIGHT_PCT because the
 * deref carries a runtime prereq (live or-null pointer in R0) the
 * dispatch cannot force, so most rolls would be no-ops anyway -- the
 * marker survives across iterations that don't touch R0, giving 3% a
 * chance to fire on any of several iterations after a lookup lands.
 * The same weight covers every helper in the or-null set; widening the
 * set keeps the aggregate gate reasonable since per-helper firing rate
 * still tracks how often each helper is picked from the table.
 */
#define MAP_VAL_DEREF_WEIGHT_PCT	3

/*
 * Which tier 2 sub-strategy index forces a typed helper call.  Acts as
 * the dedicated counterpart to tier1's lottery so map-helper and
 * scalar-arg paths see traffic even when the lottery doesn't fire.
 */
#define TIER2_STRATEGY_HELPER_CALL	5
#define TIER2_STRATEGY_COUNT		6

/*
 * Per-arg type tag in the helper descriptor table.  The generator emits
 * a setup sequence for each arg matching its kind, then a BPF_CALL.
 * Kinds intentionally limited to what we can satisfy cheaply and
 * verifier-cleanly; richer kinds (ARG_CONST_MAP_VALUE, ARG_PTR_TO_MEM
 * with strict size matching, varargs, etc.) are not modelled.
 */
enum helper_arg_kind {
	ARG_SCALAR,		/* MOV64_IMM small constant */
	ARG_MAP_PTR,		/* copy of an existing PTR_TO_MAP reg */
	ARG_STACK_PTR,		/* R10 + offset into the call-local init slot */
	ARG_STACK_SIZE,		/* MOV64_IMM matching the init-slot byte size */
};

struct helper_desc {
	int	func;		/* BPF_FUNC_* helper id */
	uint8_t	nargs;		/* 0..5 */
	uint8_t	arg_kind[5];	/* per-arg enum helper_arg_kind */
};

#define HD0(f) \
	{ .func = (f), .nargs = 0, .arg_kind = { 0, 0, 0, 0, 0 } }
#define HD2(f, a0, a1) \
	{ .func = (f), .nargs = 2, \
	  .arg_kind = { (a0), (a1), 0, 0, 0 } }
#define HD3(f, a0, a1, a2) \
	{ .func = (f), .nargs = 3, \
	  .arg_kind = { (a0), (a1), (a2), 0, 0 } }
#define HD4(f, a0, a1, a2, a3) \
	{ .func = (f), .nargs = 4, \
	  .arg_kind = { (a0), (a1), (a2), (a3), 0 } }

/*
 * Per-prog-type helper descriptor tables.
 *
 * Curated set: zero-arg helpers (always safe to call), plus a small
 * arg-bearing core — map_lookup/update/delete, probe_read_kernel —
 * whose prototypes we can satisfy from this generator's vocabulary.
 * No privileged helpers, no kfuncs, no socket sendmsg / override_return,
 * no skb-mutating helpers that need a live skb context.  Helpers whose
 * verifier prototype demands kinds we don't model yet stay out.
 */
static const struct helper_desc helpers_universal[] = {
	HD0(BPF_FUNC_ktime_get_ns),
	HD0(BPF_FUNC_get_prandom_u32),
	HD0(BPF_FUNC_get_smp_processor_id),
	HD0(BPF_FUNC_get_current_pid_tgid),
	HD0(BPF_FUNC_get_current_uid_gid),
	HD0(BPF_FUNC_get_numa_node_id),
	HD0(BPF_FUNC_ktime_get_boot_ns),
	HD0(BPF_FUNC_ktime_get_coarse_ns),
	HD0(BPF_FUNC_jiffies64),
	HD0(BPF_FUNC_ktime_get_tai_ns),
	HD2(BPF_FUNC_map_lookup_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD4(BPF_FUNC_map_update_elem, ARG_MAP_PTR, ARG_STACK_PTR,
	    ARG_STACK_PTR, ARG_SCALAR),
	HD2(BPF_FUNC_map_delete_elem, ARG_MAP_PTR, ARG_STACK_PTR),
};

/* Tracing types: kprobe, tracepoint, perf_event, raw_tracepoint */
static const struct helper_desc helpers_tracing[] = {
	HD0(BPF_FUNC_ktime_get_ns),
	HD0(BPF_FUNC_get_prandom_u32),
	HD0(BPF_FUNC_get_smp_processor_id),
	HD0(BPF_FUNC_get_current_pid_tgid),
	HD0(BPF_FUNC_get_current_uid_gid),
	HD0(BPF_FUNC_get_numa_node_id),
	HD0(BPF_FUNC_ktime_get_boot_ns),
	HD0(BPF_FUNC_get_current_task),
	HD0(BPF_FUNC_get_current_cgroup_id),
	HD2(BPF_FUNC_map_lookup_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD4(BPF_FUNC_map_update_elem, ARG_MAP_PTR, ARG_STACK_PTR,
	    ARG_STACK_PTR, ARG_SCALAR),
	HD2(BPF_FUNC_map_delete_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD3(BPF_FUNC_probe_read_kernel, ARG_STACK_PTR, ARG_STACK_SIZE,
	    ARG_SCALAR),
};

/* Networking types: socket_filter, sched_cls, sched_act, xdp, lwt, etc. */
static const struct helper_desc helpers_networking[] = {
	HD0(BPF_FUNC_ktime_get_ns),
	HD0(BPF_FUNC_get_prandom_u32),
	HD0(BPF_FUNC_get_smp_processor_id),
	HD0(BPF_FUNC_get_current_pid_tgid),
	HD0(BPF_FUNC_get_current_uid_gid),
	HD0(BPF_FUNC_get_numa_node_id),
	HD0(BPF_FUNC_ktime_get_boot_ns),
	HD2(BPF_FUNC_map_lookup_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD4(BPF_FUNC_map_update_elem, ARG_MAP_PTR, ARG_STACK_PTR,
	    ARG_STACK_PTR, ARG_SCALAR),
	HD2(BPF_FUNC_map_delete_elem, ARG_MAP_PTR, ARG_STACK_PTR),
};

/* Cgroup types */
static const struct helper_desc helpers_cgroup[] = {
	HD0(BPF_FUNC_ktime_get_ns),
	HD0(BPF_FUNC_get_prandom_u32),
	HD0(BPF_FUNC_get_smp_processor_id),
	HD0(BPF_FUNC_get_current_pid_tgid),
	HD0(BPF_FUNC_get_current_uid_gid),
	HD0(BPF_FUNC_get_numa_node_id),
	HD0(BPF_FUNC_ktime_get_boot_ns),
	HD0(BPF_FUNC_get_current_cgroup_id),
	HD2(BPF_FUNC_map_lookup_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD4(BPF_FUNC_map_update_elem, ARG_MAP_PTR, ARG_STACK_PTR,
	    ARG_STACK_PTR, ARG_SCALAR),
	HD2(BPF_FUNC_map_delete_elem, ARG_MAP_PTR, ARG_STACK_PTR),
};

struct helper_set {
	const struct helper_desc *helpers;
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
 *
 * map_reg tracks the most recent register holding a PTR_TO_MAP
 * (set by the LD_MAP_FD prepend in ebpf_gen_program_into).  Helper calls
 * needing an ARG_MAP_PTR copy from this register instead of emitting a
 * fresh LD_MAP_FD pair, keeping the call sequence short and avoiding any
 * mid-program 2-slot pseudo-imm that a future jump might land on.  Cleared
 * (-1) whenever the tracked register is overwritten or clobbered by a
 * caller-saved reset.
 */
struct reg_state {
	uint16_t live;		/* bitmask: 1 << reg if initialized */
	int8_t map_reg;		/* register holding PTR_TO_MAP, or -1 */
	bool r0_or_null;	/* R0 holds a PTR_OR_NULL return value */
	bool r0_writable;	/* deref of R0 may use STXW as well as LDXW */
};

static void reg_init(struct reg_state *rs, int prepend_map_reg)
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

static void reg_set(struct reg_state *rs, int reg)
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

static void reg_clear_caller_saved(struct reg_state *rs)
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
	return candidates[rnd_modulo_u32(n)];
}

/* Pick a writable destination register (r0-r9, not r10) */
static int reg_pick_dst(void)
{
	return rnd_modulo_u32(BPF_REG_10);
}

/* Random stack offset, 8-byte aligned, negative from r10 */
static int rand_stack_offset(void)
{
	int slot = (rnd_modulo_u32(EBPF_STACK_SLOTS)) + 1;
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
 * Emit one ALU64 op with a sign-bounded immediate.  MOV always initializes
 * the destination; for other ops, dst must already be live or we emit a
 * priming MOV first (and bail if that priming insn hit body_len).
 */
static int emit_tier1_alu64_imm(struct bpf_insn *insns, int pos, int body_len,
				 struct reg_state *rs)
{
	int dst = reg_pick_dst();
	int op = RAND_ARRAY(alu_ops);
	int imm = (int)(rnd_modulo_u32(65536)) - 32768;

	if (op != BPF_MOV && !(rs->live & (1 << dst))) {
		insns[pos++] = EBPF_MOV64_IMM(dst, rnd_modulo_u32(100));
		reg_set(rs, dst);
		if (pos >= body_len)
			return pos;
	}
	/* Avoid shift by >= 64 */
	if (op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)
		imm = rnd_modulo_u32(64);
	insns[pos++] = EBPF_ALU64_IMM(op, dst, imm);
	reg_set(rs, dst);
	return pos;
}

/*
 * Emit one ALU64 reg-to-reg op, priming dst with a MOV first when
 * required for liveness (same pattern as the IMM variant).
 */
static int emit_tier1_alu64_reg(struct bpf_insn *insns, int pos, int body_len,
				 struct reg_state *rs)
{
	int dst = reg_pick_dst();
	int src = reg_pick_live(rs);
	int op = RAND_ARRAY(alu_ops);

	if (op != BPF_MOV && !(rs->live & (1 << dst))) {
		insns[pos++] = EBPF_MOV64_IMM(dst, 1);
		reg_set(rs, dst);
		if (pos >= body_len)
			return pos;
	}
	insns[pos++] = EBPF_ALU64_REG(op, dst, src);
	reg_set(rs, dst);
	return pos;
}

/* Emit a single ALU32 MOV-immediate.  Always initializes dst. */
static int emit_tier1_alu32_mov_imm(struct bpf_insn *insns, int pos,
				     struct reg_state *rs)
{
	int dst = reg_pick_dst();
	int imm = rnd_modulo_u32(256);

	insns[pos++] = EBPF_ALU32_IMM(BPF_MOV, dst, imm);
	reg_set(rs, dst);
	return pos;
}

/*
 * Emit a stack store of a live reg, then optionally a load from the
 * same slot into a fresh dst.  If the store alone lands on body_len,
 * return early without the follow-up load.
 */
static int emit_tier1_stack_roundtrip(struct bpf_insn *insns, int pos,
				       int body_len, struct reg_state *rs)
{
	int reg = reg_pick_live(rs);
	int off = rand_stack_offset();

	insns[pos++] = EBPF_STX_MEM(BPF_DW, BPF_REG_10, reg, off);
	if (pos >= body_len)
		return pos;

	if (ONE_IN(2)) {
		int dst = reg_pick_dst();

		insns[pos++] = EBPF_LDX_MEM(BPF_DW, dst, BPF_REG_10, off);
		reg_set(rs, dst);
	}
	return pos;
}

/* Emit one ST_MEM of a small immediate into a random stack slot. */
static int emit_tier1_st_imm(struct bpf_insn *insns, int pos)
{
	int off = rand_stack_offset();
	int sz = RAND_ARRAY(mem_sizes);
	int val = rnd_modulo_u32(256);

	insns[pos++] = EBPF_ST_MEM(sz, BPF_REG_10, off, val);
	return pos;
}

/*
 * Emit a forward conditional jump that skips 1-3 insns, then fill
 * the skipped slots with mov-self NOPs.  Caller must have ensured
 * body_len - pos >= 3 before dispatch so the skip range is non-zero.
 */
static int emit_tier1_jmp_fwd(struct bpf_insn *insns, int pos, int body_len,
			       struct reg_state *rs)
{
	int src = reg_pick_live(rs);
	int op = RAND_ARRAY(jmp_ops);
	int max_skip = (body_len - pos) - 2;
	int skip;

	if (max_skip > 3)
		max_skip = 3;

	skip = 1 + (rnd_modulo_u32(max_skip));
	insns[pos++] = EBPF_JMP_IMM(op, src, rnd_modulo_u32(100), skip);

	/* Fill skipped slots with safe NOPs (mov rX, rX) */
	for (int j = 0; j < skip && pos < body_len; j++) {
		int r = reg_pick_live(rs);

		insns[pos++] = EBPF_MOV64_REG(r, r);
	}
	return pos;
}

/* Emit one MOV64 reg-to-reg copy from a live src to a fresh dst. */
static int emit_tier1_mov64_reg(struct bpf_insn *insns, int pos,
				 struct reg_state *rs)
{
	int dst = reg_pick_dst();
	int src = reg_pick_live(rs);

	insns[pos++] = EBPF_MOV64_REG(dst, src);
	reg_set(rs, dst);
	return pos;
}

/*
 * Per-call init slot the verifier sees as "definitely written" before
 * any ARG_STACK_PTR is read.  Zero-initialised at the start of the call
 * sequence with a single ST_MEM BPF_DW so each STACK_PTR arg can point
 * at it without dragging in its own init burden.  Fixed offset/size
 * keeps the descriptor emission tiny; map keys/values larger than
 * HELPER_ARG_STACK_BYTES will be verifier-rejected (an accepted
 * outcome).
 */
#define HELPER_ARG_STACK_OFF	-8
#define HELPER_ARG_STACK_BYTES	8
#define HELPER_PICK_RETRIES	4

static int helper_call_insns(const struct helper_desc *h, bool *need_init)
{
	int n = 1;	/* the BPF_CALL itself */
	int i;

	*need_init = false;
	for (i = 0; i < h->nargs; i++) {
		switch (h->arg_kind[i]) {
		case ARG_SCALAR:
		case ARG_STACK_SIZE:
		case ARG_MAP_PTR:
			n += 1;	/* MOV / MOV64_IMM */
			break;
		case ARG_STACK_PTR:
			n += 2;	/* MOV64_REG r,R10 ; ALU64_IMM SUB */
			*need_init = true;
			break;
		}
	}
	if (*need_init)
		n += 1;		/* one ST_MEM DW zero-init */
	return n;
}

/*
 * Pick a helper whose prerequisites the current reg state satisfies.
 * Only ARG_MAP_PTR has a runtime prereq (a live PTR_TO_MAP
 * register from a prior LD_MAP_FD); everything else is unconditional.
 * Returns NULL after a few unsuccessful picks so the caller can re-roll
 * the outer dispatch rather than burn the slot on a NOP.
 */
static const struct helper_desc *
pick_helper_satisfiable(struct helper_set hs, const struct reg_state *rs)
{
	const struct helper_desc *h;
	int i, attempt;
	bool wants_map;

	for (attempt = 0; attempt < HELPER_PICK_RETRIES; attempt++) {
		h = &hs.helpers[rnd_modulo_u32(hs.count)];
		wants_map = false;
		for (i = 0; i < h->nargs; i++) {
			if (h->arg_kind[i] == ARG_MAP_PTR) {
				wants_map = true;
				break;
			}
		}
		if (!wants_map || rs->map_reg >= 0)
			return h;
	}
	return NULL;
}

/*
 * Emit a helper call whose R1..R5 are populated per the descriptor's
 * per-arg kind, then BPF_CALL and a caller-saved clobber in the
 * liveness map.  Return value (R0) is left for the separate map-value
 * NULL-check + deref path to consume.
 *
 * Bails (returns pos unchanged) when no satisfiable helper exists in
 * the current reg state or the remaining buffer can't fit the setup
 * plus the EXIT epilogue.  The outer dispatch loop just re-rolls.
 */
static int emit_tier1_helper_call(struct bpf_insn *insns, int pos,
				   int body_len, struct reg_state *rs,
				   struct helper_set hs)
{
	const struct helper_desc *h;
	bool need_init;
	int needed, i, reg;

	h = pick_helper_satisfiable(hs, rs);
	if (h == NULL)
		return pos;

	needed = helper_call_insns(h, &need_init);
	if (body_len - pos < needed + 1)	/* +1 reserves the EXIT slot */
		return pos;

	if (need_init) {
		insns[pos++] = EBPF_ST_MEM(BPF_DW, BPF_REG_10,
					   HELPER_ARG_STACK_OFF, 0);
	}

	for (i = 0; i < h->nargs; i++) {
		reg = BPF_REG_1 + i;
		switch (h->arg_kind[i]) {
		case ARG_SCALAR:
			insns[pos++] = EBPF_MOV64_IMM(reg,
						      rnd_modulo_u32(64));
			break;
		case ARG_STACK_SIZE:
			insns[pos++] = EBPF_MOV64_IMM(reg,
						      HELPER_ARG_STACK_BYTES);
			break;
		case ARG_MAP_PTR:
			insns[pos++] = EBPF_MOV64_REG(reg, rs->map_reg);
			break;
		case ARG_STACK_PTR:
			insns[pos++] = EBPF_MOV64_REG(reg, BPF_REG_10);
			insns[pos++] = EBPF_ALU64_IMM(BPF_ADD, reg,
						      HELPER_ARG_STACK_OFF);
			break;
		}
		reg_set(rs, reg);
	}

	insns[pos++] = EBPF_CALL(h->func);
	reg_clear_caller_saved(rs);
	/*
	 * Arm the deref gate when the helper returns a possibly-NULL
	 * pointer in R0.  Writable backings (map values,
	 * sk/inode/task storage, ringbuf reservation) also permit STXW;
	 * read-only returns (BTF task ptr) get LDXW only.  Helpers not
	 * yet in any prog-type table never reach here, so listing them
	 * is harmless until the descriptor table widens.  Cleanup-
	 * required helpers (sk_lookup_tcp/udp need bpf_sk_release) are
	 * deliberately omitted: emitting a deref without the paired
	 * release would leak ref-counted sock state.
	 */
	switch (h->func) {
	case BPF_FUNC_map_lookup_elem:
	case BPF_FUNC_map_lookup_percpu_elem:
	case BPF_FUNC_inode_storage_get:
	case BPF_FUNC_task_storage_get:
	case BPF_FUNC_sk_storage_get:
	case BPF_FUNC_ringbuf_reserve:
		rs->r0_or_null = true;
		rs->r0_writable = true;
		break;
	case BPF_FUNC_get_current_task_btf:
		rs->r0_or_null = true;
		rs->r0_writable = false;
		break;
	default:
		break;
	}
	__atomic_add_fetch(&shm->stats.ebpf_gen.helper_call_emitted, 1,
			   __ATOMIC_RELAXED);
	return pos;
}

/*
 * Emit the JEQ R0,0,+1 ; LDX/STX pair that actually touches the memory
 * pointed to by R0.  Caller has verified r0_or_null
 * and that body_len - pos >= 2.  Bounded to a 4-byte access at offset 0
 * -- the verifier's per-map bounds check accepts (0, 4) on every map
 * type trinity provisions, and the same shape is safe for ringbuf and
 * the *_storage_get returns; larger offsets fail per-map and would
 * need return-type-aware sizing the generator doesn't track.  Write
 * (STXW) is only legal when the helper returned a writable backing,
 * gated via r0_writable; read-only returns fall through to LDXW.
 * Either variant drops the or-null marker since the deref consumes it.
 */
static int emit_tier1_map_val_deref(struct bpf_insn *insns, int pos,
				     struct reg_state *rs)
{
	/*
	 * +1 in the JEQ offset is the count of insns to skip past the
	 * JEQ itself.  We always emit exactly one insn after it, so the
	 * skip lands on whatever the dispatch picks next.
	 */
	insns[pos++] = EBPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1);

	if (rs->r0_writable && ONE_IN(2)) {
		int src = reg_pick_live(rs);

		insns[pos++] = EBPF_STX_MEM(BPF_W, BPF_REG_0, src, 0);
		__atomic_add_fetch(&shm->stats.ebpf_gen.map_value_deref_write,
				   1, __ATOMIC_RELAXED);
	} else {
		int dst = reg_pick_dst();

		insns[pos++] = EBPF_LDX_MEM(BPF_W, dst, BPF_REG_0, 0);
		reg_set(rs, dst);
		__atomic_add_fetch(&shm->stats.ebpf_gen.map_value_deref_read,
				   1, __ATOMIC_RELAXED);
	}

	rs->r0_or_null = false;
	rs->r0_writable = false;
	__atomic_add_fetch(&shm->stats.ebpf_gen.map_value_deref_emitted,
			   1, __ATOMIC_RELAXED);
	return pos;
}

/* Emit one endianness-conversion op on a live reg at 16/32/64 bits. */
static int emit_tier1_endian(struct bpf_insn *insns, int pos,
			      struct reg_state *rs)
{
	int dst = reg_pick_live(rs);
	int sizes[] = { 16, 32, 64 };

	insns[pos++] = EBPF_ENDIAN(BPF_K, dst, RAND_ARRAY(sizes));
	return pos;
}

/*
 * Tier 1: Generate a valid eBPF program.
 *
 * Strategy: emit a sequence of random operations that the verifier can
 * statically validate. All jumps are forward-only, all register reads
 * come from initialized registers, stack access is bounded.
 */
static int gen_tier1(struct bpf_insn *insns, int max_insns,
		     struct helper_set hs, int prepend_map_reg)
{
	struct reg_state rs;
	int pos = 0;
	int body_len;

	reg_init(&rs, prepend_map_reg);

	/* Prologue: r0 = 0 (safe default return value) */
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	reg_set(&rs, BPF_REG_0);

	/* Initialize a few registers with small constants for variety */
	if (ONE_IN(2)) {
		int reg = 2 + (rnd_modulo_u32(4));	/* r2-r5 */
		insns[pos++] = EBPF_MOV64_IMM(reg, rnd_modulo_u32(256));
		reg_set(&rs, reg);
	}

	/* Body: random operations */
	if (max_insns <= TIER1_MIN_INSNS + 2)
		body_len = pos + 1;
	else
		body_len = TIER1_MIN_INSNS + (rnd_modulo_u32(max_insns - TIER1_MIN_INSNS - 2));
	if (body_len > max_insns - 2)
		body_len = max_insns - 2;

	while (pos < body_len) {
		int remaining = body_len - pos;
		int choice;

		/*
		 * Opportunistic deref of a recent
		 * PTR_OR_NULL-returning helper result.  Rolled independently
		 * of the main lottery so the existing dispatch weights stay
		 * untouched.  The marker survives across iterations that
		 * don't touch R0, so a missed roll here still has a chance
		 * on subsequent iterations until something clobbers R0.
		 */
		if (rs.r0_or_null && remaining >= 2 &&
		    rnd_modulo_u32(100) < MAP_VAL_DEREF_WEIGHT_PCT) {
			pos = emit_tier1_map_val_deref(insns, pos, &rs);
			continue;
		}

		choice = rnd_modulo_u32(100);

		if (choice < 40) {
			pos = emit_tier1_alu64_imm(insns, pos, body_len, &rs);

		} else if (choice < 55) {
			pos = emit_tier1_alu64_reg(insns, pos, body_len, &rs);

		} else if (choice < 65) {
			pos = emit_tier1_alu32_mov_imm(insns, pos, &rs);

		} else if (choice < 75) {
			pos = emit_tier1_stack_roundtrip(insns, pos, body_len, &rs);

		} else if (choice < 82 && remaining >= 3) {
			pos = emit_tier1_jmp_fwd(insns, pos, body_len, &rs);

		} else if (choice < 87) {
			pos = emit_tier1_st_imm(insns, pos);

		} else if (choice < 90) {
			pos = emit_tier1_mov64_reg(insns, pos, &rs);

		} else if (choice < 100 - HELPER_CALL_WEIGHT_PCT) {
			pos = emit_tier1_endian(insns, pos, &rs);

		} else {
			/*
			 * Last HELPER_CALL_WEIGHT_PCT% of the lottery: a
			 * typed helper call.  May bail (returns pos
			 * unchanged) when no satisfiable helper exists in
			 * the current reg state or the buffer can't fit the
			 * arg-setup + CALL + EXIT; the next loop iteration
			 * re-rolls.
			 */
			pos = emit_tier1_helper_call(insns, pos, body_len,
						     &rs, hs);
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

static int gen_tier2(struct bpf_insn *insns, int max_insns,
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

/*
 * Tier 3: Generate chaotic eBPF programs.
 *
 * These are designed to crash, confuse, or find bugs in the verifier
 * itself. No attempt at validity — pure chaos.
 */
static int gen_tier3(struct bpf_insn *insns, int max_insns)
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
