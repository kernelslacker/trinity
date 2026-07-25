/*
 * ebpf-internal.h
 *
 * Shared declarations for the eBPF program generator split across
 * net/bpf/ebpf*.c translation units.  Private to that fileset — do
 * not include from anywhere else.
 */

#ifndef NET_BPF_EBPF_INTERNAL_H
#define NET_BPF_EBPF_INTERNAL_H

#include <stdint.h>
#include <linux/bpf.h>

#ifdef USE_BPF

/* Stack frame: 512 bytes max, 8-byte aligned slots */
#define EBPF_STACK_SIZE		512
#define EBPF_STACK_SLOTS	(EBPF_STACK_SIZE / 8)

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

void reg_init(struct reg_state *rs, int prepend_map_reg);
void reg_set(struct reg_state *rs, int reg);
void reg_clear_caller_saved(struct reg_state *rs);
int reg_pick_live(struct reg_state *rs);
int reg_pick_dst(void);
int rand_stack_offset(void);

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

struct helper_set {
	const struct helper_desc *helpers;
	int count;
};

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

struct helper_set get_helpers_for_prog_type(unsigned int prog_type);
int helper_call_insns(const struct helper_desc *h, bool *need_init);
const struct helper_desc *
pick_helper_satisfiable(struct helper_set hs, const struct reg_state *rs);

/* Program size limits */
#define TIER1_MIN_INSNS		5
#define TIER1_MAX_INSNS		64

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

/* ALU ops safe for the verifier (no div/mod by potential zero from reg) */
static const int alu_ops[] __attribute__((unused)) = {
	BPF_ADD, BPF_SUB, BPF_MUL, BPF_OR, BPF_AND,
	BPF_LSH, BPF_RSH, BPF_XOR, BPF_MOV, BPF_ARSH,
};

/* Jump comparison ops (used with forward-only offsets) */
static const int jmp_ops[] __attribute__((unused)) = {
	BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET, BPF_JNE,
	BPF_JSGT, BPF_JSGE, BPF_JLT, BPF_JLE, BPF_JSLT, BPF_JSLE,
};

/* Memory access sizes */
static const int mem_sizes[] __attribute__((unused)) = { BPF_B, BPF_H, BPF_W, BPF_DW };

struct bpf_insn;

int emit_tier1_helper_call(struct bpf_insn *insns, int pos,
			    int body_len, struct reg_state *rs,
			    struct helper_set hs);
int emit_tier1_map_val_deref(struct bpf_insn *insns, int pos,
			      struct reg_state *rs);
int gen_tier1(struct bpf_insn *insns, int max_insns,
	      struct helper_set hs, int prepend_map_reg);

/* Program size limits (tier 2) */
#define TIER2_MIN_INSNS		16
#define TIER2_MAX_INSNS		256

/*
 * Which tier 2 sub-strategy index forces a typed helper call.  Acts as
 * the dedicated counterpart to tier1's lottery so map-helper and
 * scalar-arg paths see traffic even when the lottery doesn't fire.
 */
#define TIER2_STRATEGY_HELPER_CALL	5
#define TIER2_STRATEGY_COUNT		6

int gen_tier2(struct bpf_insn *insns, int max_insns,
	      struct helper_set hs, int prepend_map_reg);

/* Program size limits (tier 3) */
#define TIER3_MIN_INSNS		2
#define TIER3_MAX_INSNS		512

int gen_tier3(struct bpf_insn *insns, int max_insns);

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

int pick_map_fd_for_program(int tier_id);
int emit_ld_map_fd_prologue(struct bpf_insn *insns, int map_fd);

#endif /* USE_BPF */

#endif /* NET_BPF_EBPF_INTERNAL_H */
