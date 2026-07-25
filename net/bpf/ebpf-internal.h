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

#endif /* USE_BPF */

#endif /* NET_BPF_EBPF_INTERNAL_H */
