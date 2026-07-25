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

#endif /* USE_BPF */

#endif /* NET_BPF_EBPF_INTERNAL_H */
