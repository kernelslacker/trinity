#pragma once

#include <stdbool.h>

#include "kernel/bpf.h"

struct bpfobj;
struct bpfprogobj;

/*
 * Draw a map from the pool.  get_rand_bpf_map() hands back what the pool
 * recorded of it, for a caller that sizes buffers by the map's type and key
 * and value size; get_rand_bpf_fd() is its fd, or -1 from an empty pool.
 */
bool get_rand_bpf_map(struct bpfobj *map);
int get_rand_bpf_fd(void);

/*
 * Draw a program from the pool: get_rand_bpf_prog() hands back its type and
 * the attach type it was loaded for, get_rand_bpf_prog_fd() its fd, or -1
 * from an empty pool.
 */
bool get_rand_bpf_prog(struct bpfprogobj *prog);
int get_rand_bpf_prog_fd(void);

/* The expected attach type the kernel holds a program of @prog_type loaded
 * with @requested to. */
unsigned int bpf_prog_loaded_attach_type(unsigned int prog_type,
					 unsigned int requested);

int get_rand_bpf_link_fd(void);
int get_rand_bpf_btf_fd(void);
int get_rand_bpf_token_fd(void);

/*
 * bpf map / prog / attach type vocabularies.  Defined in the facade
 * struct_catalog/bpf.c so the schema-aware fill's FT_ENUM tags and the
 * syscalls/bpf-*.c sanitisers share a single source.  Counts live as
 * their own extern so the sanitisers keep a runtime read.
 * The _N constants give the extern decls a complete array type so
 * the per-family leaf TUs (struct_catalog/bpf-map.c, bpf-prog.c,
 * bpf-link.c, ...) can fold ARRAY_SIZE() at their FT_ENUM
 * initialisers.  Populated only when USE_BPF is set; the catalog
 * itself is also USE_BPF-gated, so undefined-reference builds
 * without bpf support never name these symbols.
 */
enum {
	BPF_MAP_TYPES_N		= 35,
	BPF_PROG_TYPES_N	= 33,
	BPF_ATTACH_TYPES_N	= 62,
};

extern const unsigned long bpf_map_types[BPF_MAP_TYPES_N];
extern const unsigned int bpf_map_types_count;
extern const unsigned long bpf_prog_types[BPF_PROG_TYPES_N];
extern const unsigned int bpf_prog_types_count;
extern const unsigned long bpf_attach_types[BPF_ATTACH_TYPES_N];
extern const unsigned int bpf_attach_types_count;

/*
 * eBPF instruction definitions for the program generator.
 *
 * eBPF uses a 64-bit ISA with 11 registers (r0-r10), 64-bit ALU ops,
 * helper function calls, and a verifier that does abstract interpretation
 * with register state tracking and memory bounds checking.
 */

/* eBPF classes not in classic BPF */
#ifndef BPF_ALU64
#define BPF_ALU64	0x07
#endif
#ifndef BPF_JMP32
#define BPF_JMP32	0x06
#endif

/* eBPF atomic memory ops */
#ifndef BPF_ATOMIC
#define BPF_ATOMIC	0xc0
#endif
#ifndef BPF_FETCH
#define BPF_FETCH	0x01
#endif
#ifndef BPF_XCHG
#define BPF_XCHG	(0xe0 | BPF_FETCH)
#endif
#ifndef BPF_CMPXCHG
#define BPF_CMPXCHG	(0xf0 | BPF_FETCH)
#endif
#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ	0x100	/* atomic load-acquire (v6.15) */
#endif
#ifndef BPF_STORE_REL
#define BPF_STORE_REL	0x110	/* atomic store-release (v6.15) */
#endif

/* eBPF signed comparisons */
#ifndef BPF_JLT
#define BPF_JLT		0xa0
#endif
#ifndef BPF_JLE
#define BPF_JLE		0xb0
#endif
#ifndef BPF_JSLT
#define BPF_JSLT	0xc0
#endif
#ifndef BPF_JSLE
#define BPF_JSLE	0xd0
#endif

/* eBPF sign-extending load mode + conditional pseudo-jumps */
#ifndef BPF_MEMSX
#define BPF_MEMSX	0x80	/* load with sign extension (v6.6) */
#endif
#ifndef BPF_JCOND
#define BPF_JCOND	0xe0	/* conditional pseudo jumps: may_goto (v6.10) */
#endif

/* Register numbers — already defined in <linux/bpf.h> as enum + MAX_BPF_REG */

/* Max helpers as of kernel 6.x — used as upper bound for random calls */
#define EBPF_MAX_HELPER_ID	211

/*
 * eBPF instruction builder macros.
 * struct bpf_insn is { u8 code, u8 dst_reg:4, u8 src_reg:4, s16 off, s32 imm }
 */
#define EBPF_ALU64_REG(op, dst, src) \
	((struct bpf_insn) { .code = BPF_ALU64 | BPF_OP(op) | BPF_X, \
	  .dst_reg = (dst), .src_reg = (src), .off = 0, .imm = 0 })

#define EBPF_ALU64_IMM(op, dst, val) \
	((struct bpf_insn) { .code = BPF_ALU64 | BPF_OP(op) | BPF_K, \
	  .dst_reg = (dst), .src_reg = 0, .off = 0, .imm = (val) })

#define EBPF_ALU32_REG(op, dst, src) \
	((struct bpf_insn) { .code = BPF_ALU | BPF_OP(op) | BPF_X, \
	  .dst_reg = (dst), .src_reg = (src), .off = 0, .imm = 0 })

#define EBPF_ALU32_IMM(op, dst, val) \
	((struct bpf_insn) { .code = BPF_ALU | BPF_OP(op) | BPF_K, \
	  .dst_reg = (dst), .src_reg = 0, .off = 0, .imm = (val) })

#define EBPF_MOV64_REG(dst, src) \
	EBPF_ALU64_REG(BPF_MOV, dst, src)

#define EBPF_MOV64_IMM(dst, val) \
	EBPF_ALU64_IMM(BPF_MOV, dst, val)

#define EBPF_MOV32_IMM(dst, val) \
	EBPF_ALU32_IMM(BPF_MOV, dst, val)

/* Memory load/store */
#define EBPF_LDX_MEM(sz, dst, src, offset) \
	((struct bpf_insn) { .code = BPF_LDX | (sz) | BPF_MEM, \
	  .dst_reg = (dst), .src_reg = (src), .off = (offset), .imm = 0 })

#define EBPF_STX_MEM(sz, dst, src, offset) \
	((struct bpf_insn) { .code = BPF_STX | (sz) | BPF_MEM, \
	  .dst_reg = (dst), .src_reg = (src), .off = (offset), .imm = 0 })

#define EBPF_ST_MEM(sz, dst, offset, val) \
	((struct bpf_insn) { .code = BPF_ST | (sz) | BPF_MEM, \
	  .dst_reg = (dst), .src_reg = 0, .off = (offset), .imm = (val) })

/* 64-bit immediate load (uses two instruction slots) */
#define EBPF_LD_IMM64(dst, val) \
	((struct bpf_insn) { .code = BPF_LD | BPF_DW | BPF_IMM, \
	  .dst_reg = (dst), .src_reg = 0, .off = 0, \
	  .imm = (__s32)((__u64)(val)) }), \
	((struct bpf_insn) { .code = 0, .dst_reg = 0, .src_reg = 0, \
	  .off = 0, .imm = (__s32)((__u64)(val) >> 32) })

/* Map fd load (special 64-bit imm with src_reg=1) */
#define EBPF_LD_MAP_FD(dst, fd) \
	((struct bpf_insn) { .code = BPF_LD | BPF_DW | BPF_IMM, \
	  .dst_reg = (dst), .src_reg = 1, .off = 0, .imm = (fd) }), \
	((struct bpf_insn) { .code = 0, .dst_reg = 0, .src_reg = 0, \
	  .off = 0, .imm = 0 })

/* Jumps */
#define EBPF_JMP_REG(op, dst, src, offset) \
	((struct bpf_insn) { .code = BPF_JMP | BPF_OP(op) | BPF_X, \
	  .dst_reg = (dst), .src_reg = (src), .off = (offset), .imm = 0 })

#define EBPF_JMP_IMM(op, dst, val, offset) \
	((struct bpf_insn) { .code = BPF_JMP | BPF_OP(op) | BPF_K, \
	  .dst_reg = (dst), .src_reg = 0, .off = (offset), .imm = (val) })

#define EBPF_JMP32_IMM(op, dst, val, offset) \
	((struct bpf_insn) { .code = BPF_JMP32 | BPF_OP(op) | BPF_K, \
	  .dst_reg = (dst), .src_reg = 0, .off = (offset), .imm = (val) })

/* Unconditional jump */
#define EBPF_JA(offset) \
	((struct bpf_insn) { .code = BPF_JMP | BPF_JA, \
	  .dst_reg = 0, .src_reg = 0, .off = (offset), .imm = 0 })

/* Function call */
#define EBPF_CALL(func) \
	((struct bpf_insn) { .code = BPF_JMP | BPF_CALL, \
	  .dst_reg = 0, .src_reg = 0, .off = 0, .imm = (func) })

/* Program exit */
#define EBPF_EXIT() \
	((struct bpf_insn) { .code = BPF_JMP | BPF_EXIT, \
	  .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 })

/* Atomic operations */
#define EBPF_ATOMIC_ADD64(dst, src, offset) \
	((struct bpf_insn) { .code = BPF_STX | BPF_DW | BPF_ATOMIC, \
	  .dst_reg = (dst), .src_reg = (src), .off = (offset), .imm = BPF_ADD })

#define EBPF_ATOMIC_ADD32(dst, src, offset) \
	((struct bpf_insn) { .code = BPF_STX | BPF_W | BPF_ATOMIC, \
	  .dst_reg = (dst), .src_reg = (src), .off = (offset), .imm = BPF_ADD })

/* Endianness conversion */
#define EBPF_ENDIAN(type, dst, len) \
	((struct bpf_insn) { .code = BPF_ALU | BPF_END | (type), \
	  .dst_reg = (dst), .src_reg = 0, .off = 0, .imm = (len) })

/* eBPF program generation */
struct bpf_insn *ebpf_gen_program(int *insn_count, unsigned int prog_type);
void ebpf_gen_program_into(struct bpf_insn *insns, int max_insns,
			   int *insn_count, unsigned int prog_type);

/*
 * Maximum insn slots the generator may emit -- matches TIER3_MAX_INSNS
 * in net/bpf/ebpf.c.  Exposed so the schema-mutation FT_BPF_PROGRAM tag in
 * generate-args.c can size its sub-buffer without naming a net/bpf/ebpf.c
 * internal.  Bump in lockstep if a tier's MAX grows past 512.
 */
#define EBPF_GEN_PROG_MAX_INSNS	512
