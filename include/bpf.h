#pragma once

#include <linux/bpf.h>

int get_rand_bpf_fd(void);
int get_rand_bpf_prog_fd(void);
int get_rand_bpf_link_fd(void);

#ifndef BPF_MAP_TYPE_LRU_HASH
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10
#define BPF_MAP_TYPE_LPM_TRIE 11
#endif
#ifndef BPF_F_NO_COMMON_LRU
#define BPF_F_NO_COMMON_LRU     (1U << 1)
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF		27
#endif
#ifndef BPF_MAP_TYPE_BLOOM_FILTER
#define BPF_MAP_TYPE_BLOOM_FILTER	30
#endif
#ifndef BPF_MAP_TYPE_USER_RINGBUF
#define BPF_MAP_TYPE_USER_RINGBUF	31
#endif
#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA		33
#endif

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
