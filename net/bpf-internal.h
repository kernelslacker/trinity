/*
 * bpf-internal.h
 *
 * Shared declarations split out of net/bpf.c so the classic-BPF
 * disassembler (bpf-disasm.c) can compile as its own translation
 * unit and live independently of the seccomp/socket-filter generator.
 * This header is private to the two TUs that make up the bpf
 * subsystem — do not include it from anywhere else.
 *
 * The only widened symbol is bpf_disasm_all(): it is invoked from the
 * generators in bpf.c at MAX_LOGLEVEL verbosity and defined in
 * bpf-disasm.c.  Everything else the disassembler needs (the per-class
 * *_vars_name string tables, the op_table[], the per-class decode
 * helpers and bpf_disasm()) is file-static inside bpf-disasm.c.
 *
 * The BPF opcode-bit fallback macros are emitted here because both
 * TUs reference them and must observe the same constant values
 * regardless of how complete the system <linux/filter.h> happens to
 * be.  Each macro is guarded so a definition coming in via the system
 * header still wins.
 */

#ifndef NET_BPF_INTERNAL_H
#define NET_BPF_INTERNAL_H

#include <linux/filter.h>

#ifndef BPF_CLASS
#define BPF_CLASS(code) ((code) & 0x07)
#define	BPF_LD		0x00
#define	BPF_LDX		0x01
#define	BPF_ST		0x02
#define	BPF_STX		0x03
#define	BPF_ALU		0x04
#define	BPF_JMP		0x05
#define	BPF_RET		0x06
#define	BPF_MISC	0x07
#endif

#ifndef BPF_SIZE
#define BPF_SIZE(code)	((code) & 0x18)
#define	BPF_W		0x00
#define	BPF_H		0x08
#define	BPF_B		0x10
#endif
#ifndef BPF_DW
#define	BPF_DW		0x18	/* eBPF only, double word */
#endif

#ifndef BPF_MODE
#define BPF_MODE(code)	((code) & 0xe0)
#define	BPF_IMM		0x00
#define	BPF_ABS		0x20
#define	BPF_IND		0x40
#define	BPF_MEM		0x60
#define	BPF_LEN		0x80	/* classic BPF only, reserved in eBPF */
#define	BPF_MSH		0xa0	/* classic BPF only, reserved in eBPF */
#endif
#ifndef BPF_XADD
#define	BPF_XADD	0xc0	/* eBPF only, exclusive add */
#endif

#ifndef BPF_OP
#define BPF_OP(code)	((code) & 0xf0)
#define	BPF_ADD		0x00
#define	BPF_SUB		0x10
#define	BPF_MUL		0x20
#define	BPF_DIV		0x30
#define	BPF_OR		0x40
#define	BPF_AND		0x50
#define	BPF_LSH		0x60
#define	BPF_RSH		0x70
#define	BPF_NEG		0x80
#define	BPF_MOD		0x90
#define	BPF_XOR		0xa0
#endif
#ifndef BPF_MOV
#define	BPF_MOV		0xb0	/* eBPF only: mov reg to reg */
#endif
#ifndef BPF_ARSH
#define	BPF_ARSH	0xc0	/* eBPF only: sign extending shift right */
#endif
#ifndef BPF_END
#define	BPF_END		0xd0	/* eBPF only: endianness conversion */
#endif

#ifndef BPF_JA
#define	BPF_JA		0x00
#define	BPF_JEQ		0x10
#define	BPF_JGT		0x20
#define	BPF_JGE		0x30
#define	BPF_JSET	0x40
#endif
#ifndef BPF_JNE
#define	BPF_JNE		0x50  /* eBPF only: jump != */
#endif
#ifndef BPF_JSGT
#define	BPF_JSGT	0x60  /* eBPF only: signed '>' */
#endif
#ifndef BPF_JSGE
#define	BPF_JSGE	0x70  /* eBPF only: signed '>=' */
#endif
#ifndef BPF_CALL
#define	BPF_CALL	0x80  /* eBPF only: function call */
#endif
#ifndef BPF_EXIT
#define	BPF_EXIT	0x90  /* eBPF only: function return */
#endif

#ifndef BPF_SRC
#define BPF_SRC(code)	((code) & 0x08)
#define	BPF_K		0x00
#define	BPF_X		0x08
#endif

#ifndef BPF_RVAL
#define BPF_RVAL(code)	((code) & 0x18)
#define	BPF_A		0x10
#endif

#ifndef BPF_MISCOP
#define BPF_MISCOP(code) ((code) & 0xf8)
#define	BPF_TAX		0x00
#define	BPF_TXA		0x80
#endif

#define BPF_LDX_B	(BPF_LDX  |   BPF_B)
#define BPF_LDX_W	(BPF_LDX  |   BPF_W)
#define BPF_JMP_JA	(BPF_JMP  |  BPF_JA)
#define BPF_JMP_JEQ	(BPF_JMP  | BPF_JEQ)
#define BPF_JMP_JGT	(BPF_JMP  | BPF_JGT)
#define BPF_JMP_JGE	(BPF_JMP  | BPF_JGE)
#define BPF_JMP_JSET	(BPF_JMP  | BPF_JSET)
#define BPF_ALU_ADD	(BPF_ALU  | BPF_ADD)
#define BPF_ALU_SUB	(BPF_ALU  | BPF_SUB)
#define BPF_ALU_MUL	(BPF_ALU  | BPF_MUL)
#define BPF_ALU_DIV	(BPF_ALU  | BPF_DIV)
#define BPF_ALU_MOD	(BPF_ALU  | BPF_MOD)
#define BPF_ALU_NEG	(BPF_ALU  | BPF_NEG)
#define BPF_ALU_AND	(BPF_ALU  | BPF_AND)
#define BPF_ALU_OR	(BPF_ALU  |  BPF_OR)
#define BPF_ALU_XOR	(BPF_ALU  | BPF_XOR)
#define BPF_ALU_LSH	(BPF_ALU  | BPF_LSH)
#define BPF_ALU_RSH	(BPF_ALU  | BPF_RSH)
#define BPF_MISC_TAX	(BPF_MISC | BPF_TAX)
#define BPF_MISC_TXA	(BPF_MISC | BPF_TXA)
#define BPF_LD_B	(BPF_LD   |   BPF_B)
#define BPF_LD_H	(BPF_LD   |   BPF_H)
#define BPF_LD_W	(BPF_LD   |   BPF_W)

void bpf_disasm_all(const struct sock_filter *f, unsigned int len);

#endif /* NET_BPF_INTERNAL_H */
