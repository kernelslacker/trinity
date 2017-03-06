#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bpf.h"
#include "debug.h"
#include "net.h"
#include "random.h"
#include "syscall.h"
#include "tables.h"
#include "utils.h"
#include "compat.h"

#ifdef USE_BPF
/**
 * BPF filters are used in networking such as in pf_packet, but also
 * in seccomp for application sand-boxing. Additionally, with arch
 * specific BPF JIT compilers, this might be good to fuzz for errors.
 *    -- Daniel Borkmann, <borkmann@redhat.com>
 */

static int dump_bpf = 0;

/* Both here likely defined in linux/filter.h already */
#ifndef SKF_AD_OFF
# define SKF_AD_OFF	(-0x1000)
#endif

#ifndef SKF_AD_MAX
# define SKF_AD_MAX	56
#endif

#define syscall_nr	(offsetof(struct seccomp_data, nr))
#define arch_nr		(offsetof(struct seccomp_data, arch))

#define SECCOMP_MODE_FILTER	2

#define BPF_CLASS(code) ((code) & 0x07)
#define	BPF_LD		0x00
#define	BPF_LDX		0x01
#define	BPF_ST		0x02
#define	BPF_STX		0x03
#define	BPF_ALU		0x04
#define	BPF_JMP		0x05
#define	BPF_RET		0x06
#define	BPF_MISC	0x07

static const uint16_t bpf_class_vars[] = {
	BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC,
};

static const char *bpf_class_vars_name[] = {
	[BPF_LD]   = "ld",
	[BPF_LDX]  = "ldx",
	[BPF_ST]   = "st",
	[BPF_STX]  = "stx",
	[BPF_ALU]  = "alu",
	[BPF_JMP]  = "jmp",
	[BPF_RET]  = "ret",
	[BPF_MISC] = "misc",
};

#define BPF_SIZE(code)	((code) & 0x18)
#define	BPF_W		0x00
#define	BPF_H		0x08
#define	BPF_B		0x10
#define	BPF_DW		0x18	/* eBPF only, double word */

static const uint16_t bpf_size_vars[] = {
	BPF_W, BPF_H, BPF_B, BPF_DW,
};

static const char *bpf_size_vars_name[] = {
	[BPF_W] = "w",
	[BPF_H] = "h",
	[BPF_B] = "b",
	[BPF_DW] = "dw",
};

#define BPF_MODE(code)	((code) & 0xe0)
#define	BPF_IMM		0x00
#define	BPF_ABS		0x20
#define	BPF_IND		0x40
#define	BPF_MEM		0x60
#define	BPF_LEN		0x80	/* classic BPF only, reserved in eBPF */
#define	BPF_MSH		0xa0	/* classic BPF only, reserved in eBPF */
#define	BPF_XADD	0xc0	/* eBPF only, exclusive add */

static const uint16_t bpf_mode_vars[] = {
	BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM, BPF_LEN, BPF_MSH, BPF_XADD,
};

static const char *bpf_mode_vars_name[] = {
	[BPF_IMM] = "imn",
	[BPF_ABS] = "abs",
	[BPF_IND] = "ind",
	[BPF_MEM] = "mem",
	[BPF_LEN] = "len",
	[BPF_MSH] = "msh",
	[BPF_XADD] = "xadd",
};

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
#define	BPF_MOV		0xb0	/* eBPF only: mov reg to reg */
#define	BPF_ARSH	0xc0	/* eBPF only: sign extending shift right */
#define	BPF_END		0xd0	/* eBPF only: endianness conversion */

static const uint16_t bpf_alu_op_vars[] = {
	BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH,
	BPF_NEG, BPF_MOD, BPF_XOR, BPF_MOV, BPF_ARSH, BPF_END,
};

static const char *bpf_alu_op_vars_name[] = {
	[BPF_ADD] = "add",
	[BPF_SUB] = "sub",
	[BPF_MUL] = "mul",
	[BPF_DIV] = "div",
	[BPF_OR]  = "or",
	[BPF_AND] = "and",
	[BPF_LSH] = "lsh",
	[BPF_RSH] = "rsh",
	[BPF_NEG] = "neg",
	[BPF_MOD] = "mod",
	[BPF_XOR] = "xor",
	[BPF_MOV] = "mov",
	[BPF_ARSH] = "arsh",
	[BPF_END] = "end"
};

#define	BPF_JA		0x00
#define	BPF_JEQ		0x10
#define	BPF_JGT		0x20
#define	BPF_JGE		0x30
#define	BPF_JSET	0x40
#define	BPF_JNE		0x50  /* eBPF only: jump != */
#define	BPF_JSGT	0x60  /* eBPF only: signed '>' */
#define	BPF_JSGE	0x70  /* eBPF only: signed '>=' */
#define	BPF_CALL	0x80  /* eBPF only: function call */
#define	BPF_EXIT	0x90  /* eBPF only: function return */

static const uint16_t bpf_jmp_op_vars[] = {
	BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET,
	BPF_JNE, BPF_JSGT, BPF_JSGE, BPF_CALL, BPF_EXIT,
};

static const char *bpf_jmp_op_vars_name[] = {
	[BPF_JA]   = "ja",
	[BPF_JEQ]  = "jeq",
	[BPF_JGT]  = "jgt",
	[BPF_JGE]  = "jge",
	[BPF_JSET] = "jset",
	[BPF_JNE]  = "jne",
	[BPF_JSGT] = "jsgt",
	[BPF_JSGE] = "jsge",
	[BPF_CALL] = "call",
	[BPF_EXIT] = "exit",
};

#define BPF_SRC(code)	((code) & 0x08)
#define	BPF_K		0x00
#define	BPF_X		0x08

static const uint16_t bpf_src_vars[] = {
	BPF_K, BPF_X,
};

static const char *bpf_src_vars_name[] = {
	[BPF_K] = "k",
	[BPF_X] = "x",
};

#define BPF_RVAL(code)	((code) & 0x18)
#define	BPF_A		0x10

static const uint16_t bpf_ret_vars[] = {
	BPF_A, BPF_K, BPF_X,
};

static const char *bpf_ret_vars_name[] = {
	[BPF_A] = "a",
	[BPF_K] = "k",
	[BPF_X] = "x",
};

#define BPF_MISCOP(code) ((code) & 0xf8)
#define	BPF_TAX		0x00
#define	BPF_TXA		0x80

static const uint16_t bpf_misc_vars[] = {
	BPF_TAX, BPF_TXA,
};

static const char *bpf_misc_vars_name[] = {
	[BPF_TAX] = "tax",
	[BPF_TXA] = "txa",
};

#define SECCOMP_RET_KILL	0x00000000U
#define SECCOMP_RET_TRAP	0x00030000U
#define SECCOMP_RET_ALLOW	0x7fff0000U

static const uint32_t bpf_seccomp_ret_k_vars[] = {
	SECCOMP_RET_KILL, SECCOMP_RET_TRAP, SECCOMP_RET_ALLOW,
};

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

static const uint32_t bpf_saner_vars[] = {
	BPF_LDX_B, BPF_LDX_W, BPF_JMP_JA, BPF_JMP_JEQ, BPF_JMP_JGT,
	BPF_JMP_JGE, BPF_JMP_JSET, BPF_ALU_ADD, BPF_ALU_SUB, BPF_ALU_MUL,
	BPF_ALU_DIV, BPF_ALU_MOD, BPF_ALU_NEG, BPF_ALU_AND, BPF_ALU_OR,
	BPF_ALU_XOR, BPF_ALU_LSH, BPF_ALU_RSH, BPF_MISC_TAX, BPF_MISC_TXA,
	BPF_LD_B, BPF_LD_H, BPF_LD_W, BPF_RET, BPF_ST, BPF_STX,
};

static const uint32_t bpf_seccomp_jmp_arch_vars[] = {
	AUDIT_ARCH_ALPHA, AUDIT_ARCH_ARM, AUDIT_ARCH_ARMEB, AUDIT_ARCH_CRIS,
	AUDIT_ARCH_FRV, AUDIT_ARCH_I386, AUDIT_ARCH_IA64,
	AUDIT_ARCH_M32R, AUDIT_ARCH_M68K, AUDIT_ARCH_MIPS, AUDIT_ARCH_MIPSEL,
	AUDIT_ARCH_MIPS64, AUDIT_ARCH_MIPSEL64, AUDIT_ARCH_PARISC,
	AUDIT_ARCH_PARISC64, AUDIT_ARCH_PPC, AUDIT_ARCH_PPC64, AUDIT_ARCH_S390,
	AUDIT_ARCH_S390X, AUDIT_ARCH_SH, AUDIT_ARCH_SHEL, AUDIT_ARCH_SH64,
	AUDIT_ARCH_SHEL64, AUDIT_ARCH_SPARC, AUDIT_ARCH_SPARC64,
	AUDIT_ARCH_X86_64,
};

#if defined(__i386__)
# define TRUE_REG_SYSCALL	REG_EAX
# define TRUE_ARCH		AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define TRUE_REG_SYSCALL	REG_RAX
# define TRUE_ARCH		AUDIT_ARCH_X86_64
#else
# define TRUE_REG_SYSCALL	((uint32_t) rnd()) /* TODO later */
# define TRUE_ARCH		((uint32_t) rnd()) /* TODO later */
#endif

struct seccomp_data {
	int nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};

#define bpf_rand(type) \
	(bpf_##type##_vars[rnd() % ARRAY_SIZE(bpf_##type##_vars)])

static const char * const op_table[] = {
#define OP(_op, _name)  [_op] = _name
	OP(BPF_ST,       "st"),
	OP(BPF_STX,      "stx"),
	OP(BPF_LD_B,     "ldb"),
	OP(BPF_LD_H,     "ldh"),
	OP(BPF_LD_W,     "ld"),
	OP(BPF_LDX,      "ldx"),
	OP(BPF_LDX_B,    "ldxb"),
	OP(BPF_JMP_JA,   "ja"),
	OP(BPF_JMP_JEQ,  "jeq"),
	OP(BPF_JMP_JGT,  "jgt"),
	OP(BPF_JMP_JGE,  "jge"),
	OP(BPF_JMP_JSET, "jset"),
	OP(BPF_ALU_ADD,  "add"),
	OP(BPF_ALU_SUB,  "sub"),
	OP(BPF_ALU_MUL,  "mul"),
	OP(BPF_ALU_DIV,  "div"),
	OP(BPF_ALU_MOD,  "mod"),
	OP(BPF_ALU_NEG,  "neg"),
	OP(BPF_ALU_AND,  "and"),
	OP(BPF_ALU_OR,   "or"),
	OP(BPF_ALU_XOR,  "xor"),
	OP(BPF_ALU_LSH,  "lsh"),
	OP(BPF_ALU_RSH,  "rsh"),
	OP(BPF_MISC_TAX, "tax"),
	OP(BPF_MISC_TXA, "txa"),
	OP(BPF_RET,      "ret"),
};

static void bpf_disasm(const struct sock_filter f, unsigned int i)
{
	const char *op, *fmt;
	int val = f.k;
	char buf[256], tmp[128];

	memset(tmp, 0, sizeof(tmp));

	switch (f.code) {
	case BPF_RET | BPF_K:
		op = op_table[BPF_RET];
		fmt = "#%#x";
		break;
	case BPF_RET | BPF_A:
		op = op_table[BPF_RET];
		fmt = "a";
		break;
	case BPF_RET | BPF_X:
		op = op_table[BPF_RET];
		fmt = "x";
		break;
	case BPF_MISC_TAX:
		op = op_table[BPF_MISC_TAX];
		fmt = "";
		break;
	case BPF_MISC_TXA:
		op = op_table[BPF_MISC_TXA];
		fmt = "";
		break;
	case BPF_ST:
		op = op_table[BPF_ST];
		fmt = "M[%d]";
		break;
	case BPF_STX:
		op = op_table[BPF_STX];
		fmt = "M[%d]";
		break;
	case BPF_LD_W | BPF_ABS:
		op = op_table[BPF_LD_W];
		fmt = "[%d]";
		break;
	case BPF_LD_H | BPF_ABS:
		op = op_table[BPF_LD_H];
		fmt = "[%d]";
		break;
	case BPF_LD_B | BPF_ABS:
		op = op_table[BPF_LD_B];
		fmt = "[%d]";
		break;
	case BPF_LD_W | BPF_LEN:
		op = op_table[BPF_LD_W];
		fmt = "#len";
		break;
	case BPF_LD_W | BPF_IND:
		op = op_table[BPF_LD_W];
		fmt = "[x+%d]";
		break;
	case BPF_LD_H | BPF_IND:
		op = op_table[BPF_LD_H];
		fmt = "[x+%d]";
		break;
	case BPF_LD_B | BPF_IND:
		op = op_table[BPF_LD_B];
		fmt = "[x+%d]";
		break;
	case BPF_LD | BPF_IMM:
		op = op_table[BPF_LD_W];
		fmt = "#%#x";
		break;
	case BPF_LDX | BPF_IMM:
		op = op_table[BPF_LDX];
		fmt = "#%#x";
		break;
	case BPF_LDX_B | BPF_MSH:
		op = op_table[BPF_LDX_B];
		fmt = "4*([%d]&0xf)";
		break;
	case BPF_LD | BPF_MEM:
		op = op_table[BPF_LD_W];
		fmt = "M[%d]";
		break;
	case BPF_LDX | BPF_MEM:
		op = op_table[BPF_LDX];
		fmt = "M[%d]";
		break;
	case BPF_JMP_JA:
		op = op_table[BPF_JMP_JA];
		fmt = "%d";
		val = i + 1 + f.k;
		break;
	case BPF_JMP_JGT | BPF_X:
		op = op_table[BPF_JMP_JGT];
		fmt = "x";
		break;
	case BPF_JMP_JGT | BPF_K:
		op = op_table[BPF_JMP_JGT];
		fmt = "#%#x";
		break;
	case BPF_JMP_JGE | BPF_X:
		op = op_table[BPF_JMP_JGE];
		fmt = "x";
		break;
	case BPF_JMP_JGE | BPF_K:
		op = op_table[BPF_JMP_JGE];
		fmt = "#%#x";
		break;
	case BPF_JMP_JEQ | BPF_X:
		op = op_table[BPF_JMP_JEQ];
		fmt = "x";
		break;
	case BPF_JMP_JEQ | BPF_K:
		op = op_table[BPF_JMP_JEQ];
		fmt = "#%#x";
		break;
	case BPF_JMP_JSET | BPF_X:
		op = op_table[BPF_JMP_JSET];
		fmt = "x";
		break;
	case BPF_JMP_JSET | BPF_K:
		op = op_table[BPF_JMP_JSET];
		fmt = "#%#x";
		break;
	case BPF_ALU_NEG:
		op = op_table[BPF_ALU_NEG];
		fmt = "";
		break;
	case BPF_ALU_LSH | BPF_X:
		op = op_table[BPF_ALU_LSH];
		fmt = "x";
		break;
	case BPF_ALU_LSH | BPF_K:
		op = op_table[BPF_ALU_LSH];
		fmt = "#%d";
		break;
	case BPF_ALU_RSH | BPF_X:
		op = op_table[BPF_ALU_RSH];
		fmt = "x";
		break;
	case BPF_ALU_RSH | BPF_K:
		op = op_table[BPF_ALU_RSH];
		fmt = "#%d";
		break;
	case BPF_ALU_ADD | BPF_X:
		op = op_table[BPF_ALU_ADD];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_K:
		op = op_table[BPF_ALU_ADD];
		fmt = "#%d";
		break;
	case BPF_ALU_SUB | BPF_X:
		op = op_table[BPF_ALU_SUB];
		fmt = "x";
		break;
	case BPF_ALU_SUB | BPF_K:
		op = op_table[BPF_ALU_SUB];
		fmt = "#%d";
		break;
	case BPF_ALU_MUL | BPF_X:
		op = op_table[BPF_ALU_MUL];
		fmt = "x";
		break;
	case BPF_ALU_MUL | BPF_K:
		op = op_table[BPF_ALU_MUL];
		fmt = "#%d";
		break;
	case BPF_ALU_DIV | BPF_X:
		op = op_table[BPF_ALU_DIV];
		fmt = "x";
		break;
	case BPF_ALU_DIV | BPF_K:
		op = op_table[BPF_ALU_DIV];
		fmt = "#%d";
		break;
	case BPF_ALU_MOD | BPF_X:
		op = op_table[BPF_ALU_MOD];
		fmt = "x";
		break;
	case BPF_ALU_MOD | BPF_K:
		op = op_table[BPF_ALU_MOD];
		fmt = "#%d";
		break;
	case BPF_ALU_AND | BPF_X:
		op = op_table[BPF_ALU_AND];
		fmt = "x";
		break;
	case BPF_ALU_AND | BPF_K:
		op = op_table[BPF_ALU_AND];
		fmt = "#%#x";
		break;
	case BPF_ALU_OR | BPF_X:
		op = op_table[BPF_ALU_OR];
		fmt = "x";
		break;
	case BPF_ALU_OR | BPF_K:
		op = op_table[BPF_ALU_OR];
		fmt = "#%#x";
		break;
	case BPF_ALU_XOR | BPF_X:
		op = op_table[BPF_ALU_XOR];
		fmt = "x";
		break;
	case BPF_ALU_XOR | BPF_K:
		op = op_table[BPF_ALU_XOR];
		fmt = "#%#x";
		break;
	default:
		/* Lets decode it step by step. */
		switch (BPF_CLASS(f.code)) {
		case BPF_LD:
		case BPF_LDX:
		case BPF_ST:
		case BPF_STX:
			snprintf(tmp, sizeof(tmp), "inv[%s] %s %s %s",
				 bpf_class_vars_name[BPF_CLASS(f.code)],
				 bpf_size_vars_name[BPF_SIZE(f.code)],
				 bpf_mode_vars_name[BPF_MODE(f.code)],
				 bpf_src_vars_name[BPF_SRC(f.code)]);
			goto cont;
		case BPF_ALU:
			snprintf(tmp, sizeof(tmp), "inv[%s] %s %s",
				 bpf_class_vars_name[BPF_CLASS(f.code)],
				 bpf_alu_op_vars_name[BPF_OP(f.code)],
				 bpf_src_vars_name[BPF_SRC(f.code)]);
			goto cont;
		case BPF_JMP:
			snprintf(tmp, sizeof(tmp), "inv[%s] %s %s",
				 bpf_class_vars_name[BPF_CLASS(f.code)],
				 bpf_jmp_op_vars_name[BPF_OP(f.code)],
				 bpf_src_vars_name[BPF_SRC(f.code)]);
			goto cont;
		case BPF_RET:
			snprintf(tmp, sizeof(tmp), "inv[%s] %s",
				 bpf_class_vars_name[BPF_CLASS(f.code)],
				 bpf_ret_vars_name[BPF_RVAL(f.code)]);
			goto cont;
		case BPF_MISC:
			snprintf(tmp, sizeof(tmp), "inv[%s] %s",
				 bpf_class_vars_name[BPF_CLASS(f.code)],
				 bpf_misc_vars_name[BPF_MISCOP(f.code)]);
			goto cont;
		default:
			snprintf(tmp, sizeof(tmp), "inv[??][%u,%u,%u,%u]",
				 f.code, f.jt, f.jf, f.k);
		}
cont:
		op = tmp;
		fmt = "%#x";
		val = f.code;
		break;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), fmt, val);
	buf[sizeof(buf) - 1] = 0;

	if ((BPF_CLASS(f.code) == BPF_JMP && BPF_OP(f.code) != BPF_JA))
		debugf("l%d:\t%s %s, l%d, l%d\n", i, op, buf,
			  i + 1 + f.jt, i + 1 + f.jf);
	else
		debugf("l%d:\t%s %s\n", i, op, buf);
}

static void bpf_disasm_all(const struct sock_filter *f, unsigned int len)
{
	unsigned int i;

	debugf("---filter-dump-start---\n");
	for (i = 0; i < len; i++)
		bpf_disasm(f[i], i);
	debugf("---filter-dump-end---\n");
}

static uint16_t gen_bpf_code_less_crazy(bool last_instr)
{
	uint16_t ret = bpf_rand(saner);

	if (last_instr)
		ret = BPF_RET;

	switch (ret) {
	case BPF_LD:
	case BPF_LDX:
		ret |= bpf_rand(mode);
		break;
	case BPF_ST:
	case BPF_STX:
		break;
	case BPF_ALU:
		ret |= bpf_rand(src);
		break;
	case BPF_JMP:
		ret |= bpf_rand(src);
		break;
	case BPF_RET:
		ret |= bpf_rand(ret);
		break;
	case BPF_MISC:
	default:
		break;
	}

	return ret;
}

static uint16_t gen_bpf_code_more_crazy(bool last_instr)
{
	uint16_t ret = bpf_rand(class);

	if (last_instr) {
		/* The kernel filter precheck code already tests if
		 * there's a return instruction as the last one, so
		 * increase the chance to be accepted and that we
		 * actually run the generated fuzz filter code.
		 */
		if (RAND_BOOL())
			ret = BPF_RET;
	}

	switch (ret) {
	case BPF_LD:
	case BPF_LDX:
	case BPF_ST:
	case BPF_STX:
		ret |= bpf_rand(size) | bpf_rand(mode);
		break;
	case BPF_ALU:
		ret |= bpf_rand(alu_op) | bpf_rand(src);
		break;
	case BPF_JMP:
		ret |= bpf_rand(jmp_op) | bpf_rand(src);
		break;
	case BPF_RET:
		ret |= bpf_rand(ret);
		break;
	case BPF_MISC:
	default:
		ret |= bpf_rand(misc);
		break;
	}

	/* Also give it a chance to fuzz some crap into it */
	if (ONE_IN(1000))
		ret |= (uint16_t) rnd();

	return ret;
}

static int seccomp_state;

enum {
	STATE_GEN_VALIDATE_ARCH    = 0,
	STATE_GEN_EXAMINE_SYSCALL  = 1,
	STATE_GEN_ALLOW_SYSCALL    = 2,
	STATE_GEN_KILL_PROCESS     = 3,
	STATE_GEN_RANDOM_CRAP      = 4,
	__STATE_GEN_MAX,
};

#define STATE_GEN_MAX	(__STATE_GEN_MAX - 1)

static const float
seccomp_markov[__STATE_GEN_MAX][__STATE_GEN_MAX] = {
	{ .1f,	.5f,	.3f,	.09f,	.01f },
	{ .1f,	.3f,	.5f,	.09f,	.01f },
	{ .1f,	.3f,	.5f,	.09f,	.01f },
	{ .2f,	.2f,	.3f,	.29f,	.01f },
	{ .2f,	.2f,	.2f,	.2f,	.2f  },
};

static const float seccomp_markov_init[__STATE_GEN_MAX] = {
	.5f, .3f, .1f, .05f, .05f
};

static int gen_seccomp_bpf_code(struct sock_filter *curr)
{
	int used = 0;
	struct sock_filter validate_arch[] = {
		BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, arch_nr),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
	};
	struct sock_filter examine_syscall[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr),
	};
	struct sock_filter allow_syscall[] = {
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_filter kill_process[] = {
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
	};

	switch (seccomp_state) {
	case STATE_GEN_VALIDATE_ARCH:
		used = 3;
		memcpy(curr, validate_arch, sizeof(validate_arch));
		/* Randomize architecture */
		if (ONE_IN(3))
			curr[0].k = bpf_rand(seccomp_jmp_arch);
		else
			curr[0].k = TRUE_ARCH;
		break;
	case STATE_GEN_EXAMINE_SYSCALL:
		used = 1;
		memcpy(curr, examine_syscall, sizeof(examine_syscall));
		break;
	case STATE_GEN_ALLOW_SYSCALL:
		used = 2;
		memcpy(curr, allow_syscall, sizeof(allow_syscall));
		/* We assume here that max_nr_syscalls was computed before */
		curr[0].k = rnd() % max_nr_syscalls;
		break;
	case STATE_GEN_KILL_PROCESS:
		used = 1;
		memcpy(curr, kill_process, sizeof(kill_process));
		if (ONE_IN(3))
			/* Variate between seccomp ret values */
			curr[0].k = bpf_rand(seccomp_ret_k);
		break;
	default:
	case STATE_GEN_RANDOM_CRAP:
		used = 1;
		curr->code = (uint16_t) rnd();
		curr->jt = (uint8_t) rnd();
		curr->jf = (uint8_t) rnd();
		curr->k = rand32();
		break;
	}

	/* Also give it a tiny chance to fuzz some crap into it */
	if (ONE_IN(10000))
		curr[0].code |= (uint16_t) rnd();
	if (ONE_IN(10000))
		curr[1].code |= (uint16_t) rnd();
	if (ONE_IN(10000))
		curr[2].code |= (uint16_t) rnd();

	return used;
}

static int seccomp_choose(const float probs[__STATE_GEN_MAX])
{
	int i;
	float sum = .001f;
	float thr = (float) rnd() / (float) RAND_MAX;

	for (i = 0; i < __STATE_GEN_MAX; ++i) {
		sum += probs[i];
		if (sum > thr)
			return i;
	}

	BUG("wrong state\n");
	return -1;
}

void bpf_gen_seccomp(unsigned long **addr, unsigned long *addrlen)
{
	int avail;
	struct sock_filter *curr;
	struct sock_fprog *bpf = (void *) *addr;

	if (addrlen != NULL && bpf == NULL)
		bpf = zmalloc(sizeof(struct sock_fprog));

	bpf->len = avail = rnd() % 50;
	/* Give it from time to time a chance to load big filters as well. */
	if (ONE_IN(1000))
		bpf->len = avail = rnd() % BPF_MAXINSNS;
	if (bpf->len == 0)
		bpf->len = avail = 50;

	bpf->filter = zmalloc(bpf->len * sizeof(struct sock_filter));

	seccomp_state = seccomp_choose(seccomp_markov_init);

	for (curr = bpf->filter; avail > 3; ) {
		int used;

		used = gen_seccomp_bpf_code(curr);
		curr  += used;
		avail -= used;

		seccomp_state = seccomp_choose(seccomp_markov[seccomp_state]);
	}

	*addr = (void *) bpf;
	if (addrlen != NULL)
		*addrlen = sizeof(struct sock_fprog);

	if (dump_bpf)
		bpf_disasm_all(bpf->filter, bpf->len);
}

void bpf_gen_filter(unsigned long **addr, unsigned long *addrlen)
{
	int i;
	struct sock_fprog *bpf = (void *) *addr;

	if (addrlen != NULL && bpf == NULL)
		bpf = zmalloc(sizeof(struct sock_fprog));

	bpf->len = rnd() % 10;
	/* Give it from time to time a chance to load big filters as well. */
	if (ONE_IN(100))
		bpf->len = rnd() % 100;
	if (ONE_IN(1000))
		bpf->len = rnd() % BPF_MAXINSNS;
	if (bpf->len == 0)
		bpf->len = 50;

	bpf->filter = zmalloc(bpf->len * sizeof(struct sock_filter));

	for (i = 0; i < bpf->len; i++) {
		if (ONE_IN(100))
			bpf->filter[i].code = gen_bpf_code_more_crazy(i == bpf->len - 1);
		else
			bpf->filter[i].code = gen_bpf_code_less_crazy(i == bpf->len - 1);

		/* Fill out jump offsets if jmp instruction */
		if (BPF_CLASS(bpf->filter[i].code) == BPF_JMP) {
			bpf->filter[i].jt = (uint8_t) rnd() % bpf->len;
			bpf->filter[i].jf = (uint8_t) rnd() % bpf->len;
		}

		/* Also give it a chance if not BPF_JMP */
		if (ONE_IN(100))
			bpf->filter[i].jt |= (uint8_t) rnd();
		if (ONE_IN(100))
			bpf->filter[i].jf |= (uint8_t) rnd();

		/* Not always fill out k */
		switch (rnd() % 3) {
		case 0:	bpf->filter[i].k = (uint32_t) rand32();
			break;
		case 1:	bpf->filter[i].k = (uint32_t) get_rand_bpf_fd();
			break;
		case 2:	break;
		}

		/* Also try to jump into BPF extensions by chance */
		if (BPF_CLASS(bpf->filter[i].code) == BPF_LD ||
		    BPF_CLASS(bpf->filter[i].code) == BPF_LDX) {
			if (bpf->filter[i].k > 65000 &&
			    bpf->filter[i].k < (uint32_t) SKF_AD_OFF) {
				if (ONE_IN(10)) {
					bpf->filter[i].k = (uint32_t) (SKF_AD_OFF +
							   rnd() % SKF_AD_MAX);
				}
			}
		}

		/* In case of M[] access, kernel checks it anyway,
		 * so do not go out of bounds.
		 */
		if (BPF_CLASS(bpf->filter[i].code) == BPF_ST  ||
		    BPF_CLASS(bpf->filter[i].code) == BPF_STX ||
		    (BPF_CLASS(bpf->filter[i].code) == BPF_LD &&
		     BPF_MODE(bpf->filter[i].code) == BPF_MEM) ||
		    (BPF_CLASS(bpf->filter[i].code) == BPF_LDX &&
		     BPF_MODE(bpf->filter[i].code) == BPF_MEM))
			bpf->filter[i].k = (uint32_t) (rnd() % 16);
	}

	*addr = (void *) bpf;
	if (addrlen != NULL)
		*addrlen = sizeof(struct sock_fprog);

	if (dump_bpf)
		bpf_disasm_all(bpf->filter, bpf->len);
}
#endif
