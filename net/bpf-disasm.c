#include <linux/filter.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "utils.h"
#include "bpf-internal.h"

#ifdef USE_BPF

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

static const char *bpf_size_vars_name[] = {
	[BPF_W] = "w",
	[BPF_H] = "h",
	[BPF_B] = "b",
	[BPF_DW] = "dw",
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

static const char *bpf_src_vars_name[] = {
	[BPF_K] = "k",
	[BPF_X] = "x",
};

static const char *bpf_ret_vars_name[] = {
	[BPF_A] = "a",
	[BPF_K] = "k",
	[BPF_X] = "x",
};

static const char *bpf_misc_vars_name[] = {
	[BPF_TAX] = "tax",
	[BPF_TXA] = "txa",
};

#define SAFE_NAME(table, idx) \
	(((idx) < ARRAY_SIZE(table) && (table)[idx]) ? (table)[idx] : "?")

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

static void decode_mem(const struct sock_filter f,
		       const char **op, const char **fmt, int *val,
		       char *tmp, size_t tmplen)
{
	switch (f.code) {
	case BPF_ST:
		*op = op_table[BPF_ST];
		*fmt = "M[%d]";
		return;
	case BPF_STX:
		*op = op_table[BPF_STX];
		*fmt = "M[%d]";
		return;
	case BPF_LD_W | BPF_ABS:
		*op = op_table[BPF_LD_W];
		*fmt = "[%d]";
		return;
	case BPF_LD_H | BPF_ABS:
		*op = op_table[BPF_LD_H];
		*fmt = "[%d]";
		return;
	case BPF_LD_B | BPF_ABS:
		*op = op_table[BPF_LD_B];
		*fmt = "[%d]";
		return;
	case BPF_LD_W | BPF_LEN:
		*op = op_table[BPF_LD_W];
		*fmt = "#len";
		return;
	case BPF_LD_W | BPF_IND:
		*op = op_table[BPF_LD_W];
		*fmt = "[x+%d]";
		return;
	case BPF_LD_H | BPF_IND:
		*op = op_table[BPF_LD_H];
		*fmt = "[x+%d]";
		return;
	case BPF_LD_B | BPF_IND:
		*op = op_table[BPF_LD_B];
		*fmt = "[x+%d]";
		return;
	case BPF_LD | BPF_IMM:
		*op = op_table[BPF_LD_W];
		*fmt = "#%#x";
		return;
	case BPF_LDX | BPF_IMM:
		*op = op_table[BPF_LDX];
		*fmt = "#%#x";
		return;
	case BPF_LDX_B | BPF_MSH:
		*op = op_table[BPF_LDX_B];
		*fmt = "4*([%d]&0xf)";
		return;
	case BPF_LD | BPF_MEM:
		*op = op_table[BPF_LD_W];
		*fmt = "M[%d]";
		return;
	case BPF_LDX | BPF_MEM:
		*op = op_table[BPF_LDX];
		*fmt = "M[%d]";
		return;
	}
	/* Lets decode it step by step. */
	snprintf(tmp, tmplen, "inv[%s] %s %s %s",
		 SAFE_NAME(bpf_class_vars_name, BPF_CLASS(f.code)),
		 SAFE_NAME(bpf_size_vars_name, BPF_SIZE(f.code)),
		 SAFE_NAME(bpf_mode_vars_name, BPF_MODE(f.code)),
		 SAFE_NAME(bpf_src_vars_name, BPF_SRC(f.code)));
	*op = tmp;
	*fmt = "%#x";
	*val = f.code;
}

static void decode_jmp(const struct sock_filter f, unsigned int i,
		       const char **op, const char **fmt, int *val,
		       char *tmp, size_t tmplen)
{
	switch (f.code) {
	case BPF_JMP_JA:
		*op = op_table[BPF_JMP_JA];
		*fmt = "%d";
		*val = i + 1 + f.k;
		return;
	case BPF_JMP_JGT | BPF_X:
		*op = op_table[BPF_JMP_JGT];
		*fmt = "x";
		return;
	case BPF_JMP_JGT | BPF_K:
		*op = op_table[BPF_JMP_JGT];
		*fmt = "#%#x";
		return;
	case BPF_JMP_JGE | BPF_X:
		*op = op_table[BPF_JMP_JGE];
		*fmt = "x";
		return;
	case BPF_JMP_JGE | BPF_K:
		*op = op_table[BPF_JMP_JGE];
		*fmt = "#%#x";
		return;
	case BPF_JMP_JEQ | BPF_X:
		*op = op_table[BPF_JMP_JEQ];
		*fmt = "x";
		return;
	case BPF_JMP_JEQ | BPF_K:
		*op = op_table[BPF_JMP_JEQ];
		*fmt = "#%#x";
		return;
	case BPF_JMP_JSET | BPF_X:
		*op = op_table[BPF_JMP_JSET];
		*fmt = "x";
		return;
	case BPF_JMP_JSET | BPF_K:
		*op = op_table[BPF_JMP_JSET];
		*fmt = "#%#x";
		return;
	}
	snprintf(tmp, tmplen, "inv[%s] %s %s",
		 SAFE_NAME(bpf_class_vars_name, BPF_CLASS(f.code)),
		 SAFE_NAME(bpf_jmp_op_vars_name, BPF_OP(f.code)),
		 SAFE_NAME(bpf_src_vars_name, BPF_SRC(f.code)));
	*op = tmp;
	*fmt = "%#x";
	*val = f.code;
}

static void decode_alu(const struct sock_filter f,
		       const char **op, const char **fmt, int *val,
		       char *tmp, size_t tmplen)
{
	switch (f.code) {
	case BPF_ALU_NEG:
		*op = op_table[BPF_ALU_NEG];
		*fmt = "";
		return;
	case BPF_ALU_LSH | BPF_X:
		*op = op_table[BPF_ALU_LSH];
		*fmt = "x";
		return;
	case BPF_ALU_LSH | BPF_K:
		*op = op_table[BPF_ALU_LSH];
		*fmt = "#%d";
		return;
	case BPF_ALU_RSH | BPF_X:
		*op = op_table[BPF_ALU_RSH];
		*fmt = "x";
		return;
	case BPF_ALU_RSH | BPF_K:
		*op = op_table[BPF_ALU_RSH];
		*fmt = "#%d";
		return;
	case BPF_ALU_ADD | BPF_X:
		*op = op_table[BPF_ALU_ADD];
		*fmt = "x";
		return;
	case BPF_ALU_ADD | BPF_K:
		*op = op_table[BPF_ALU_ADD];
		*fmt = "#%d";
		return;
	case BPF_ALU_SUB | BPF_X:
		*op = op_table[BPF_ALU_SUB];
		*fmt = "x";
		return;
	case BPF_ALU_SUB | BPF_K:
		*op = op_table[BPF_ALU_SUB];
		*fmt = "#%d";
		return;
	case BPF_ALU_MUL | BPF_X:
		*op = op_table[BPF_ALU_MUL];
		*fmt = "x";
		return;
	case BPF_ALU_MUL | BPF_K:
		*op = op_table[BPF_ALU_MUL];
		*fmt = "#%d";
		return;
	case BPF_ALU_DIV | BPF_X:
		*op = op_table[BPF_ALU_DIV];
		*fmt = "x";
		return;
	case BPF_ALU_DIV | BPF_K:
		*op = op_table[BPF_ALU_DIV];
		*fmt = "#%d";
		return;
	case BPF_ALU_MOD | BPF_X:
		*op = op_table[BPF_ALU_MOD];
		*fmt = "x";
		return;
	case BPF_ALU_MOD | BPF_K:
		*op = op_table[BPF_ALU_MOD];
		*fmt = "#%d";
		return;
	case BPF_ALU_AND | BPF_X:
		*op = op_table[BPF_ALU_AND];
		*fmt = "x";
		return;
	case BPF_ALU_AND | BPF_K:
		*op = op_table[BPF_ALU_AND];
		*fmt = "#%#x";
		return;
	case BPF_ALU_OR | BPF_X:
		*op = op_table[BPF_ALU_OR];
		*fmt = "x";
		return;
	case BPF_ALU_OR | BPF_K:
		*op = op_table[BPF_ALU_OR];
		*fmt = "#%#x";
		return;
	case BPF_ALU_XOR | BPF_X:
		*op = op_table[BPF_ALU_XOR];
		*fmt = "x";
		return;
	case BPF_ALU_XOR | BPF_K:
		*op = op_table[BPF_ALU_XOR];
		*fmt = "#%#x";
		return;
	}
	snprintf(tmp, tmplen, "inv[%s] %s %s",
		 SAFE_NAME(bpf_class_vars_name, BPF_CLASS(f.code)),
		 SAFE_NAME(bpf_alu_op_vars_name, BPF_OP(f.code)),
		 SAFE_NAME(bpf_src_vars_name, BPF_SRC(f.code)));
	*op = tmp;
	*fmt = "%#x";
	*val = f.code;
}

static void decode_ret(const struct sock_filter f,
		       const char **op, const char **fmt, int *val,
		       char *tmp, size_t tmplen)
{
	switch (f.code) {
	case BPF_RET | BPF_K:
		*op = op_table[BPF_RET];
		*fmt = "#%#x";
		return;
	case BPF_RET | BPF_A:
		*op = op_table[BPF_RET];
		*fmt = "a";
		return;
	case BPF_RET | BPF_X:
		*op = op_table[BPF_RET];
		*fmt = "x";
		return;
	}
	snprintf(tmp, tmplen, "inv[%s] %s",
		 SAFE_NAME(bpf_class_vars_name, BPF_CLASS(f.code)),
		 SAFE_NAME(bpf_ret_vars_name, BPF_RVAL(f.code)));
	*op = tmp;
	*fmt = "%#x";
	*val = f.code;
}

static void decode_misc(const struct sock_filter f,
			const char **op, const char **fmt, int *val,
			char *tmp, size_t tmplen)
{
	switch (f.code) {
	case BPF_MISC_TAX:
		*op = op_table[BPF_MISC_TAX];
		*fmt = "";
		return;
	case BPF_MISC_TXA:
		*op = op_table[BPF_MISC_TXA];
		*fmt = "";
		return;
	}
	snprintf(tmp, tmplen, "inv[%s] %s",
		 SAFE_NAME(bpf_class_vars_name, BPF_CLASS(f.code)),
		 SAFE_NAME(bpf_misc_vars_name, BPF_MISCOP(f.code)));
	*op = tmp;
	*fmt = "%#x";
	*val = f.code;
}

static void bpf_disasm(const struct sock_filter f, unsigned int i)
{
	const char *op = NULL, *fmt = NULL;
	int val = f.k;
	char buf[256], tmp[128];

	memset(tmp, 0, sizeof(tmp));

	switch (BPF_CLASS(f.code)) {
	case BPF_LD:
	case BPF_LDX:
	case BPF_ST:
	case BPF_STX:
		decode_mem(f, &op, &fmt, &val, tmp, sizeof(tmp));
		break;
	case BPF_JMP:
		decode_jmp(f, i, &op, &fmt, &val, tmp, sizeof(tmp));
		break;
	case BPF_ALU:
		decode_alu(f, &op, &fmt, &val, tmp, sizeof(tmp));
		break;
	case BPF_RET:
		decode_ret(f, &op, &fmt, &val, tmp, sizeof(tmp));
		break;
	case BPF_MISC:
		decode_misc(f, &op, &fmt, &val, tmp, sizeof(tmp));
		break;
	default:
		snprintf(tmp, sizeof(tmp), "inv[??][%u,%u,%u,%u]",
			 f.code, f.jt, f.jf, f.k);
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

void bpf_disasm_all(const struct sock_filter *f, unsigned int len)
{
	unsigned int i;

	debugf("---filter-dump-start---\n");
	for (i = 0; i < len; i++)
		bpf_disasm(f[i], i);
	debugf("---filter-dump-end---\n");
}
#endif
