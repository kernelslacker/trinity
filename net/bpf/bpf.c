#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>

#include "bpf.h"
#include "internal.h"
#include "arch.h"
#include "debug.h"
#include "deferred-free.h"
#include "net.h"
#include "params.h"
#include "random.h"
#include "trinity.h"	// MAX_LOGLEVEL
#include "tables.h"
#include "rnd.h"
#include "utils.h"

#include "kernel/seccomp.h"
#ifdef USE_BPF
/**
 * BPF filters are used in networking such as in pf_packet, but also
 * in seccomp for application sand-boxing. Additionally, with arch
 * specific BPF JIT compilers, this might be good to fuzz for errors.
 *    -- Daniel Borkmann, <borkmann@redhat.com>
 */


/* Both here likely defined in linux/filter.h already */
#ifndef SKF_AD_OFF
# define SKF_AD_OFF	(-0x1000)
#endif

#ifndef SKF_AD_MAX
# define SKF_AD_MAX	56
#endif

#define syscall_nr	(offsetof(struct seccomp_data, nr))
#define arch_nr		(offsetof(struct seccomp_data, arch))

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER	2
#endif

static const uint16_t bpf_class_vars[] = {
	BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC,
};

static const uint16_t bpf_size_vars[] = {
	BPF_W, BPF_H, BPF_B, BPF_DW,
};

static const uint16_t bpf_mode_vars[] = {
	BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM, BPF_LEN, BPF_MSH, BPF_XADD,
};

static const uint16_t bpf_alu_op_vars[] = {
	BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH,
	BPF_NEG, BPF_MOD, BPF_XOR, BPF_MOV, BPF_ARSH, BPF_END,
};

static const uint16_t bpf_jmp_op_vars[] = {
	BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET,
	BPF_JNE, BPF_JSGT, BPF_JSGE, BPF_CALL, BPF_EXIT,
};

static const uint16_t bpf_src_vars[] = {
	BPF_K, BPF_X,
};

static const uint16_t bpf_ret_vars[] = {
	BPF_A, BPF_K, BPF_X,
};

static const uint16_t bpf_misc_vars[] = {
	BPF_TAX, BPF_TXA,
};

#ifndef SECCOMP_RET_KILL
#define SECCOMP_RET_KILL	0x00000000U
#define SECCOMP_RET_TRAP	0x00030000U
#define SECCOMP_RET_ALLOW	0x7fff0000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO	0x00050000U
#endif
#ifndef SECCOMP_RET_TRACE
#define SECCOMP_RET_TRACE	0x7ff00000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG		0x7ffc0000U
#endif

static const uint32_t bpf_seccomp_ret_k_vars[] = {
	SECCOMP_RET_KILL, SECCOMP_RET_KILL_PROCESS,
	SECCOMP_RET_TRAP, SECCOMP_RET_ERRNO,
	SECCOMP_RET_USER_NOTIF, SECCOMP_RET_TRACE,
	SECCOMP_RET_LOG, SECCOMP_RET_ALLOW,
};

static const uint32_t bpf_saner_vars[] = {
	BPF_LDX_B, BPF_LDX_W, BPF_JMP_JA, BPF_JMP_JEQ, BPF_JMP_JGT,
	BPF_JMP_JGE, BPF_JMP_JSET, BPF_ALU_ADD, BPF_ALU_SUB, BPF_ALU_MUL,
	BPF_ALU_DIV, BPF_ALU_MOD, BPF_ALU_NEG, BPF_ALU_AND, BPF_ALU_OR,
	BPF_ALU_XOR, BPF_ALU_LSH, BPF_ALU_RSH, BPF_MISC_TAX, BPF_MISC_TXA,
	BPF_LD_B, BPF_LD_H, BPF_LD_W, BPF_RET, BPF_ST, BPF_STX,
};

static const uint32_t bpf_seccomp_jmp_arch_vars[] = {
	AUDIT_ARCH_ALPHA, AUDIT_ARCH_ARM, AUDIT_ARCH_ARMEB,
	AUDIT_ARCH_I386,
	AUDIT_ARCH_M68K, AUDIT_ARCH_MIPS, AUDIT_ARCH_MIPSEL,
	AUDIT_ARCH_MIPS64, AUDIT_ARCH_MIPSEL64, AUDIT_ARCH_PARISC,
	AUDIT_ARCH_PARISC64, AUDIT_ARCH_PPC, AUDIT_ARCH_PPC64, AUDIT_ARCH_S390,
	AUDIT_ARCH_S390X, AUDIT_ARCH_SH, AUDIT_ARCH_SHEL,
	AUDIT_ARCH_SPARC, AUDIT_ARCH_SPARC64,
	AUDIT_ARCH_X86_64,
};

#if defined(__i386__)
# define TRUE_REG_SYSCALL	REG_EAX
# define TRUE_ARCH		AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define TRUE_REG_SYSCALL	REG_RAX
# define TRUE_ARCH		AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_AARCH64
#elif defined(__arm__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_ARM
#elif defined(__powerpc64__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_PPC64
#elif defined(__powerpc__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_PPC
#elif defined(__s390x__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_S390X
#elif defined(__s390__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_S390
#elif defined(__mips__) && defined(__LP64__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_MIPS64
#elif defined(__mips__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_MIPS
#elif defined(__sparc__) && defined(__LP64__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_SPARC64
#elif defined(__sparc__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_SPARC
#elif defined(__alpha__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_ALPHA
#elif defined(__sh__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_SH
#elif defined(__hppa__) && defined(__LP64__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_PARISC64
#elif defined(__hppa__)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_PARISC
#elif defined(__riscv) && (__riscv_xlen == 64)
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		AUDIT_ARCH_RISCV64
#else
# define TRUE_REG_SYSCALL	syscall_nr
# define TRUE_ARCH		(rnd_u32())
#endif

#ifndef _LINUX_SECCOMP_H
struct seccomp_data {
	int nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};
#endif

#define bpf_rand(type) \
	(bpf_##type##_vars[rnd_modulo_u32(ARRAY_SIZE(bpf_##type##_vars))])


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
		ret |= (uint16_t) rnd_u32();

	return ret;
}

enum {
	STATE_GEN_VALIDATE_ARCH    = 0,
	STATE_GEN_EXAMINE_SYSCALL  = 1,
	STATE_GEN_ALLOW_SYSCALL    = 2,
	STATE_GEN_KILL_PROCESS     = 3,
	STATE_GEN_RANDOM_CRAP      = 4,
	__STATE_GEN_MAX,
};

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

static int gen_seccomp_bpf_code(struct sock_filter *curr, int state)
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

	switch (state) {
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
		/* Pick a syscall nr from whichever table is active. */
		if (biarch) {
			if (syscalls == syscalls_32bit)
				curr[0].k = rnd_modulo_u32(max_nr_32bit_syscalls);
			else
				curr[0].k = rnd_modulo_u32(max_nr_64bit_syscalls);
		} else {
			curr[0].k = rnd_modulo_u32(max_nr_syscalls);
		}
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
		/* Mask to the cBPF instruction-class bits (BPF_CLASS = 0x07).
		 * Picking an arbitrary uint16 here mostly produces opcodes from
		 * the eBPF-only space (e.g. BPF_CALL=0x85, BPF_EXIT=0x95), which
		 * the kernel's bpf_check_classic() rejects up-front before the
		 * filter ever gets exercised. The ONE_IN(10000) arm below can
		 * still OR in more random bits when we want to push beyond the
		 * class set. */
		curr->code = (uint16_t) rnd_u32() & 0x07;
		curr->jt = (uint8_t) rnd_u32();
		curr->jf = (uint8_t) rnd_u32();
		curr->k = rand32();
		break;
	}

	/* Also give it a tiny chance to fuzz some crap into it */
	if (ONE_IN(10000))
		curr[0].code |= (uint16_t) rnd_u32();
	if (used > 1 && ONE_IN(10000))
		curr[1].code |= (uint16_t) rnd_u32();
	if (used > 2 && ONE_IN(10000))
		curr[2].code |= (uint16_t) rnd_u32();

	return used;
}

static int seccomp_choose(const float probs[__STATE_GEN_MAX])
{
	int i;
	float sum = .001f;
	float thr = (float) rnd_u32() / (float) UINT32_MAX;

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
	int state;
	struct sock_filter *curr;
	struct sock_fprog *bpf = (void *) *addr;

	if (addrlen != NULL && bpf == NULL)
		bpf = zmalloc_tracked(sizeof(struct sock_fprog));

	if (bpf == NULL)
		return;

	bpf->len = avail = rnd_modulo_u32(50);
	/* Give it from time to time a chance to load big filters as well. */
	if (ONE_IN(1000))
		bpf->len = avail = rnd_modulo_u32(BPF_MAXINSNS);
	if (bpf->len == 0)
		bpf->len = avail = 50;

	bpf->filter = zmalloc_tracked(bpf->len * sizeof(struct sock_filter));

	state = seccomp_choose(seccomp_markov_init);

	for (curr = bpf->filter; avail > 3; ) {
		int used;

		used = gen_seccomp_bpf_code(curr, state);
		curr  += used;
		avail -= used;

		state = seccomp_choose(seccomp_markov[state]);
	}

	*addr = (void *) bpf;
	if (addrlen != NULL)
		*addrlen = sizeof(struct sock_fprog);

	if (verbosity >= MAX_LOGLEVEL)
		bpf_disasm_all(bpf->filter, bpf->len);
}

void bpf_gen_filter(unsigned long **addr, unsigned long *addrlen)
{
	int i;
	struct sock_fprog *bpf = (void *) *addr;

	if (addrlen != NULL && bpf == NULL)
		bpf = zmalloc_tracked(sizeof(struct sock_fprog));

	if (bpf == NULL)
		return;

	bpf->len = rnd_modulo_u32(10);
	/* Give it from time to time a chance to load big filters as well. */
	if (ONE_IN(100))
		bpf->len = rnd_modulo_u32(100);
	if (ONE_IN(1000))
		bpf->len = rnd_modulo_u32(BPF_MAXINSNS);
	if (bpf->len == 0)
		bpf->len = 50;

	bpf->filter = zmalloc_tracked(bpf->len * sizeof(struct sock_filter));

	for (i = 0; i < bpf->len; i++) {
		if (ONE_IN(100))
			bpf->filter[i].code = gen_bpf_code_more_crazy(i == bpf->len - 1);
		else
			bpf->filter[i].code = gen_bpf_code_less_crazy(i == bpf->len - 1);

		/* Fill out jump offsets if jmp instruction */
		if (BPF_CLASS(bpf->filter[i].code) == BPF_JMP) {
			bpf->filter[i].jt = (uint8_t) (rnd_modulo_u32(bpf->len));
			bpf->filter[i].jf = (uint8_t) (rnd_modulo_u32(bpf->len));
		}

		/* Also give it a chance if not BPF_JMP */
		if (ONE_IN(100))
			bpf->filter[i].jt |= (uint8_t) rnd_u32();
		if (ONE_IN(100))
			bpf->filter[i].jf |= (uint8_t) rnd_u32();

		/* Not always fill out k */
		switch (rnd_modulo_u32(3)) {
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
							   rnd_modulo_u32(SKF_AD_MAX));
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
			bpf->filter[i].k = (uint32_t) (rnd_modulo_u32(16));
	}

	*addr = (void *) bpf;
	if (addrlen != NULL)
		*addrlen = sizeof(struct sock_fprog);

	if (verbosity >= MAX_LOGLEVEL)
		bpf_disasm_all(bpf->filter, bpf->len);
}

/*
 * Two-tier free for a sock_fprog produced by bpf_gen_filter(): inner
 * filter buffer and outer wrapper are independent zmalloc_tracked()
 * allocations.  Both go through deferred_free_enqueue() so the alloc
 * tracker consumes their entries on the same path as every other
 * sanitise-time allocation -- direct free() on the outer wrapper would
 * bypass the consume step and leave a stale tracker slot to be evicted
 * by LRU, and the inner buffer needs explicit handling because the
 * wrapper-tracking fix in f9913742ec91 only tagged the outer alloc.
 *
 * Helper-boundary validation: the .post paths in syscalls/setsockopt.c,
 * syscalls/seccomp.c and syscalls/prctl.c already gate the wrapper with
 * alloc_track_lookup() || range_readable_user() before reaching us, but
 * syscalls/bpf.c's BPF_PROG_LOAD classic-BPF cleanup calls in directly
 * from snap->classic_bpf_insns + attr->insns -- a sibling-scribbled
 * attr->insns that survives the snap shape check would fault on the
 * bpf->filter deref here.  Prove the wrapper inside the helper so the
 * direct caller is safe and the .post-path callers stay double-gated
 * without per-file edits.  Same shape as those callers: tracked
 * allocation (definitively one we produced via zmalloc_tracked in
 * bpf_gen_filter / bpf_gen_seccomp) or at minimum readable for a
 * sock_fprog-sized window.
 *
 * Inner-filter free is alloc_track_lookup()-only: free what we own,
 * leak the unproven.  A readable-but-untracked inner pointer (a wild
 * fuzz pointer that happens to land in a real mapping) is deliberately
 * left to leak rather than handed to deferred_free_enqueue() ->
 * tracked_free_now(), which resolves an alloc_track miss to free() on
 * a foreign chunk (deferred-free.c:525-532).  The outer wrapper still
 * enqueues so the post_state / tracker slot releases.
 */
void bpf_free_filter(struct sock_fprog *bpf)
{
	if (bpf == NULL)
		return;

	if (alloc_track_lookup(bpf) ||
	    range_readable_user(bpf, sizeof(struct sock_fprog))) {
		if (bpf->filter != NULL && alloc_track_lookup(bpf->filter))
			deferred_free_enqueue(bpf->filter);
	}

	deferred_free_enqueue(bpf);
}
#endif
