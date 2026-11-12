#include <linux/unistd.h>
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

#include "kernel/audit.h"
#include "kernel/filter.h"
#include "kernel/seccomp.h"

/*
 * Set in a child once a seccomp filter of its own, one bpf_gen_seccomp()
 * built, has installed in it.  From then on a call the filter matches can
 * fail by its hand, with the errno an ERRNO return names or the ENOSYS a
 * TRACE or USER_NOTIF return gets with no tracer or listener attached, so
 * what such a child sees no longer speaks for the kernel alone and must not
 * settle what the rest of the fleet believes about it.
 */
bool seccomp_own_filter;

#ifdef USE_BPF
/**
 * BPF filters are used in networking such as in pf_packet, but also
 * in seccomp for application sand-boxing. Additionally, with arch
 * specific BPF JIT compilers, this might be good to fuzz for errors.
 *    -- Daniel Borkmann, <borkmann@redhat.com>
 */

#define syscall_nr	(offsetof(struct seccomp_data, nr))
#define arch_nr		(offsetof(struct seccomp_data, arch))

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

/* The opcodes chk_code_allowed() (net/core/filter.c) takes. */
static const uint16_t bpf_saner_vars[] = {
	BPF_ALU | BPF_ADD | BPF_K, BPF_ALU | BPF_ADD | BPF_X,
	BPF_ALU | BPF_SUB | BPF_K, BPF_ALU | BPF_SUB | BPF_X,
	BPF_ALU | BPF_MUL | BPF_K, BPF_ALU | BPF_MUL | BPF_X,
	BPF_ALU | BPF_DIV | BPF_K, BPF_ALU | BPF_DIV | BPF_X,
	BPF_ALU | BPF_MOD | BPF_K, BPF_ALU | BPF_MOD | BPF_X,
	BPF_ALU | BPF_AND | BPF_K, BPF_ALU | BPF_AND | BPF_X,
	BPF_ALU | BPF_OR | BPF_K, BPF_ALU | BPF_OR | BPF_X,
	BPF_ALU | BPF_XOR | BPF_K, BPF_ALU | BPF_XOR | BPF_X,
	BPF_ALU | BPF_LSH | BPF_K, BPF_ALU | BPF_LSH | BPF_X,
	BPF_ALU | BPF_RSH | BPF_K, BPF_ALU | BPF_RSH | BPF_X,
	BPF_ALU | BPF_NEG,
	BPF_LD | BPF_W | BPF_ABS, BPF_LD | BPF_H | BPF_ABS,
	BPF_LD | BPF_B | BPF_ABS, BPF_LD | BPF_W | BPF_LEN,
	BPF_LD | BPF_W | BPF_IND, BPF_LD | BPF_H | BPF_IND,
	BPF_LD | BPF_B | BPF_IND, BPF_LD | BPF_IMM, BPF_LD | BPF_MEM,
	BPF_LDX | BPF_W | BPF_LEN, BPF_LDX | BPF_B | BPF_MSH,
	BPF_LDX | BPF_IMM, BPF_LDX | BPF_MEM,
	BPF_ST, BPF_STX,
	BPF_MISC | BPF_TAX, BPF_MISC | BPF_TXA,
	BPF_RET | BPF_K, BPF_RET | BPF_A,
	BPF_JMP | BPF_JA,
	BPF_JMP | BPF_JEQ | BPF_K, BPF_JMP | BPF_JEQ | BPF_X,
	BPF_JMP | BPF_JGE | BPF_K, BPF_JMP | BPF_JGE | BPF_X,
	BPF_JMP | BPF_JGT | BPF_K, BPF_JMP | BPF_JGT | BPF_X,
	BPF_JMP | BPF_JSET | BPF_K, BPF_JMP | BPF_JSET | BPF_X,
};

static const uint32_t bpf_seccomp_jmp_arch_vars[] = {
	AUDIT_ARCH_ALPHA, AUDIT_ARCH_ARM, AUDIT_ARCH_ARMEB,
	AUDIT_ARCH_I386,
	AUDIT_ARCH_M68K, AUDIT_ARCH_MIPS, AUDIT_ARCH_MIPSEL,
	AUDIT_ARCH_MIPS64, AUDIT_ARCH_MIPSEL64, AUDIT_ARCH_PARISC,
	AUDIT_ARCH_PARISC64, AUDIT_ARCH_PPC, AUDIT_ARCH_PPC64, AUDIT_ARCH_S390,
	AUDIT_ARCH_S390X, AUDIT_ARCH_SH, AUDIT_ARCH_SHEL,
	AUDIT_ARCH_SPARC, AUDIT_ARCH_SPARC64,
	AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64, AUDIT_ARCH_RISCV64,
	AUDIT_ARCH_LOONGARCH64,
};

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


/* An opcode the kernel takes, and last a RET of K or A, which
 * bpf_check_classic() wants there. */
static uint16_t gen_bpf_code_less_crazy(bool last_instr)
{
	if (last_instr)
		return BPF_RET | (RAND_BOOL() ? BPF_K : BPF_A);
	return bpf_rand(saner);
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
	STATE_GEN_MATCH_SYSCALL    = 2,
	STATE_GEN_ALLOW            = 3,
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

/*
 * The action of the RET behind a syscall-number match; every other RET
 * allows.  A filter stays on the child for good and filters stack, so
 * a RET every call reaches that refused them would leave the child
 * fuzzing nothing, and a match ends the child one time in 256.  The rest
 * return LOG, TRACE, ERRNO or, if @notify, USER_NOTIF.  With no tracer or
 * listener attached TRACE and USER_NOTIF fail the call with ENOSYS,
 * which deactivate_enosys() does not take for a missing syscall in a
 * child with a filter of its own (seccomp_own_filter).  A filter that
 * gets a listener (NEW_LISTENER) must not return USER_NOTIF: the child
 * would wait on its own listener for a reply nothing sends.  ERRNO's
 * errno is nonzero, as 0 returns success without running the call.
 */
static uint32_t seccomp_match_action(bool notify)
{
	static const uint32_t fatal[] = {
		SECCOMP_RET_KILL_THREAD, SECCOMP_RET_KILL_PROCESS,
		SECCOMP_RET_TRAP,
	};

	if (!ONE_IN(8))
		return SECCOMP_RET_ALLOW;
	if (ONE_IN(32))
		return RAND_ARRAY(fatal);
	switch (rnd_modulo_u32(notify ? 4 : 3)) {
	case 0:
		return SECCOMP_RET_LOG;
	case 1:
		return SECCOMP_RET_TRACE | rnd_modulo_u32(SECCOMP_RET_DATA + 1);
	case 2:
		return SECCOMP_RET_ERRNO | (1 + rnd_modulo_u32(SECCOMP_RET_DATA));
	default:
		return SECCOMP_RET_USER_NOTIF;
	}
}

static int gen_seccomp_bpf_code(struct sock_filter *curr, int state,
				bool notify)
{
	unsigned int nr;
	int used = 0;
	struct sock_filter validate_arch[] = {
		BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, arch_nr),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_filter examine_syscall[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr),
	};
	struct sock_filter match_syscall[] = {
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	struct sock_filter allow[] = {
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	switch (state) {
	case STATE_GEN_VALIDATE_ARCH:
		used = 3;
		memcpy(curr, validate_arch, sizeof(validate_arch));
		/* Randomize the arch the JEQ compares the loaded one with */
		if (ONE_IN(3))
			curr[1].k = bpf_rand(seccomp_jmp_arch);
		else
			curr[1].k = NATIVE_AUDIT_ARCH;
		break;
	case STATE_GEN_EXAMINE_SYSCALL:
		used = 1;
		memcpy(curr, examine_syscall, sizeof(examine_syscall));
		break;
	case STATE_GEN_MATCH_SYSCALL:
		used = 2;
		memcpy(curr, match_syscall, sizeof(match_syscall));
		/* Pick a syscall nr from whichever table is active, but not
		 * 0: A is 0 until the program loads a word, so a match on 0
		 * ahead of the first load would answer every call. */
		if (biarch) {
			if (syscalls == syscalls_32bit)
				nr = max_nr_32bit_syscalls;
			else
				nr = max_nr_64bit_syscalls;
		} else {
			nr = max_nr_syscalls;
		}
		curr[0].k = nr > 1 ? 1 + rnd_modulo_u32(nr - 1) : 1;
		curr[1].k = seccomp_match_action(notify);
		break;
	case STATE_GEN_ALLOW:
		used = 1;
		memcpy(curr, allow, sizeof(allow));
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
		/* A RET here answers every call that reaches it, so it
		 * allows. */
		curr->k = BPF_CLASS(curr->code) == BPF_RET ?
			  SECCOMP_RET_ALLOW : rand32();
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

void bpf_gen_seccomp(unsigned long **addr, unsigned long *addrlen, bool notify)
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

		used = gen_seccomp_bpf_code(curr, state, notify);
		curr  += used;
		avail -= used;

		state = seccomp_choose(seccomp_markov[state]);
	}
	/* bpf_check_classic() wants a RET last.  The loop leaves one to
	 * three slots free, and a jump past a state lands in them. */
	bpf->filter[bpf->len - 1] =
		(struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

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
		/* The instructions after this one, where its jumps may land:
		 * an offset past them is refused. */
		unsigned int span = bpf->len - i - 1;
		unsigned int reach = span < 256 ? span : 256;

		if (ONE_IN(100))
			bpf->filter[i].code = gen_bpf_code_more_crazy(i == bpf->len - 1);
		else
			bpf->filter[i].code = gen_bpf_code_less_crazy(i == bpf->len - 1);

		/* Fill out jump offsets if jmp instruction */
		if (BPF_CLASS(bpf->filter[i].code) == BPF_JMP && reach != 0) {
			bpf->filter[i].jt = (uint8_t) rnd_modulo_u32(reach);
			bpf->filter[i].jf = (uint8_t) rnd_modulo_u32(reach);
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

		/* Also try to jump into BPF extensions by chance: each
		 * ancillary load sits on a multiple of four below
		 * SKF_AD_MAX, and an absolute load of any other offset
		 * from SKF_AD_OFF up is refused. */
		if (BPF_CLASS(bpf->filter[i].code) == BPF_LD ||
		    BPF_CLASS(bpf->filter[i].code) == BPF_LDX) {
			if (bpf->filter[i].k > 65000 &&
			    bpf->filter[i].k < (uint32_t) SKF_AD_OFF) {
				if (ONE_IN(10)) {
					bpf->filter[i].k = (uint32_t) (SKF_AD_OFF +
							   4 * rnd_modulo_u32(SKF_AD_MAX / 4));
				}
			}
		}

		/* bpf_check_classic() refuses a K divisor of 0, a K shift
		 * of 32 or more, and a JA past the end. */
		switch (bpf->filter[i].code) {
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_MOD | BPF_K:
			if (bpf->filter[i].k == 0)
				bpf->filter[i].k = 1 + rnd_modulo_u32(255);
			break;
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_K:
			bpf->filter[i].k &= 31;
			break;
		case BPF_JMP | BPF_JA:
			bpf->filter[i].k = span ? rnd_modulo_u32(span) : 0;
			break;
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
 * by LRU, and the inner buffer needs explicit handling because freeing
 * the outer wrapper does not release it.
 *
 * Helper-boundary validation: the .post paths in
 * syscalls/socket/setsockopt.c, syscalls/process/seccomp.c and
 * syscalls/process/prctl.c already gate the wrapper with
 * alloc_track_lookup() || range_readable_user() before reaching us, but
 * syscalls/bpf.c's BPF_PROG_LOAD classic-BPF cleanup calls in directly
 * from snap->classic_bpf_insns + attr->insns -- a sibling-scribbled
 * attr->insns that survives the snap shape check would fault on the
 * bpf->filter deref here.  Prove the wrapper inside the helper so the
 * direct caller is safe and the .post-path callers stay double-gated
 * without per-file edits.  Same shape as those callers: tracked allocation
 * (definitively one we produced via zmalloc_tracked in bpf_gen_filter /
 * bpf_gen_seccomp) or at minimum readable for a sock_fprog-sized window.
 *
 * Inner-filter free is alloc_track_lookup()-only: free what we can
 * prove we own, leak the unproven.  alloc_track_lookup() hashes first
 * and falls back to a linear df_alloc_track[] scan on a NULL-slot hash
 * miss, so the mirror-desync class (duplicate-ptr displaced-eviction
 * leaves the hash empty while the array still owns the ptr) still
 * gates the free.  A readable-but-untracked inner pointer
 * (a wild fuzz pointer that happens to land in a real mapping) is
 * deliberately left to leak rather than handed to
 * deferred_free_enqueue(): leaking an unproven pointer is the safer
 * direction than freeing a chunk we cannot prove we allocated.  The
 * outer wrapper still enqueues so the post_state / tracker slot
 * releases.
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
