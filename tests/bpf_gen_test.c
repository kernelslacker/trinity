/*
 * Self-check for what the bpf() sanitisers and the eBPF program generator
 * hand the kernel: each case holds one of them to a fact about the kernel's
 * handling of the call.  The pickers the sanitisers draw their fds from are
 * the fakes in fake_fds.c, and no call reaches the kernel.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"
#include "debug.h"		/* BUG */
#include "rnd.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_bpf */
#include "utils.h"		/* ARRAY_SIZE */

#include "net/bpf/ebpf-internal.h"

#ifdef USE_BPF
static unsigned int failed;

static void check(const char *what, const char *case_name, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "bpf gen: %s: %s\n", case_name, what);
	failed++;
}

#ifdef USE_BPF_PROG_STREAM_OPEN
/*
 * prog_stream_open() refuses a call whose attr has a byte set past flags
 * (CHECK_ATTR), bpf_stream_get() serves only the stdout and stderr ids, and
 * the kernel takes no flag but BPF_F_STREAM_NONBLOCK.  Most calls are meant
 * to pass all three, and some of each kind are not, to reach the ENOENT and
 * EINVAL returns; of the opens that pass, some leave the stream fd blocking.
 */
static void stream_open_draws_mostly_valid_calls(void)
{
	enum { ROUNDS = 4000 };
	static struct syscallrecord rec;
	unsigned int good_id = 0, bad_id = 0, good_flags = 0, bad_flags = 0;
	unsigned int stdout_ids = 0, stderr_ids = 0, blocking = 0, round;
	const union bpf_attr *attr;
	const unsigned char *raw;
	size_t i;

	for (round = 0; round < ROUNDS; round++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = BPF_PROG_STREAM_OPEN;
		syscall_bpf.sanitise(&rec);
		attr = (const union bpf_attr *) rec.a2;
		raw = (const unsigned char *) attr;

		check("the size is not the three fields", "stream open",
		      rec.a3 == sizeof(attr->prog_stream_open));
		check("the call does not return an fd", "stream open",
		      rec.rettype == RET_FD);
		for (i = rec.a3; i < sizeof(union bpf_attr); i++) {
			if (raw[i] == 0)
				continue;
			check("a byte past flags is set", "stream open", false);
			break;
		}

		if (attr->prog_stream_open.stream_id == BPF_STREAM_STDOUT) {
			good_id++;
			stdout_ids++;
		} else if (attr->prog_stream_open.stream_id == BPF_STREAM_STDERR) {
			good_id++;
			stderr_ids++;
		} else {
			bad_id++;
		}

		if (attr->prog_stream_open.flags == 0) {
			good_flags++;
			blocking++;
		} else if (attr->prog_stream_open.flags == BPF_F_STREAM_NONBLOCK) {
			good_flags++;
		} else {
			bad_flags++;
		}

		/* Releases the snapshot, as the dispatcher does.  Deferred
		 * free refuses the attr, which the fake allocator never
		 * tracked, so it is freed here. */
		rec.retval = (unsigned long) -1L;
		rec.errno_post = ENOENT;
		syscall_bpf.post(&rec);
		free((void *) attr);
	}

	check("fewer than 85% of the ids are one the kernel serves",
	      "stream open", good_id * 100 >= ROUNDS * 85);
	check("no id reaches the ENOENT return", "stream open", bad_id > 0);
	check("an id of one stream is never drawn", "stream open",
	      stdout_ids > 0 && stderr_ids > 0);
	check("fewer than 85% of the flags are one the kernel takes",
	      "stream open", good_flags * 100 >= ROUNDS * 85);
	check("no flags value reaches the EINVAL return", "stream open",
	      bad_flags > 0);
	check("not a tenth to a half of the opens are blocking", "stream open",
	      blocking * 10 >= good_flags && blocking * 2 <= good_flags);
}
#endif /* USE_BPF_PROG_STREAM_OPEN */

/*
 * The frame a program draws its stack offsets from is 512 bytes, the
 * interpreter's, or 2 KiB, which bpf_prog_stack_limit() grants a JITed
 * program on the architectures whose JIT lays out such frames (x86-64 and
 * arm64, which report bpf_jit_supports_large_stack()).  Valid programs
 * (tiers 1 and 2) draw from the larger one about a quarter of the time, so
 * the verifier sees deep frames and the access it bounds past 512 bytes.
 */
#if defined(__x86_64__) || defined(__aarch64__)
# define LARGE_FRAMES	true
#else
# define LARGE_FRAMES	false
#endif

#define KERNEL_MAX_BPF_STACK_JIT	2048

/* Every access through R10 the generated instructions make, but the one at
 * -8 the helper-call setup always makes: how many, and the deepest. */
static unsigned int stack_accesses(const struct bpf_insn *insns, int len,
				   int *deepest)
{
	unsigned int n = 0;
	int i;

	*deepest = 0;
	for (i = 0; i < len; i++) {
		const struct bpf_insn *insn = &insns[i];
		unsigned char cls = BPF_CLASS(insn->code);
		int base;

		if (BPF_MODE(insn->code) != BPF_MEM)
			continue;
		if (cls == BPF_LDX)
			base = insn->src_reg;
		else if (cls == BPF_ST || cls == BPF_STX)
			base = insn->dst_reg;
		else
			continue;
		if (base != BPF_REG_10)
			continue;

		check("a stack access is not a slot of the program's frame",
		      "stack", insn->off < 0 &&
		      insn->off >= -KERNEL_MAX_BPF_STACK_JIT &&
		      insn->off % 8 == 0);
		if (insn->off == HELPER_ARG_STACK_OFF)
			continue;
		n++;
		if (insn->off < *deepest)
			*deepest = insn->off;
	}
	return n;
}

/* The frame is the program's: every offset it draws lies in that one
 * frame, and a program holding the 2 KiB one does use what is past 512. */
static void a_program_keeps_to_its_frame(void)
{
	enum { PROGRAMS = 4000, DRAWS = 64 };
	unsigned int large = 0, round, draw;

	for (round = 0; round < PROGRAMS; round++) {
		struct reg_state rs;
		bool deep = false;

		reg_init(&rs, -1);
		check("the frame is neither 512 bytes nor 2 KiB", "stack",
		      rs.stack_size == EBPF_STACK_SIZE ||
		      rs.stack_size == KERNEL_MAX_BPF_STACK_JIT);
		if (rs.stack_size == KERNEL_MAX_BPF_STACK_JIT)
			large++;

		for (draw = 0; draw < DRAWS; draw++) {
			int off = rand_stack_offset(&rs);

			check("an offset is outside the program's frame",
			      "stack", off < 0 && off >= -rs.stack_size &&
			      off % 8 == 0);
			if (off < -EBPF_STACK_SIZE)
				deep = true;
		}
		check("a 512-byte program drew past its frame", "stack",
		      rs.stack_size != EBPF_STACK_SIZE || !deep);
		check("a 2 KiB program never drew past 512 bytes", "stack",
		      rs.stack_size != KERNEL_MAX_BPF_STACK_JIT || deep);
	}

	if (LARGE_FRAMES) {
		check("under 20% of the programs draw the 2 KiB frame",
		      "stack", large * 100 >= PROGRAMS * 20);
		check("over 30% of the programs draw the 2 KiB frame",
		      "stack", large * 100 <= PROGRAMS * 30);
	} else {
		check("a program drew the 2 KiB frame where the JIT does "
		      "not grant it", "stack", large == 0);
	}
}

/* Programs from the two tiers that draw from the frame; a program with
 * fewer than MIN_ACCESSES accesses is too short to tell the two frames
 * apart (one access in four of a large frame stays within 512 bytes). */
static void valid_programs_draw_both_frames(void)
{
	enum { PROGRAMS = 6000, MIN_ACCESSES = 6 };
	static struct bpf_insn insns[TIER2_MAX_INSNS];
	struct helper_set hs = get_helpers_for_prog_type(BPF_PROG_TYPE_KPROBE);
	unsigned int counted = 0, deep = 0, round;

	for (round = 0; round < PROGRAMS; round++) {
		int len, deepest;

		memset(insns, 0, sizeof(insns));
		if (round % 2)
			len = gen_tier1(insns, TIER1_MAX_INSNS, hs, -1);
		else
			len = gen_tier2(insns, TIER2_MAX_INSNS, hs, -1);

		if (stack_accesses(insns, len, &deepest) < MIN_ACCESSES)
			continue;
		counted++;
		if (deepest < -EBPF_STACK_SIZE)
			deep++;
	}

	check("too few programs had enough stack accesses to judge",
	      "stack", counted >= PROGRAMS / 10);
	if (LARGE_FRAMES) {
		check("under 15% of the programs use a frame past 512 bytes",
		      "stack", deep * 100 >= counted * 15);
		check("over 35% of the programs use a frame past 512 bytes",
		      "stack", deep * 100 <= counted * 35);
	} else {
		check("a program used a frame past 512 bytes where the JIT "
		      "does not grant one", "stack", deep == 0);
	}
}

#endif /* USE_BPF */

void bpf_gen_self_check(void);
void bpf_gen_self_check(void)
{
#ifdef USE_BPF
#ifdef USE_BPF_PROG_STREAM_OPEN
	stream_open_draws_mostly_valid_calls();
#endif
	a_program_keeps_to_its_frame();
	valid_programs_draw_both_frames();

	if (failed != 0)
		BUG("a bpf sanitiser or generator drew what the kernel does not take");
#endif
}
