/*
 * Self-check for what the bpf() sanitisers and the eBPF program generator
 * hand the kernel: each case holds one of them to a fact about the kernel's
 * handling of the call.  The pickers the sanitisers draw their fds from are
 * the fakes in fake_fds.c, and no call reaches the kernel.
 */

#include <errno.h>
#include <limits.h>
#include <linux/filter.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"		/* page_size */
#include "bpf.h"
#include "debug.h"		/* BUG */
#include "rnd.h"
#include "sanitise.h"		/* range_in_writable_pool, writable_pool_init */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_bpf */
#include "utils.h"		/* ARRAY_SIZE */

#include "net/bpf/ebpf-internal.h"
#include "syscalls/bpf-internal.h"

extern bool fake_rand_bitmask_draws;	/* genl_ops_test.c */
int entry_check_status(struct syscallentry *entry);	/* sanitiser_owned_mask_test.c */

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

/*
 * The prog_flags bpf_prog_load() checks against, less BPF_F_TOKEN_FD, which
 * the arm of its own sets.  Any other bit is -EINVAL.  BPF_F_ARENA_SCALAR is
 * -EOPNOTSUPP without bpf_jit_supports_arena_scalar(), which only the x86-64
 * and arm64 JITs have.
 */
#define KERNEL_PROG_FLAGS_MASK ( \
	BPF_F_STRICT_ALIGNMENT | BPF_F_ANY_ALIGNMENT | BPF_F_TEST_RND_HI32 | \
	BPF_F_TEST_STATE_FREQ | BPF_F_SLEEPABLE | BPF_F_XDP_HAS_FRAGS | \
	BPF_F_XDP_DEV_BOUND_ONLY | BPF_F_TEST_REG_INVARIANTS)
#define ARENA_SCALAR_FLAG	(LARGE_FRAMES ? BPF_F_ARENA_SCALAR : 0UL)

/* The program types can_be_sleepable() takes without an attach target. */
static bool can_be_sleepable(unsigned int type)
{
	return type == BPF_PROG_TYPE_KPROBE ||
	       type == BPF_PROG_TYPE_TRACEPOINT ||
	       type == BPF_PROG_TYPE_RAW_TRACEPOINT;
}

/* The generated program is the case's to free: deferred free refuses what
 * the fake allocator never tracked. */
static void free_program(const union bpf_attr *attr, bool classic)
{
	if (classic) {
		struct sock_fprog *prog =
			(struct sock_fprog *)(unsigned long) attr->insns;

		free(prog->filter);
		free(prog);
	} else {
		free((void *)(unsigned long) attr->insns);
	}
}

/*
 * Most loads set no prog_flags, so the common path keeps loading, and what
 * is set is something the kernel takes together: only flags of its mask;
 * BPF_F_SLEEPABLE only on a type that can be sleepable; and a prog_ifindex,
 * which the kernel reads only for the dev-bound path, only on an XDP
 * program with BPF_F_XDP_DEV_BOUND_ONLY and no flag but BPF_F_XDP_HAS_FRAGS.
 */
static void prog_load_draws_flags_the_kernel_takes(void)
{
	enum { ROUNDS = 20000 };
	const unsigned long takes = KERNEL_PROG_FLAGS_MASK | ARENA_SCALAR_FLAG;
	static struct syscallrecord rec;
	static union bpf_attr attr;
	unsigned long seen = 0;
	unsigned int none = 0, round;

	fake_rand_bitmask_draws = true;
	for (round = 0; round < ROUNDS; round++) {
		unsigned long flags;
		bool classic;

		memset(&attr, 0, sizeof(attr));
		memset(&rec, 0, sizeof(rec));
		classic = sanitise_bpf_prog_load(&attr, &rec);
		flags = attr.prog_flags & ~BPF_F_TOKEN_FD;

		check("a flag the kernel does not take was drawn", "prog flags",
		      (flags & ~takes) == 0);
		check("the size does not reach prog_ifindex", "prog flags",
		      rec.a3 >= offsetof(union bpf_attr, prog_ifindex) +
				sizeof(attr.prog_ifindex));
		if (flags == 0)
			none++;
		seen |= flags;

		if (flags & BPF_F_SLEEPABLE)
			check("BPF_F_SLEEPABLE was drawn for a type that "
			      "cannot be sleepable", "prog flags",
			      can_be_sleepable(attr.prog_type));
		if (flags & BPF_F_XDP_DEV_BOUND_ONLY)
			check("BPF_F_XDP_DEV_BOUND_ONLY was drawn without a "
			      "prog_ifindex, or off XDP", "prog flags",
			      attr.prog_ifindex != 0 &&
			      attr.prog_type == BPF_PROG_TYPE_XDP);
		if (attr.prog_ifindex != 0)
			check("a prog_ifindex came with what the dev-bound "
			      "check refuses", "prog flags",
			      attr.prog_type == BPF_PROG_TYPE_XDP &&
			      (flags & BPF_F_XDP_DEV_BOUND_ONLY) &&
			      (flags & ~(BPF_F_XDP_DEV_BOUND_ONLY |
					 BPF_F_XDP_HAS_FRAGS)) == 0);

		free_program(&attr, classic);
	}
	fake_rand_bitmask_draws = false;

	check("under 65% of the loads set no flags", "prog flags",
	      none * 100 >= ROUNDS * 65);
	check("over 85% of the loads set no flags", "prog flags",
	      none * 100 <= ROUNDS * 85);
	check("a flag the kernel takes was never drawn", "prog flags",
	      (seen & takes) == takes);
}

/*
 * struct bpf_common_attr rides in the fourth and fifth arguments of bpf().
 * __sys_bpf() reads it only when cmd carries BPF_COMMON_ATTRS, and of the
 * commands only BPF_MAP_CREATE, BPF_PROG_LOAD and BPF_BTF_LOAD do anything
 * with it: they take their verifier log from it (bpf_log_attr_create_vlog()
 * and bpf_log_attr_init() in kernel/bpf/log.c).  kernel_common_attr() is
 * those checks as the kernel writes them, and a draw is judged by the
 * verdict it gives.  A pointer is memory the kernel can read and write where
 * the writable pool is, and nowhere else.
 */
#define COMMON_POISON		0x5a5a5a5aUL

/* Where __sys_bpf()'s tail check on the struct starts. */
#define COMMON_ATTR_END		(offsetof(struct bpf_common_attr, log_true_size) + sizeof(__u32))

/* BPF_LOG_MASK and the size cap of bpf_verifier_log_attr_valid(). */
#define KERNEL_LOG_MASK		15U
#define KERNEL_LOG_SIZE_MAX	(UINT_MAX >> 2)

struct common_verdict {
	int err;		/* 0, -E2BIG, -EFAULT or -EINVAL */
	bool mismatch;		/* the -EINVAL is two logs that differ */
	bool log_from_common;	/* the verifier log is the struct's */
	bool log_unwritable;	/* and a write it makes to the call's memory faults */
};

static bool kernel_log_attr_valid(unsigned int level, unsigned long buf,
				  unsigned int size)
{
	if (!!buf != !!size)
		return false;
	if (buf && level == 0)
		return false;
	if (level & ~KERNEL_LOG_MASK)
		return false;
	return size <= KERNEL_LOG_SIZE_MAX;
}

/* A field of the attr the call hands over, zero where the size it passes
 * stops short of it, as the kernel's zeroed copy leaves it. */
#define ATTR_FIELD(attr, size, member) \
	((size) >= offsetof(union bpf_attr, member) + sizeof((attr)->member) ? \
	 (unsigned long) (attr)->member : 0UL)

static struct common_verdict kernel_common_attr(unsigned long cmd_arg,
						const union bpf_attr *attr,
						unsigned long size,
						unsigned long uattr_common,
						unsigned long size_common_arg)
{
	const unsigned char *user = (const unsigned char *) uattr_common;
	unsigned int cmd = cmd_arg, size_common = size_common_arg;
	unsigned long own_buf = 0, own_size = 0, own_level = 0;
	struct common_verdict v = { 0 };
	struct bpf_common_attr common;
	bool loads, creates;
	unsigned int i;

	if (!(cmd & BPF_COMMON_ATTRS))
		return v;

	/* bpf_check_uarg_tail_zero(): too long, or bytes set past the end of
	 * log_true_size, in memory the kernel can read. */
	if (size_common > page_size) {
		v.err = -E2BIG;
		return v;
	}
	if (size_common > COMMON_ATTR_END) {
		if (!range_in_writable_pool(uattr_common + COMMON_ATTR_END,
					    size_common - COMMON_ATTR_END)) {
			v.err = -EFAULT;
			return v;
		}
		for (i = COMMON_ATTR_END; i < size_common; i++) {
			if (user[i] != 0) {
				v.err = -E2BIG;
				return v;
			}
		}
	}

	/* The copy: size_common bytes, to the struct's size, into zeroes. */
	memset(&common, 0, sizeof(common));
	if (size_common > sizeof(common))
		size_common = sizeof(common);
	if (size_common != 0) {
		if (!range_in_writable_pool(uattr_common, size_common)) {
			v.err = -EFAULT;
			return v;
		}
		memcpy(&common, user, size_common);
	}

	cmd &= ~BPF_COMMON_ATTRS;
	creates = cmd == BPF_MAP_CREATE;
	loads = cmd == BPF_PROG_LOAD || cmd == BPF_BTF_LOAD;
	if (!creates && !loads)
		return v;

	if (creates) {
		/* bpf_log_attr_create_vlog(): no log without a struct. */
		if (size_common == 0)
			return v;
		if (!kernel_log_attr_valid(common.log_level, common.log_buf,
					   common.log_size)) {
			v.err = -EINVAL;
			return v;
		}
		v.log_from_common = common.log_level != 0;
	} else {
		if (cmd == BPF_PROG_LOAD) {
			own_buf = ATTR_FIELD(attr, size, log_buf);
			own_size = ATTR_FIELD(attr, size, log_size);
			own_level = ATTR_FIELD(attr, size, log_level);
		} else {
			own_buf = ATTR_FIELD(attr, size, btf_log_buf);
			own_size = ATTR_FIELD(attr, size, btf_log_size);
			own_level = ATTR_FIELD(attr, size, btf_log_level);
		}

		/* bpf_log_attr_init(): both logs well formed, and one buffer
		 * named twice is named alike. */
		if (!kernel_log_attr_valid(common.log_level, common.log_buf,
					   common.log_size) ||
		    !kernel_log_attr_valid(own_level, own_buf, own_size)) {
			v.err = -EINVAL;
			return v;
		}
		if (own_buf != 0 && common.log_buf != 0 &&
		    (own_buf != common.log_buf || own_size != common.log_size ||
		     own_level != common.log_level)) {
			v.err = -EINVAL;
			v.mismatch = true;
			return v;
		}
		v.log_from_common = own_buf == 0 && common.log_buf != 0;
	}

	if (v.log_from_common) {
		if (common.log_buf != 0 &&
		    !range_in_writable_pool(common.log_buf, common.log_size))
			v.log_unwritable = true;
		/* The log's true size goes back into the struct, past the
		 * fields the log is made of. */
		if (size_common >= COMMON_ATTR_END &&
		    !range_in_writable_pool(uattr_common +
					    offsetof(struct bpf_common_attr,
						     log_true_size),
					    sizeof(common.log_true_size)))
			v.log_unwritable = true;
	} else if (own_buf != 0 && !range_in_writable_pool(own_buf, own_size)) {
		v.log_unwritable = true;
	}
	return v;
}

struct common_tally {
	unsigned int rounds, carried, accepted;
	unsigned int e2big, efault, einval, mismatch;
	unsigned int from_common, unwritable;
};

static void tally_common(struct common_tally *t, const struct syscallrecord *rec,
			 unsigned long cmd, const union bpf_attr *attr)
{
	struct common_verdict v;

	t->rounds++;
	check("the draw changed more of the command than its flag",
	      "common attr", (rec->a1 & ~(unsigned long) BPF_COMMON_ATTRS) == cmd);
	check("the draw left a slot of the common attrs unwritten",
	      "common attr", rec->a4 != COMMON_POISON && rec->a5 != COMMON_POISON);

	if (!(rec->a1 & BPF_COMMON_ATTRS)) {
		check("a call without the flag carries a struct", "common attr",
		      rec->a4 == 0 && rec->a5 == 0);
		return;
	}

	t->carried++;
	v = kernel_common_attr(rec->a1, attr, rec->a3, rec->a4, rec->a5);
	switch (v.err) {
	case 0:
		t->accepted++;
		break;
	case -E2BIG:
		t->e2big++;
		break;
	case -EFAULT:
		t->efault++;
		break;
	case -EINVAL:
		t->einval++;
		if (v.mismatch)
			t->mismatch++;
		break;
	}
	if (v.log_from_common)
		t->from_common++;
	if (v.log_unwritable)
		t->unwritable++;
}

/* The kernel reads the struct's tail wherever the pool has put it, and a
 * pool a run has used holds what earlier calls left.  Fill it, so the slots
 * the next draws take come back as junk and the tail is zero only if the
 * sanitiser zeroed it: an allocation of the pool's whole size starts at its
 * base and parks the cursor at its end, which the next one wraps. */
static void dirty_writable_pool(void)
{
	memset(get_writable_address(WRITABLE_POOL_BYTES), 0xa5, WRITABLE_POOL_BYTES);
}

/* The sanitiser and the post handler, as the dispatcher runs them.  The
 * post handler hands the attr to deferred free, which refuses what the fake
 * allocator never tracked, so the attr is the case's to free. */
static void draw_common_attr(struct common_tally *t, unsigned long cmd,
			     unsigned int rounds)
{
	static struct syscallrecord rec;
	unsigned int round;

	for (round = 0; round < rounds; round++) {
		const union bpf_attr *attr;

		if (round % 32 == 0)
			dirty_writable_pool();
		memset(&rec, 0, sizeof(rec));
		rec.a1 = cmd;
		rec.a4 = COMMON_POISON;
		rec.a5 = COMMON_POISON;
		syscall_bpf.sanitise(&rec);
		attr = (const union bpf_attr *) rec.a2;
		tally_common(t, &rec, cmd, attr);

		rec.retval = (unsigned long) -1L;
		rec.errno_post = EINVAL;
		syscall_bpf.post(&rec);
		free((void *) attr);
	}
}

/* PROG_LOAD's program is the case's to free, so it is drawn without the
 * post handler: the attr is the one the sanitiser builds, then the step
 * under test. */
static void draw_common_attr_for_prog_load(struct common_tally *t,
					   unsigned int rounds)
{
	static struct syscallrecord rec;
	static union bpf_attr attr;
	unsigned int round;

	for (round = 0; round < rounds; round++) {
		bool classic;

		if (round % 32 == 0)
			dirty_writable_pool();
		memset(&attr, 0, sizeof(attr));
		memset(&rec, 0, sizeof(rec));
		rec.a1 = BPF_PROG_LOAD;
		classic = sanitise_bpf_prog_load(&attr, &rec);
		rec.a4 = COMMON_POISON;
		rec.a5 = COMMON_POISON;
		sanitise_bpf_common_attr(&attr, &rec);
		tally_common(t, &rec, BPF_PROG_LOAD, &attr);
		free_program(&attr, classic);
	}
}

/*
 * Most calls leave both slots 0 and the flag clear, as before.  The ones
 * that carry the struct are mostly ones the kernel takes, and a few break
 * one rule each so every rejection stays reachable: too long, tail bytes
 * set, an unreadable pointer, a log that is no log, and for a load a second
 * log that differs from the struct's.  The commands that read the struct
 * carry it oftener than the rest, which only run the checks around it.
 */
static void common_attr_follows_the_kernels_rules(void)
{
	enum { ROUNDS = 4000, OTHER_ROUNDS = 400 };
	const unsigned long *cmds = syscall_bpf.arg_params[0].list.values;
	struct common_tally map = { 0 }, prog = { 0 }, btf = { 0 }, other = { 0 };
	struct common_tally *const readers[] = { &map, &prog, &btf };
	unsigned int i;

	check("sanity_check_tables refuses the bpf entry", "common attr",
	      entry_check_status(&syscall_bpf) == 0);

	if (get_writable_address(sizeof(unsigned long)) == NULL)
		writable_pool_init();

	draw_common_attr(&map, BPF_MAP_CREATE, ROUNDS);
	draw_common_attr_for_prog_load(&prog, ROUNDS);
	draw_common_attr(&btf, BPF_BTF_LOAD, ROUNDS);
	for (i = 0; i < syscall_bpf.arg_params[0].list.num; i++) {
		if (cmds[i] == BPF_MAP_CREATE || cmds[i] == BPF_PROG_LOAD ||
		    cmds[i] == BPF_BTF_LOAD)
			continue;
		draw_common_attr(&other, cmds[i], OTHER_ROUNDS);
	}

	for (i = 0; i < ARRAY_SIZE(readers); i++) {
		const struct common_tally *t = readers[i];

		check("under 15% of the calls carry the struct", "common attr",
		      t->carried * 100 >= t->rounds * 15);
		check("over 35% of the calls carry the struct", "common attr",
		      t->carried * 100 <= t->rounds * 35);
		check("under 75% of the structs are ones the kernel takes",
		      "common attr", t->accepted * 100 >= t->carried * 75);
		check("under 15% of the structs the kernel takes give it a log",
		      "common attr", t->from_common * 100 >= t->accepted * 15);
		check("a log the kernel writes is memory it cannot write",
		      "common attr", t->unwritable == 0);
		check("no struct is too long", "common attr", t->e2big > 0);
		check("no struct is unreadable", "common attr", t->efault > 0);
		check("no struct holds a log that is no log", "common attr",
		      t->einval > 0);
	}
	check("no load names a second log that differs", "common attr",
	      prog.mismatch > 0);

	check("no call of another command carries the struct", "common attr",
	      other.carried > 0);
	check("over 8% of the calls of another command carry the struct",
	      "common attr", other.carried * 100 <= other.rounds * 8);
	check("a log the kernel writes is memory it cannot write",
	      "common attr", other.unwritable == 0);

	/* Leave the pool clean for the suites that follow. */
	memset(get_writable_address(WRITABLE_POOL_BYTES), 0, WRITABLE_POOL_BYTES);
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
	prog_load_draws_flags_the_kernel_takes();
	common_attr_follows_the_kernels_rules();

	if (failed != 0)
		BUG("a bpf sanitiser or generator drew what the kernel does not take");
#endif
}
