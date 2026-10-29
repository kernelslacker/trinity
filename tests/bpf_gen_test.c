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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "bpf.h"
#include "debug.h"		/* BUG */
#include "objects.h"		/* struct bpfobj */
#include "rnd.h"
#include "sanitise.h"		/* range_in_writable_pool, writable_pool_init */
#include "struct_catalog.h"	/* struct union_variant */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_bpf */
#include "utils.h"		/* ARRAY_SIZE */

#include "net/bpf/ebpf-internal.h"
#include "struct_catalog-internal.h"	/* bpf_attr_variants */
#include "syscalls/bpf-internal.h"

extern bool fake_rand_bitmask_draws;	/* genl_ops_test.c */
extern bool fake_catalog_lookup;	/* fake_stubs.c */
extern bool fake_random_fd_empty;	/* fake_stubs.c */
extern int fake_bpf_prog_fd;		/* fake_fds.c */
extern bool (*fake_get_rand_bpf_prog)(struct bpfprogobj *prog);	/* fake_fds.c */
extern int fake_perf_fd;		/* fake_fds.c */
extern int fake_cgroup_fd;		/* fake_fds.c */
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

/*
 * The element commands copy the key and the value in or out through
 * pointers of the attr, and a pointer that does not take the copy ends the
 * call in -EFAULT (-EINVAL for a key a map with no key is given) before the
 * map's own code runs.  kernel_map_elem() is what kernel/bpf/syscall.c does
 * ahead of that code: CHECK_ATTR(), the flag rules of
 * bpf_map_check_op_flags(), the key copy of __bpf_copy_key() and the value
 * size of bpf_map_value_size().  A draw is judged by how far it gets.  The
 * maps are the pool's: some it records the type and sizes of, some it knows
 * nothing of, as of a map met by id that the kernel would not describe.
 */
#define FAKE_MAP_FD	100

struct fake_map {
	unsigned int type, key_size, value_size;
	bool pooled;		/* whether the pool recorded the three */
};

static const struct fake_map fake_maps[] = {
	{ BPF_MAP_TYPE_HASH, 8, 8, true },
	{ BPF_MAP_TYPE_ARRAY, 4, 8, true },
	{ BPF_MAP_TYPE_PERCPU_HASH, 4, 1016, true },
	{ BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, true },
	{ BPF_MAP_TYPE_LRU_PERCPU_HASH, 4, 8, true },
	{ BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE, 8, 8, true },
	/* A row of every cpu's value is too big for the pool. */
	{ BPF_MAP_TYPE_PERCPU_ARRAY, 4, 65535, true },
	{ BPF_MAP_TYPE_LPM_TRIE, 8, 8, true },
	{ BPF_MAP_TYPE_PROG_ARRAY, 4, 4, true },
	{ BPF_MAP_TYPE_QUEUE, 0, 8, true },
	{ BPF_MAP_TYPE_BLOOM_FILTER, 0, 4, true },
	{ BPF_MAP_TYPE_RINGBUF, 0, 0, true },
	{ BPF_MAP_TYPE_HASH, 512, 30000, false },
	{ BPF_MAP_TYPE_PERCPU_HASH, 16, 8, false },
};

static const struct fake_map *picked_map;

static bool pick_fake_map(struct bpfobj *map)
{
	memset(map, 0, sizeof(*map));
	map->map_fd = FAKE_MAP_FD + (picked_map - fake_maps);
	if (picked_map->pooled) {
		map->map_type = picked_map->type;
		map->key_size = picked_map->key_size;
		map->value_size = picked_map->value_size;
	}
	return true;
}

extern bool (*fake_get_rand_bpf_map)(struct bpfobj *map);	/* fake_fds.c */

/*
 * Owned by main/trinity-warmstart.c, which the test binary does not link.
 * num_possible_cpus() is what the kernel sizes a per-cpu row by, and a host
 * with hotplug slots has cpus possible that sysconf() does not count as
 * configured: the element draws below are made on such a host.
 */
unsigned int num_possible_cpus;

static bool kernel_percpu_map(unsigned int type)
{
	return type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	       type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
}

/* IS_FD_MAP(), whose elements read back as a 4-byte id. */
static bool kernel_fd_map(unsigned int type)
{
	return type == BPF_MAP_TYPE_PERF_EVENT_ARRAY ||
	       type == BPF_MAP_TYPE_CGROUP_ARRAY ||
	       type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
	       type == BPF_MAP_TYPE_PROG_ARRAY ||
	       type == BPF_MAP_TYPE_HASH_OF_MAPS;
}

static unsigned long kernel_value_size(const struct fake_map *m, uint64_t flags)
{
	if (flags & (BPF_F_CPU | BPF_F_ALL_CPUS))
		return m->value_size;
	if (kernel_percpu_map(m->type))
		return ((m->value_size + 7UL) & ~7UL) * num_possible_cpus;
	if (kernel_fd_map(m->type))
		return sizeof(__u32);
	return m->value_size;
}

/* bpf_map_check_op_flags(), for a map no BTF record gives a spin lock. */
static int kernel_map_check_op_flags(const struct fake_map *m, uint64_t flags,
				     uint64_t allowed)
{
	if ((__u32) flags & ~allowed)
		return -EINVAL;
	if (flags & BPF_F_LOCK)
		return -EINVAL;
	if (!(flags & BPF_F_CPU) && flags >> 32)
		return -EINVAL;
	if (flags & (BPF_F_CPU | BPF_F_ALL_CPUS)) {
		if (!kernel_percpu_map(m->type))
			return -EINVAL;
		if ((flags & BPF_F_CPU) && (flags & BPF_F_ALL_CPUS))
			return -EINVAL;
		if ((flags & BPF_F_CPU) && (flags >> 32) >= num_possible_cpus)
			return -ERANGE;
	}
	return 0;
}

static bool user_memory(unsigned long ptr, unsigned long len)
{
	return len == 0 || range_in_writable_pool(ptr, len);
}

struct elem_verdict {
	int err;		/* what ends the call ahead of the map's code */
	unsigned long value_len; /* the bytes it moves through the value pointer */
	bool value_faults;	/* the copy that follows the map's code does */
	bool exist_conflict;	/* the map's own -EINVAL for both existence flags */
};

static struct elem_verdict kernel_map_elem(unsigned int cmd,
					   const union bpf_attr *attr,
					   unsigned long size,
					   const struct fake_map *m)
{
	const unsigned char *raw = (const unsigned char *) attr;
	unsigned long key = attr->key, value = attr->value;
	uint64_t flags = attr->flags;
	struct elem_verdict v = { 0 };
	size_t last_end, i;

	switch (cmd) {
	case BPF_MAP_DELETE_ELEM:
		last_end = offsetof(union bpf_attr, key) + sizeof(attr->key);
		break;
	case BPF_MAP_GET_NEXT_KEY:
		last_end = offsetof(union bpf_attr, next_key) +
			   sizeof(attr->next_key);
		break;
	default:
		last_end = offsetof(union bpf_attr, flags) + sizeof(attr->flags);
		break;
	}
	/* CHECK_ATTR(): nothing set past the command's last field. */
	for (i = last_end; i < size && i < sizeof(*attr); i++) {
		if (raw[i] != 0) {
			v.err = -EINVAL;
			return v;
		}
	}

	if (cmd == BPF_MAP_LOOKUP_AND_DELETE_ELEM && (flags & ~BPF_F_LOCK)) {
		v.err = -EINVAL;
		return v;
	}
	if (attr->map_fd != FAKE_MAP_FD + (m - fake_maps)) {
		v.err = -EBADF;
		return v;
	}

	if (cmd == BPF_MAP_LOOKUP_ELEM)
		v.err = kernel_map_check_op_flags(m, flags, BPF_F_LOCK | BPF_F_CPU);
	else if (cmd == BPF_MAP_UPDATE_ELEM)
		v.err = kernel_map_check_op_flags(m, flags, ~0ULL);
	else if (cmd == BPF_MAP_LOOKUP_AND_DELETE_ELEM && flags != 0 &&
		 (m->type == BPF_MAP_TYPE_QUEUE || m->type == BPF_MAP_TYPE_STACK))
		v.err = -EINVAL;
	if (v.err)
		return v;

	if (m->key_size == 0 && key != 0) {
		v.err = -EINVAL;
		return v;
	}
	if (m->key_size != 0 && (cmd != BPF_MAP_GET_NEXT_KEY || key != 0) &&
	    !user_memory(key, m->key_size)) {
		v.err = -EFAULT;
		return v;
	}

	switch (cmd) {
	case BPF_MAP_UPDATE_ELEM:
		/* kvmemdup_bpfptr() reads the value before the map's code. */
		v.value_len = kernel_value_size(m, flags);
		if (!user_memory(value, v.value_len)) {
			v.err = -EFAULT;
			return v;
		}
		v.exist_conflict = (flags & BPF_NOEXIST) && (flags & BPF_EXIST);
		break;
	case BPF_MAP_LOOKUP_ELEM:
		v.value_len = kernel_value_size(m, flags);
		if (m->type == BPF_MAP_TYPE_BLOOM_FILTER) {
			if (!user_memory(value, v.value_len)) {
				v.err = -EFAULT;
				return v;
			}
		} else {
			v.value_faults = !user_memory(value, v.value_len);
		}
		break;
	case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
		v.value_len = kernel_value_size(m, 0);
		v.value_faults = !user_memory(value, v.value_len);
		break;
	case BPF_MAP_GET_NEXT_KEY:
		/* The next key is copied out after the map's code. */
		v.value_len = m->key_size;
		v.value_faults = !user_memory(value, v.value_len);
		break;
	}
	return v;
}

struct elem_tally {
	unsigned int rounds, reached, efault, einval, erange, value_faults;
	unsigned int exist_conflicts, cpu, cpu_valid, all_cpus, cpu_off_percpu;
	unsigned int undersized, big_rows;
	uint64_t cpus_seen;	/* bit n: BPF_F_CPU named cpu n, for n below 64 */
};

static void tally_elem(struct elem_tally *t, unsigned int cmd,
		       const union bpf_attr *attr, unsigned long size,
		       unsigned long span)
{
	const struct fake_map *m = picked_map;
	struct elem_verdict v = kernel_map_elem(cmd, attr, size, m);
	uint64_t flags = attr->flags;

	t->rounds++;
	if (v.err == 0)
		t->reached++;
	else if (v.err == -EFAULT)
		t->efault++;
	else if (v.err == -ERANGE)
		t->erange++;
	else if (v.err == -EINVAL)
		t->einval++;
	else
		check("a call fails where the kernel's checks do not",
		      "map elem", false);
	if (v.exist_conflict)
		t->exist_conflicts++;

	/* A row of every cpu's value that no buffer the arms make holds is
	 * sent only by the call that cannot name one value instead: it is not
	 * the draw's to get right, but any other call's is to name one. */
	if (v.value_len > BPF_ELEM_BUF_MAX) {
		if (cmd != BPF_MAP_LOOKUP_AND_DELETE_ELEM &&
		    (v.err == 0 || v.err == -EFAULT))
			t->big_rows++;
		v.value_faults = false;
	}
	if (v.value_faults)
		t->value_faults++;

	if (flags & BPF_F_CPU) {
		t->cpu++;
		if ((flags >> 32) < num_possible_cpus)
			t->cpu_valid++;
		if ((flags >> 32) < 64)
			t->cpus_seen |= 1ULL << (flags >> 32);
	}
	if (flags & BPF_F_ALL_CPUS)
		t->all_cpus++;
	if ((flags & (BPF_F_CPU | BPF_F_ALL_CPUS)) &&
	    !kernel_percpu_map(m->type))
		t->cpu_off_percpu++;

	/* The pool the draw took holds at least the value the call moves, in
	 * a buffer that is one: what a buffer smaller than that would run
	 * into.  A pointer outside the pool is no buffer. */
	if (v.err == 0 && v.value_len <= BPF_ELEM_BUF_MAX &&
	    range_in_writable_pool(attr->value, 1) && span < v.value_len)
		t->undersized++;
}

/* Draws of one command against every fake map.  The pool is parked at its
 * end first, so the draw starts at its base and what it took is the
 * distance to the next allocation. */
static void draw_map_elem(struct elem_tally *t, unsigned int cmd,
			  unsigned int rounds)
{
	static struct syscallrecord rec;
	unsigned int round;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(fake_maps); i++) {
		picked_map = &fake_maps[i];
		for (round = 0; round < rounds; round++) {
			const union bpf_attr *attr;
			unsigned char *before, *after;

			(void) get_writable_address(WRITABLE_POOL_BYTES);
			before = get_writable_address(16);
			memset(&rec, 0, sizeof(rec));
			rec.a1 = cmd;
			syscall_bpf.sanitise(&rec);
			after = get_writable_address(16);
			attr = (const union bpf_attr *) rec.a2;

			tally_elem(t, cmd, attr, rec.a3, after - before);

			rec.retval = (unsigned long) -1L;
			rec.errno_post = EBADF;
			syscall_bpf.post(&rec);
			free((void *) attr);
		}
	}
}

static void map_elem_draws_reach_the_maps_code(void)
{
	static const unsigned int cmds[] = {
		BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM,
		BPF_MAP_GET_NEXT_KEY, BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	};
	long conf = sysconf(_SC_NPROCESSORS_CONF);
	unsigned int c;

	num_possible_cpus = (conf > 0 ? conf : 1) + 64;
	if (get_writable_address(sizeof(unsigned long)) == NULL)
		writable_pool_init();
	fake_get_rand_bpf_map = pick_fake_map;
	fake_rand_bitmask_draws = true;

	for (c = 0; c < ARRAY_SIZE(cmds); c++) {
		struct elem_tally t = { 0 };

		draw_map_elem(&t, cmds[c], 400);

		check("under 80% of the draws get past the key and flag checks",
		      "map elem", t.reached * 100 >= t.rounds * 80);
		check("no draw is refused for a pointer", "map elem", t.efault > 0);
		check("over 12% of the draws are refused for a pointer",
		      "map elem", t.efault * 100 <= t.rounds * 12);
		check("over 12% of the draws fault in the copy after the map's code",
		      "map elem", t.value_faults * 100 <= t.rounds * 12);
		check("a value buffer is smaller than the value the call moves",
		      "map elem", t.undersized == 0);
		check("a row of every cpu's value, too big for the pool, is sent "
		      "where one value could be", "map elem", t.big_rows == 0);

		if (cmds[c] == BPF_MAP_LOOKUP_ELEM ||
		    cmds[c] == BPF_MAP_UPDATE_ELEM ||
		    cmds[c] == BPF_MAP_LOOKUP_AND_DELETE_ELEM)
			check("no draw is refused for its flags", "map elem",
			      t.einval > 0);

		if (cmds[c] == BPF_MAP_LOOKUP_ELEM ||
		    cmds[c] == BPF_MAP_UPDATE_ELEM) {
			check("no draw puts a cpu in BPF_F_CPU", "map elem",
			      t.cpu > 0);
			check("under 90% of the cpus of BPF_F_CPU are possible ones",
			      "map elem", t.cpu_valid * 100 >= t.cpu * 90);
			check("no cpu of BPF_F_CPU is refused as out of range",
			      "map elem", t.erange > 0);
			check("BPF_F_CPU names too few of the cpus", "map elem",
			      __builtin_popcountll(t.cpus_seen) >=
			      (num_possible_cpus < 8 ? num_possible_cpus : 8));
			check("over 10% of the draws put a cpu flag on a map that "
			      "is not per-cpu", "map elem",
			      t.cpu_off_percpu * 100 <= t.rounds * 10);
		}
		if (cmds[c] == BPF_MAP_UPDATE_ELEM) {
			check("no draw sets BPF_F_ALL_CPUS", "map elem",
			      t.all_cpus > 0);
			check("over 10% of the updates set both existence flags",
			      "map elem", t.exist_conflicts * 100 <= t.rounds * 10);
		}
		/* Takes no flag but BPF_F_LOCK, which a map with no BTF spin
		 * lock refuses too: the odd draw of the update flags is all
		 * that may carry one. */
		if (cmds[c] == BPF_MAP_LOOKUP_AND_DELETE_ELEM)
			check("over 5% of the lookup-and-deletes send BPF_F_CPU",
			      "map elem", t.cpu * 100 <= t.rounds * 5);
	}

	fake_rand_bitmask_draws = false;
	fake_get_rand_bpf_map = NULL;
}

/*
 * link_create() (kernel/bpf/syscall.c) hands the attr to the taker for the
 * attach type, which reads the arm of the union that type names, so the
 * sanitiser takes the arm from the catalog and draws the head, which every
 * attach type shares, from the pools.  A taker that has no use for a head
 * field answers -EINVAL when it is set: bpf_iter_link_attach()
 * (kernel/bpf/bpf_iter.c) and bpf_tracing_multi_attach()
 * (kernel/trace/bpf_trace.c) to a target_fd or flags, and
 * bpf_perf_link_attach() (kernel/bpf/syscall.c),
 * bpf_kprobe_multi_link_attach() and bpf_uprobe_multi_link_attach()
 * (kernel/trace/bpf_trace.c), bpf_nf_link_attach()
 * (net/netfilter/nf_bpf_link.c), netns_bpf_link_create()
 * (kernel/bpf/net_namespace.c) and sock_map_link_create()
 * (net/core/sock_map.c) to flags.
 */
static bool kernel_refuses_flags(unsigned long type)
{
	switch (type) {
	case BPF_TRACE_ITER:
	case BPF_PERF_EVENT:
	case BPF_TRACE_KPROBE_MULTI:
	case BPF_TRACE_KPROBE_SESSION:
	case BPF_TRACE_UPROBE_MULTI:
	case BPF_TRACE_UPROBE_SESSION:
	case BPF_TRACE_FENTRY_MULTI:
	case BPF_TRACE_FEXIT_MULTI:
	case BPF_TRACE_FSESSION_MULTI:
	case BPF_NETFILTER:
	case BPF_FLOW_DISSECTOR:
	case BPF_SK_LOOKUP:
	case BPF_SK_SKB_STREAM_PARSER:
	case BPF_SK_SKB_STREAM_VERDICT:
	case BPF_SK_SKB_VERDICT:
	case BPF_SK_MSG_VERDICT:
		return true;
	}
	return false;
}

/*
 * bpf_tracing_prog_attach() (kernel/bpf/syscall.c), the taker of these, answers
 * -EINVAL to a target_fd without a target_btf_id and to a btf id without an fd:
 * the pair names a program and a function in it, and neither names the target
 * the program was loaded with.
 */
static bool kernel_pairs_target(unsigned long type)
{
	switch (type) {
	case BPF_TRACE_FENTRY:
	case BPF_TRACE_FEXIT:
	case BPF_MODIFY_RETURN:
	case BPF_LSM_MAC:
	case BPF_TRACE_FSESSION:
		return true;
	}
	return false;
}

static bool kernel_refuses_target_fd(unsigned long type)
{
	switch (type) {
	case BPF_TRACE_ITER:
	case BPF_TRACE_FENTRY_MULTI:
	case BPF_TRACE_FEXIT_MULTI:
	case BPF_TRACE_FSESSION_MULTI:
		return true;
	}
	return false;
}

/*
 * The tail fields a multi attach cannot do without, whatever else its taker
 * checks: bpf_kprobe_multi_link_attach() answers -EINVAL to a cnt of 0 and to
 * a call that names neither syms nor addrs, bpf_uprobe_multi_link_attach() to
 * a cnt of 0 and to no offsets, and bpf_tracing_multi_attach() to a cnt of 0
 * and to no ids.
 */
static bool kernel_gets_its_tail(const union bpf_attr *attr)
{
	switch (attr->link_create.attach_type) {
	case BPF_TRACE_KPROBE_MULTI:
	case BPF_TRACE_KPROBE_SESSION:
		return attr->link_create.kprobe_multi.cnt != 0 &&
		       (attr->link_create.kprobe_multi.syms != 0 ||
			attr->link_create.kprobe_multi.addrs != 0);
	case BPF_TRACE_UPROBE_MULTI:
	case BPF_TRACE_UPROBE_SESSION:
		return attr->link_create.uprobe_multi.cnt != 0 &&
		       attr->link_create.uprobe_multi.offsets != 0;
#ifdef USE_BPF_LINK_CREATE_TRACING_MULTI
	case BPF_TRACE_FENTRY_MULTI:
	case BPF_TRACE_FEXIT_MULTI:
	case BPF_TRACE_FSESSION_MULTI:
		return attr->link_create.tracing_multi.cnt != 0 &&
		       attr->link_create.tracing_multi.ids != 0;
#endif
	}
	return true;
}

/* The pools' fds, which nothing else a draw is given can be mistaken for: the
 * catalog's own draw of a head field is an fd of the generic pool, here -1. */
#define LINK_PROG_FD	88
#define LINK_MAP_FD	100
#define LINK_PERF_FD	120
#define LINK_CGROUP_FD	130

enum link_target_kind { TARGET_MAP, TARGET_PERF, TARGET_CGROUP, TARGET_IFINDEX };

/*
 * What the taker of @type reads target_fd as: a perf event for
 * bpf_perf_link_attach(), a cgroup for cgroup_bpf_link_attach(), the union's
 * target_ifindex for bpf_xdp_link_attach(), tcx_link_attach() and
 * netkit_link_attach().  The rest are handed a map.
 */
static enum link_target_kind kernel_target_kind(unsigned long type)
{
	switch (type) {
	case BPF_PERF_EVENT:
		return TARGET_PERF;
	case BPF_XDP:
	case BPF_TCX_INGRESS:
	case BPF_TCX_EGRESS:
	case BPF_NETKIT_PRIMARY:
	case BPF_NETKIT_PEER:
		return TARGET_IFINDEX;
	case BPF_CGROUP_INET_INGRESS:
	case BPF_CGROUP_INET_EGRESS:
	case BPF_CGROUP_INET_SOCK_CREATE:
	case BPF_CGROUP_INET_SOCK_RELEASE:
	case BPF_CGROUP_INET4_POST_BIND:
	case BPF_CGROUP_INET6_POST_BIND:
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET6_BIND:
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_INET6_CONNECT:
	case BPF_CGROUP_UNIX_CONNECT:
	case BPF_CGROUP_INET4_GETPEERNAME:
	case BPF_CGROUP_INET6_GETPEERNAME:
	case BPF_CGROUP_UNIX_GETPEERNAME:
	case BPF_CGROUP_INET4_GETSOCKNAME:
	case BPF_CGROUP_INET6_GETSOCKNAME:
	case BPF_CGROUP_UNIX_GETSOCKNAME:
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP6_SENDMSG:
	case BPF_CGROUP_UNIX_SENDMSG:
	case BPF_CGROUP_UDP4_RECVMSG:
	case BPF_CGROUP_UDP6_RECVMSG:
	case BPF_CGROUP_UNIX_RECVMSG:
	case BPF_CGROUP_SOCK_OPS:
	case BPF_CGROUP_DEVICE:
	case BPF_CGROUP_SYSCTL:
	case BPF_CGROUP_GETSOCKOPT:
	case BPF_CGROUP_SETSOCKOPT:
	case BPF_LSM_CGROUP:
		return TARGET_CGROUP;
	default:
		return TARGET_MAP;
	}
}

static bool pick_link_map(struct bpfobj *map)
{
	memset(map, 0, sizeof(*map));
	map->map_fd = LINK_MAP_FD;
	map->map_type = BPF_MAP_TYPE_HASH;
	return true;
}

struct link_tally {
	unsigned int draws, refused, flags_set, pool_target, prog_target;
	unsigned int perf_target, cgroup_target, ifindex_target, ifindex_lo;
	unsigned int generic_prog;
	unsigned int tail_set, no_tail, tail_uncovered;
};

/* The sub-buffers the fill made for the pointer fields of the arm the attr's
 * attach type names; deferred free refused them, as it did the attr itself. */
static void free_arm_buffers(const union bpf_attr *attr)
{
	static struct syscallrecord probe;
	const struct union_variant *outer, *arm;
	unsigned int i;

	memset(&probe, 0, sizeof(probe));
	probe.a1 = BPF_LINK_CREATE;
	outer = struct_desc_resolve_variant(struct_catalog_lookup("bpf_attr"),
					    &probe, NULL);
	arm = struct_desc_resolve_nested_variant(outer,
						 (const unsigned char *) attr,
						 sizeof(*attr));
	if (arm == NULL)
		return;

	for (i = 0; i < arm->num_fields; i++) {
		const struct struct_field *f = &arm->fields[i];
		uint64_t ptr;

		if (f->tag != FT_PTR_BYTES && f->tag != FT_PTR_ARRAY)
			continue;
		memcpy(&ptr, (const unsigned char *) attr + f->offset, sizeof(ptr));
		free((void *)(uintptr_t) ptr);
	}
}

static void link_create_takes_its_arm_and_the_head_its_taker_wants(void)
{
	enum { ROUNDS = 8000 };
	static struct link_tally tally[BPF_ATTACH_TYPES_N];
	static struct syscallrecord rec;
	unsigned int round, i;

	if (get_writable_address(sizeof(unsigned long)) == NULL)
		writable_pool_init();
	fake_catalog_lookup = true;
	fake_random_fd_empty = true;
	fake_bpf_prog_fd = LINK_PROG_FD;
	fake_perf_fd = LINK_PERF_FD;
	fake_cgroup_fd = LINK_CGROUP_FD;
	fake_get_rand_bpf_map = pick_link_map;

	for (round = 0; round < ROUNDS; round++) {
		const union bpf_attr *attr;
		const unsigned char *raw;
		struct link_tally *t = NULL;
		size_t b, last = 0;
		bool tail_set = false;
		unsigned long type;

		memset(&rec, 0, sizeof(rec));
		rec.a1 = BPF_LINK_CREATE;
		syscall_bpf.sanitise(&rec);
		attr = (const union bpf_attr *) rec.a2;
		raw = (const unsigned char *) attr;
		type = attr->link_create.attach_type;

		for (i = 0; i < bpf_attach_types_count; i++) {
			if (bpf_attach_types[i] == type)
				t = &tally[i];
		}
		check("an attach type outside the vocabulary was drawn",
		      "link create", t != NULL);

		if (t != NULL) {
			t->draws++;
			if ((kernel_refuses_flags(type) && attr->link_create.flags != 0) ||
			    (kernel_refuses_target_fd(type) &&
			     attr->link_create.target_fd != 0) ||
			    (kernel_pairs_target(type) &&
			     !attr->link_create.target_fd !=
			     !attr->link_create.target_btf_id))
				t->refused++;
			t->flags_set += attr->link_create.flags != 0;
			t->pool_target += (int) attr->link_create.target_fd == LINK_MAP_FD;
			t->prog_target += (int) attr->link_create.target_fd == LINK_PROG_FD;
			t->perf_target += (int) attr->link_create.target_fd == LINK_PERF_FD;
			t->cgroup_target += (int) attr->link_create.target_fd == LINK_CGROUP_FD;
			t->ifindex_target += attr->link_create.target_ifindex < 64;
			t->ifindex_lo += attr->link_create.target_ifindex == 1;
			t->generic_prog += (int) attr->link_create.prog_fd != LINK_PROG_FD;

			/* Past the head are the arm's fields, and with them the
			 * target_btf_id every attach type has in the catalog. */
			for (b = 0; b < sizeof(attr->link_create); b++) {
				if (raw[b] == 0)
					continue;
				last = b;
				if (b >= offsetof(union bpf_attr, link_create.target_btf_id))
					tail_set = true;
			}
			t->tail_set += tail_set;
			t->no_tail += !kernel_gets_its_tail(attr);
			t->tail_uncovered += rec.a3 <= last;
		}

		rec.retval = (unsigned long) -1L;
		rec.errno_post = EBADF;
		syscall_bpf.post(&rec);
		free_arm_buffers(attr);
		free((void *) attr);
	}

	fake_get_rand_bpf_map = NULL;
	fake_bpf_prog_fd = -1;
	fake_perf_fd = -1;
	fake_cgroup_fd = -1;
	fake_random_fd_empty = false;
	fake_catalog_lookup = false;

	for (i = 0; i < bpf_attach_types_count; i++) {
		const struct link_tally *t = &tally[i];
		unsigned long type = bpf_attach_types[i];
		char name[40];

		snprintf(name, sizeof(name), "link create, attach type %lu", type);
		check("the attach type was never drawn", name, t->draws > 0);
		check("a draw sets a head field its taker refuses", name,
		      t->refused == 0);
		check("a draw has no field past the head", name,
		      t->tail_set * 2 >= t->draws);
		check("a multi attach has no count, or no array under it", name,
		      t->no_tail == 0);
		check("the size stops short of what the draw filled", name,
		      t->tail_uncovered == 0);
		check("a program is not the pool's", name, t->generic_prog == 0);
		if (!kernel_refuses_flags(type))
			check("the flags of a taker that takes them are no longer drawn",
			      name, t->flags_set * 100 >= t->draws * 80);
		if (kernel_pairs_target(type)) {
			check("a tracing attach is handed the map pool's fd", name,
			      t->pool_target == 0);
			check("a tracing attach never names a program to attach in",
			      name, t->prog_target > 0 &&
			      t->prog_target * 2 < t->draws);
		} else if (kernel_refuses_target_fd(type)) {
			continue;
		} else if (kernel_target_kind(type) == TARGET_PERF) {
			check("a perf link's target is not a perf event", name,
			      t->perf_target == t->draws);
		} else if (kernel_target_kind(type) == TARGET_CGROUP) {
			check("a cgroup link's target is not a cgroup", name,
			      t->cgroup_target == t->draws);
		} else if (kernel_target_kind(type) == TARGET_IFINDEX) {
			check("a device link's target is not a small ifindex", name,
			      t->ifindex_target == t->draws);
			check("a device link does not name lo about half the time",
			      name, t->ifindex_lo * 100 >= t->draws * 30 &&
			      t->ifindex_lo * 100 <= t->draws * 75);
		} else {
			check("a target_fd is not the pool's map", name,
			      t->pool_target == t->draws);
		}
	}
}

/*
 * bpf_prog_attach_check_attach_type() and link_create() (kernel/bpf/syscall.c):
 * whether a program of @prog_type loaded for @expected gets past the check on
 * @type and to a taker.  The check lets a plain kprobe through on the multi
 * attach types too, but their takers want a program loaded for them.
 */
static bool kernel_takes_attach_type(unsigned int prog_type,
				     unsigned int expected, unsigned int type)
{
	switch (prog_type) {
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_SK_LOOKUP:
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_LSM:
		return type == expected;
	case BPF_PROG_TYPE_CGROUP_SKB:
		return type == BPF_CGROUP_INET_INGRESS ||
		       type == BPF_CGROUP_INET_EGRESS;
	case BPF_PROG_TYPE_KPROBE:
		if (expected == BPF_TRACE_KPROBE_MULTI ||
		    expected == BPF_TRACE_KPROBE_SESSION ||
		    expected == BPF_TRACE_UPROBE_MULTI ||
		    expected == BPF_TRACE_UPROBE_SESSION)
			return type == expected;
		return type == BPF_PERF_EVENT;
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_TRACEPOINT:
		return type == BPF_PERF_EVENT;
	case BPF_PROG_TYPE_SCHED_CLS:
		return type == BPF_TCX_INGRESS || type == BPF_TCX_EGRESS ||
		       type == BPF_NETKIT_PRIMARY || type == BPF_NETKIT_PEER;
	case BPF_PROG_TYPE_SK_SKB:
		return type == BPF_SK_SKB_STREAM_PARSER ||
		       type == BPF_SK_SKB_STREAM_VERDICT ||
		       type == BPF_SK_SKB_VERDICT;
	case BPF_PROG_TYPE_XDP:
		return type == BPF_XDP;
	case BPF_PROG_TYPE_NETFILTER:
		return type == BPF_NETFILTER;
	default:
		return false;
	}
}

static struct bpfprogobj link_prog;

static bool pick_link_prog(struct bpfprogobj *prog)
{
	*prog = link_prog;
	return true;
}

/*
 * A link is drawn for the program it carries: an attach type the program
 * takes seven times in eight and any the eighth, each of the program's
 * attach types in turn when it takes more than one.  A program no link takes
 * gets any attach type.
 */
static void link_create_draws_an_attach_type_its_program_takes(void)
{
	enum { ROUNDS = 800, MAX_SEEN = 8 };
	/* kinds: how many attach types the program takes. */
	static const struct {
		unsigned int prog_type, expected, kinds;
	} progs[] = {
		{ BPF_PROG_TYPE_KPROBE, 0, 1 },
		{ BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_MULTI, 1 },
		{ BPF_PROG_TYPE_TRACEPOINT, 0, 1 },
		{ BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_INGRESS, 2 },
		{ BPF_PROG_TYPE_CGROUP_SOCK, BPF_CGROUP_INET_SOCK_CREATE, 1 },
		{ BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT, 1 },
		{ BPF_PROG_TYPE_XDP, 0, 1 },
		{ BPF_PROG_TYPE_SCHED_CLS, 0, 4 },
		{ BPF_PROG_TYPE_SK_SKB, 0, 3 },
		{ BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY, 1 },
		{ BPF_PROG_TYPE_LSM, BPF_LSM_MAC, 1 },
		{ BPF_PROG_TYPE_SOCKET_FILTER, 0, 0 },
	};
	static struct syscallrecord rec;
	unsigned int p, round, i;

	if (get_writable_address(sizeof(unsigned long)) == NULL)
		writable_pool_init();
	fake_catalog_lookup = true;
	fake_random_fd_empty = true;
	fake_get_rand_bpf_map = pick_link_map;
	fake_get_rand_bpf_prog = pick_link_prog;

	for (p = 0; p < ARRAY_SIZE(progs); p++) {
		unsigned int seen_type[MAX_SEEN], seen_count[MAX_SEEN];
		unsigned int n_seen = 0, taken = 0;
		char name[64];

		memset(&link_prog, 0, sizeof(link_prog));
		link_prog.fd = LINK_PROG_FD;
		link_prog.prog_type = progs[p].prog_type;
		link_prog.expected_attach_type = progs[p].expected;

		for (round = 0; round < ROUNDS; round++) {
			const union bpf_attr *attr;
			unsigned int type;

			memset(&rec, 0, sizeof(rec));
			rec.a1 = BPF_LINK_CREATE;
			syscall_bpf.sanitise(&rec);
			attr = (const union bpf_attr *) rec.a2;
			type = attr->link_create.attach_type;
			if (kernel_takes_attach_type(progs[p].prog_type,
						     progs[p].expected, type)) {
				taken++;
				for (i = 0; i < n_seen && seen_type[i] != type; i++)
					;
				if (i == n_seen && n_seen < MAX_SEEN) {
					seen_type[n_seen] = type;
					seen_count[n_seen++] = 0;
				}
				if (i < n_seen)
					seen_count[i]++;
			}
			rec.retval = (unsigned long) -1L;
			rec.errno_post = EBADF;
			syscall_bpf.post(&rec);
			free_arm_buffers(attr);
			free((void *) attr);
		}

		snprintf(name, sizeof(name), "link create, prog type %u loaded for %u",
			 progs[p].prog_type, progs[p].expected);
		if (progs[p].prog_type == BPF_PROG_TYPE_SOCKET_FILTER) {
			check("a program no link takes was paired with an attach type",
			      name, taken == 0);
			continue;
		}
		check("the attach type is not one the program takes seven times in eight",
		      name, taken * 100 >= ROUNDS * 82 && taken * 100 <= ROUNDS * 95);
		check("an attach type the program takes is never drawn", name,
		      n_seen == progs[p].kinds);
		for (i = 0; i < n_seen; i++)
			check("an attach type the program takes is seldom drawn", name,
			      seen_count[i] * 10 >= taken / n_seen);
	}

	fake_get_rand_bpf_prog = NULL;
	fake_get_rand_bpf_map = NULL;
	fake_random_fd_empty = false;
	fake_catalog_lookup = false;
}

#ifdef USE_BPF_LINK_CREATE_TRACING_MULTI
/*
 * bpf_tracing_multi_attach() reads link_create.tracing_multi.ids, .cookies
 * and .cnt, and only for the three attach types is_tracing_multi() names;
 * every other tracing type goes through bpf_tracing_prog_attach().  So the
 * catalog's sub-variant of LINK_CREATE for those three fills those three
 * members, the two arrays under the one count and nothing past it, and no
 * other attach type resolves to it.
 */
static void link_create_catalog_has_the_tracing_multi_tail(void)
{
	const struct union_variant *outer = NULL;
	static union bpf_attr attr;
	unsigned int i, multi = 0;

	for (i = 0; i < ARRAY_SIZE(bpf_attr_variants); i++) {
		if (bpf_attr_variants[i].name != NULL &&
		    strcmp(bpf_attr_variants[i].name, "LINK_CREATE") == 0)
			outer = &bpf_attr_variants[i];
	}
	check("the catalog has no LINK_CREATE variant", "tracing multi",
	      outer != NULL);
	if (outer == NULL)
		return;

	for (i = 0; i < bpf_attach_types_count; i++) {
		unsigned long type = bpf_attach_types[i];
		bool is_multi = type == BPF_TRACE_FENTRY_MULTI ||
				type == BPF_TRACE_FEXIT_MULTI ||
				type == BPF_TRACE_FSESSION_MULTI;
		const struct union_variant *nested;

		attr.link_create.attach_type = type;
		nested = struct_desc_resolve_nested_variant(outer,
					(const unsigned char *) &attr,
					sizeof(attr));
		if (nested == NULL || strcmp(nested->name,
					     "LINK_CREATE/TRACING_MULTI") != 0) {
			check("a tracing_multi attach type has another tail",
			      "tracing multi", !is_multi);
			continue;
		}
		check("another attach type takes the tracing_multi tail",
		      "tracing multi", is_multi);
		multi++;

		check("the tail is not the ids, cookies and cnt",
		      "tracing multi", nested->num_fields == 3 &&
		      nested->fields[0].offset ==
		      offsetof(union bpf_attr, link_create.tracing_multi.ids) &&
		      nested->fields[1].offset ==
		      offsetof(union bpf_attr, link_create.tracing_multi.cookies) &&
		      nested->fields[2].offset ==
		      offsetof(union bpf_attr, link_create.tracing_multi.cnt) &&
		      nested->fields[2].tag == FT_LEN_COUNT);
		check("the tail's size stops short of cnt", "tracing multi",
		      nested->effective_size ==
		      offsetof(union bpf_attr, link_create.tracing_multi.cnt) +
		      sizeof(attr.link_create.tracing_multi.cnt));
	}
	check("not all three tracing_multi attach types are drawn",
	      "tracing multi", multi == 3);
}
#endif /* USE_BPF_LINK_CREATE_TRACING_MULTI */

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
	map_elem_draws_reach_the_maps_code();
	link_create_takes_its_arm_and_the_head_its_taker_wants();
	link_create_draws_an_attach_type_its_program_takes();
#ifdef USE_BPF_LINK_CREATE_TRACING_MULTI
	link_create_catalog_has_the_tracing_multi_tail();
#endif

	if (failed != 0)
		BUG("a bpf sanitiser or generator drew what the kernel does not take");
#endif
}
