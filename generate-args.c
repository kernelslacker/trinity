#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "arch.h"
#include "argtype-ops.h"
#include "cmp_hints.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd.h"
#include "maps.h"
#include "minicorpus.h"
#include "net.h"
#include "numa.h"
#include "pathnames.h"
#include "random.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "strategy.h"	// plateau_rescue_bias_active_for, RRC_CMP_DERIVED
#include "struct_catalog.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// num_online_cpus
#include "utils.h"	// zmalloc

/*
 * CMP-hint injection rate.  Baseline is 1-in-16 (the historical rate the
 * ARG_OP / ARG_LIST paths shipped with); boosted to 1-in-4 inside a
 * SR_PLATEAU_FORCE intervention whose dominant rescue class is
 * RRC_CMP_DERIVED, so the learned constants the classifier credited
 * for the recent rescues fire more aggressively during the targeted
 * intervention.  Wrapped in a helper so any future tuning lands in one
 * place rather than scattered across the three call sites.
 */
#define CMP_HINT_INJECT_DENOM_BASELINE  16U
#define CMP_HINT_INJECT_DENOM_AMPLIFIED 4U

static unsigned int cmp_hint_inject_denom(void)
{
	return plateau_rescue_bias_active_for(RRC_CMP_DERIVED) ?
		CMP_HINT_INJECT_DENOM_AMPLIFIED :
		CMP_HINT_INJECT_DENOM_BASELINE;
}

/* ONE_IN denominator for substituting a wrong-subtype fd (or a generic
 * pool fd) into a typed-fd argument slot.  Trades a small fraction of
 * the precision win that typed-fd dispatch buys for coverage of the
 * wrong-fd-type bug class -- without this, a kernel type-check guard
 * sitting on the path that only fires for a mismatched fd subtype is
 * never exercised, because the consumer always hands the syscall the
 * correct subtype out of the matching obj pool. */
#define WRONG_FD_TYPE_FREQ	16

static int get_cpu(void)
{
	int i;
	i = rand() % 100;

	switch (i) {
	case 0: return -1;
	case 1: return rand() % 4096;
	case 2: return INT_MAX;
	case 3 ... 99:
		return rand() % num_online_cpus;
	}
	return 0;
}

static unsigned long handle_arg_address(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	unsigned long addr = 0;

	if (argnum == 1)
		return (unsigned long) get_address();

	if (RAND_BOOL())
		return (unsigned long) get_address();

	/* Half the time, we look to see if earlier args were also ARG_ADDRESS,
	 * and munge that instead of returning a new one from get_address() */

	addr = find_previous_arg_address(entry, rec, argnum);
	if (addr == 0)
		return (unsigned long) get_address();

	switch (rand() % 4) {
	case 0:	break;	/* return unmodified */
	case 1:	addr++;
		break;
	case 2:	addr+= sizeof(int);
		break;
	case 3:	addr+= sizeof(long);
		break;
	}

	return addr;
}

static unsigned long handle_arg_range(struct syscallentry *entry,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum)
{
	unsigned long i;
	unsigned long low = entry->arg_params[argnum - 1].range.low;
	unsigned long high = entry->arg_params[argnum - 1].range.hi;

	if (high == 0) {
		outputerr("%s forgets to set hirange!\n", entry->name);
		BUG("Fix syscall definition!\n");
	}

	if (low >= high) {
		outputerr("%s has invalid range: low(%lu) >= high(%lu)!\n",
			entry->name, low, high);
		BUG("Fix syscall definition!\n");
	}

	/* ~1 in 8: bias toward the range boundaries where off-by-one bugs hide */
	if (ONE_IN(8)) {
		switch (rand() % 4) {
		case 0: return low;
		case 1: return high;
		case 2: return (low < high) ? low + 1 : low;
		case 3: return (high > low) ? high - 1 : high;
		}
	}

	/* Guard against overflow: if high == ULONG_MAX, high - low + 1 wraps to 0 */
	if (high - low == ULONG_MAX)
		i = low + (unsigned long) rand64();
	else
		i = low + (unsigned long) rand64() % (high - low + 1);
	return i;
}

static void get_num_and_values(struct syscallentry *entry, unsigned int argnum,
		unsigned int *num, const unsigned long **values)
{
	*num = entry->arg_params[argnum - 1].list.num;
	*values = entry->arg_params[argnum - 1].list.values;

	if (*num == 0)
		BUG("ARG_OP/LIST with 0 args. What?\n");

	if (*values == NULL)
		BUG("ARG_OP/LIST with no values.\n");
}

/*
 * Get a single entry from the list of values.
 */
static unsigned long handle_arg_op(struct syscallentry *entry,
				   struct syscallrecord *rec,
				   unsigned int argnum)
{
	const unsigned long *values = NULL;
	unsigned int num = 0;
	unsigned int call = rec->nr;
	unsigned long hint;

	get_num_and_values(entry, argnum, &num, &values);

	/* ~1 in 16: try a CMP hint as an undocumented command code.
	 * Bumped to ~1 in 4 inside a SR_PLATEAU_FORCE intervention whose
	 * dominant rescue class is RRC_CMP_DERIVED. */
	if (ONE_IN(cmp_hint_inject_denom()) &&
	    cmp_hints_try_get(call, &hint))
		return hint;

	return values[rand() % num];
}

/*
 * OR a random number of bits from the list of values into a bitmask, and return it.
 */
static unsigned long handle_arg_list(struct syscallentry *entry,
				     struct syscallrecord *rec,
				     unsigned int argnum)
{
	unsigned long mask = 0;
	unsigned int num = 0;
	const unsigned long *values = NULL;
	unsigned int call = rec->nr;
	unsigned long hint;

	get_num_and_values(entry, argnum, &num, &values);

	/* ~1 in 8: OR in a shifted flag to probe for undocumented adjacent bits */
	if (ONE_IN(8)) {
		mask = set_rand_bitmask(num, values);
		mask |= shift_flag_bit(values[rand() % num]);
		return mask;
	}

	/* ~1 in 16: OR in a CMP hint as an undocumented flag bit.
	 * Bumped to ~1 in 4 inside a SR_PLATEAU_FORCE intervention whose
	 * dominant rescue class is RRC_CMP_DERIVED. */
	if (ONE_IN(cmp_hint_inject_denom()) &&
	    cmp_hints_try_get(call, &hint)) {
		mask = set_rand_bitmask(num, values);
		mask |= hint;
		return mask;
	}

	if (RAND_BOOL())
		num = min(num, 3U);

	mask = set_rand_bitmask(num, values);
	return mask;
}

/*
 * If this argtype declares a paired_length in the descriptor table and
 * the next slot is actually of that paired type, publish len there so
 * the corresponding ARG_IOVECLEN / ARG_SOCKADDRLEN generator can hand
 * it back unchanged.  Replaces the hardcoded
 * `entry->argtype[argnum] == ARG_IOVECLEN/ARG_SOCKADDRLEN` checks that
 * used to live inside handle_arg_iovec / handle_arg_sockaddr.
 */
static void publish_paired_length(struct syscallentry *entry,
				  struct syscallrecord *rec,
				  unsigned int argnum,
				  unsigned long len)
{
	const struct argtype_ops *ops = argtype_get_ops(get_argtype(entry, argnum));

	if (ops->paired_length == ARG_UNDEFINED)
		return;
	if (argnum >= 6)
		return;
	if (entry->argtype[argnum] != ops->paired_length)
		return;

	switch (argnum) {
	case 1:	rec->a2 = len; break;
	case 2:	rec->a3 = len; break;
	case 3:	rec->a4 = len; break;
	case 4:	rec->a5 = len; break;
	case 5:	rec->a6 = len; break;
	}
}

static unsigned long handle_arg_iovec(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	unsigned long num_entries;

	/* Each iovec entry pulls a map under a global lock, so bias toward
	 * small counts: 90% of the time pick 1-8, only occasionally exercise
	 * the larger 1-256 range. */
	if (ONE_IN(10))
		num_entries = RAND_RANGE(1, 256);
	else
		num_entries = RAND_RANGE(1, 8);

	publish_paired_length(entry, rec, argnum, num_entries);
	return (unsigned long) alloc_iovec(num_entries);
}

static unsigned long handle_arg_sockaddr(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	struct sockaddr *sockaddr = NULL;
	socklen_t sockaddrlen = 0;

	generate_sockaddr((struct sockaddr **)&sockaddr, &sockaddrlen, PF_NOHINT);

	publish_paired_length(entry, rec, argnum, sockaddrlen);
	return (unsigned long) sockaddr;
}

static unsigned long handle_arg_mode_t(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec __unused__,
				       unsigned int argnum __unused__)
{
	unsigned int i, count;
	mode_t mode = 0, op = 0;

	count = rand() % 9;

	for (i = 0; i < count; i++) {
		unsigned int j;

		j = rand() % 15;
		switch (j) {
		case  0: op = S_IRWXU; break;
		case  1: op = S_IRUSR; break;
		case  2: op = S_IWUSR; break;
		case  3: op = S_IXUSR; break;

		case  4: op = S_IRWXG; break;
		case  5: op = S_IRGRP; break;
		case  6: op = S_IWGRP; break;
		case  7: op = S_IXGRP; break;

		case  8: op = S_IRWXO; break;
		case  9: op = S_IROTH; break;
		case 10: op = S_IWOTH; break;
		case 11: op = S_IXOTH; break;

		case 12: op = S_ISUID; break;
		case 13: op = S_ISGID; break;
		case 14: op = S_ISVTX; break;
		}
		if (RAND_BOOL())
			mode |= op;
		else
			mode &= ~op;
	}
	return mode;
}

enum argtype get_argtype(struct syscallentry *entry, unsigned int argnum)
{
	return entry->argtype[argnum - 1];
}

static unsigned long gen_undefined_arg(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec,
				       unsigned int argnum __unused__)
{
	unsigned int call = rec->nr;
	unsigned long hint;

	switch (rand() % 9) {
	case 0:
		if (cmp_hints_try_get(call, &hint))
			return hint;
		return mutate_value(get_boundary_value());
	case 1: return mutate_value(get_boundary_value());
	case 2: return mutate_value(rand64());
	case 3: return get_interesting_value();
	case 4: return rand64();
	case 5: return (unsigned long) get_writable_address(page_size);
	case 6: return rand64() & rand64();	/* sparse bits (~25% set) */
	case 7: return rand64() | rand64();	/* dense bits (~75% set) */
	case 8: return get_sizeof_boundary_value();
	}
	return rand64();
}

/*
 * Thin generator wrappers used by argtype_table[].  Each one encodes the
 * body of the matching case in fill_arg's switch so the table can dispatch
 * directly off the argtype.  Where the inline case is a single expression
 * (ARG_LEN, ARG_MMAP, ARG_CPU, ...) the wrapper is one return statement.
 * Where the inline case used a pool-vs-garbage substitution (ARG_PID and
 * friends), the wrapper preserves the ~1-in-8 bias.
 */

static unsigned long gen_arg_fd(struct syscallentry *entry,
				struct syscallrecord *rec __unused__,
				unsigned int argnum)
{
	struct results *results = &entry->results[argnum - 1];
	bool filter;
	int fd = 0;
	int tries;

	/* Prefer live fds returned by recent syscalls (70% of the time). */
	if (rand() % 10 < 7) {
		struct childdata *child = this_child();

		if (child != NULL) {
			int live_fd = get_child_live_fd(child);

			if (live_fd >= 0)
				return live_fd;
		}
	}
	if (RAND_BOOL()) {
		unsigned int i;
		/* If this is the 2nd or more ARG_FD, make it unique */
		for (i = 1; i < argnum; i++) {
			enum argtype arg;
			arg = get_argtype(entry, i);
			if (arg == ARG_FD)
				return get_new_random_fd();
		}
	}

	/* Same failed_fds re-roll bias as the typed-fd path. */
	filter = (rand() % 10) < 7;
	for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
		fd = get_random_fd();
		if (!filter || !fd_recently_failed(results, fd))
			break;
	}
	return (unsigned long) fd;
}

static unsigned long gen_arg_typed_fd(struct syscallentry *entry,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum)
{
	enum argtype argtype = get_argtype(entry, argnum);
	struct results *results = &entry->results[argnum - 1];
	bool filter = (rand() % 10) < 7;
	enum argtype effective_argtype = argtype;
	bool use_generic = false;
	int fd = 0;
	int tries;

	/* With ~1/WRONG_FD_TYPE_FREQ probability, swap the requested typed-fd
	 * subtype for a different one (or, less often, a generic fd from the
	 * global pool) before entering the reroll loop.  The swap is sticky
	 * across rerolls so the failed-fd filter still has a chance to drop
	 * known-bad (slot, fd) pairs for whatever fd source we ended up with. */
	if (ONE_IN(WRONG_FD_TYPE_FREQ)) {
		__atomic_fetch_add(&shm->stats.wrong_fd_type_substitutions,
				   1UL, __ATOMIC_RELAXED);
		if (ONE_IN(4)) {
			use_generic = true;
			__atomic_fetch_add(&shm->stats.wrong_fd_type_subst_generic,
					   1UL, __ATOMIC_RELAXED);
		} else {
			unsigned int range = ARG_FD_TIMERFD - ARG_FD_BPF_BTF;
			unsigned int pick = rand() % range;

			effective_argtype = ARG_FD_BPF_BTF + pick;
			if (effective_argtype >= argtype)
				effective_argtype++;
		}
	}

	for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
		fd = use_generic ? get_random_fd()
				 : get_typed_fd(effective_argtype);
		if (!filter || !fd_recently_failed(results, fd))
			break;
	}
	return (unsigned long) fd;
}

static unsigned long gen_arg_len(struct syscallentry *entry __unused__,
				 struct syscallrecord *rec __unused__,
				 unsigned int argnum __unused__)
{
	return (unsigned long) get_len();
}

static unsigned long gen_arg_non_null_address(struct syscallentry *entry __unused__,
					      struct syscallrecord *rec __unused__,
					      unsigned int argnum __unused__)
{
	return (unsigned long) get_non_null_address();
}

static unsigned long gen_arg_mmap(struct syscallentry *entry __unused__,
				  struct syscallrecord *rec __unused__,
				  unsigned int argnum __unused__)
{
	return (unsigned long) get_map();
}

static unsigned long gen_arg_pid(struct syscallentry *entry __unused__,
				 struct syscallrecord *rec __unused__,
				 unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_pid_from_pool();
}

static unsigned long gen_arg_key_serial(struct syscallentry *entry __unused__,
					struct syscallrecord *rec __unused__,
					unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_key_serial();
}

static unsigned long gen_arg_timerid(struct syscallentry *entry __unused__,
				     struct syscallrecord *rec __unused__,
				     unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_timerid();
}

static unsigned long gen_arg_aio_ctx(struct syscallentry *entry __unused__,
				     struct syscallrecord *rec __unused__,
				     unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) rand64();
	return get_random_aio_ctx();
}

static unsigned long gen_arg_sem_id(struct syscallentry *entry __unused__,
				    struct syscallrecord *rec __unused__,
				    unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_sem();
}

static unsigned long gen_arg_msg_id(struct syscallentry *entry __unused__,
				    struct syscallrecord *rec __unused__,
				    unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_msg();
}

static unsigned long gen_arg_sysv_shm(struct syscallentry *entry __unused__,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_shm();
}

static unsigned long gen_arg_cpu(struct syscallentry *entry __unused__,
				 struct syscallrecord *rec __unused__,
				 unsigned int argnum __unused__)
{
	return (unsigned long) get_cpu();
}

static unsigned long gen_arg_numa_node(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec __unused__,
				       unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (rand32() & 0xFFFF);
	return (unsigned long) random_numa_node();
}

static unsigned long gen_arg_pathname(struct syscallentry *entry __unused__,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum __unused__)
{
	return (unsigned long) generate_pathname();
}

/* ARG_IOVECLEN / ARG_SOCKADDRLEN: the value was published into the slot
 * by the paired ARG_IOVEC / ARG_SOCKADDR generator that ran earlier in
 * this dispatch.  Just hand it back. */
static unsigned long gen_arg_paired_length(struct syscallentry *entry __unused__,
					   struct syscallrecord *rec,
					   unsigned int argnum)
{
	return get_argval(rec, argnum);
}

static unsigned long gen_arg_socketinfo(struct syscallentry *entry __unused__,
					struct syscallrecord *rec __unused__,
					unsigned int argnum __unused__)
{
	return (unsigned long) get_rand_socketinfo();
}

/*
 * Size used when the slot is declared ARG_STRUCT_PTR_IN but the struct
 * catalog has no entry for (syscall, arg).  Big enough to cover the
 * common kernel-side copy_from_user() sizes (sizeof(struct sched_attr)
 * etc.) without us guessing wrong about the specific layout.
 */
#define STRUCT_PTR_IN_FALLBACK_SIZE	256U

/*
 * ARG_STRUCT_PTR_IN: hand the kernel a heap-allocated buffer sized for
 * the cataloged struct at this (syscall, arg).  Walks struct_catalog for
 * the layout; for each addressable field of natural width <= 4 bytes,
 * splats a fresh random value of that width.  Wider fields (typically
 * pointers and u64 flags) are left as the zmalloc zero -- a random
 * 8-byte value in a pointer slot just bounces at copy_from_user with
 * -EFAULT and would starve every other field of fuzz coverage.
 *
 * Catalog miss: fall back to STRUCT_PTR_IN_FALLBACK_SIZE bytes of zeros.
 * The slot stays a valid kernel-readable buffer, so the kernel still
 * gets past its first copy_from_user() boundary check; it just won't
 * see varied field content until the catalog learns this syscall.
 *
 * The allocation is enqueued on the deferred-free queue at generation
 * time rather than via the argtype_ops cleanup hook, so a downstream
 * sanitise() that reallocates and overwrites the arg slot doesn't end
 * up double-enqueueing the sanitise's own pointer (which has its own
 * post-handler-driven free path).
 */
static unsigned long gen_arg_struct_ptr_in(struct syscallentry *entry __unused__,
					   struct syscallrecord *rec,
					   unsigned int argnum)
{
	const struct struct_desc *desc;
	unsigned int size;
	unsigned char *buf;

	desc = struct_arg_lookup(rec->nr, argnum, rec->do32bit);
	size = desc ? desc->struct_size : STRUCT_PTR_IN_FALLBACK_SIZE;

	buf = zmalloc(size);

	if (desc != NULL) {
		unsigned int i;

		for (i = 0; i < desc->num_fields; i++) {
			const struct struct_field *f = &desc->fields[i];

			if (f->offset + f->size > size)
				continue;
			switch (f->size) {
			case 1:
				buf[f->offset] = (unsigned char) rand32();
				break;
			case 2: {
				uint16_t v = (uint16_t) rand32();
				memcpy(buf + f->offset, &v, sizeof(v));
				break;
			}
			case 4: {
				uint32_t v = rand32();
				memcpy(buf + f->offset, &v, sizeof(v));
				break;
			}
			default:
				/* leave wider fields zeroed -- see above */
				break;
			}
		}
	}

	deferred_free_enqueue(buf, NULL);
	return (unsigned long) buf;
}

/*
 * Size used when the slot is declared ARG_STRUCT_PTR_OUT but the struct
 * catalog has no entry for (syscall, arg).  Big enough to cover the
 * common kernel-side copy_to_user() sizes (struct statx is 256 bytes,
 * struct stat ~144, struct sysinfo ~64) without guessing wrong about
 * the specific layout.
 */
#define STRUCT_PTR_OUT_FALLBACK_SIZE	256U

/*
 * Byte the buffer is pre-filled with before the kernel writes into it.
 * Any non-zero, easily-recognisable value works; 0xAA is the historical
 * "uninitialised heap" pattern and survives both the kernel's
 * copy_to_user destination check and direct byte comparison.  Bytes the
 * kernel does not overwrite remain 0xAA, which lets a future post-
 * validation pass tell touched-bytes apart from untouched-bytes
 * without an explicit length out-parameter.
 */
#define STRUCT_PTR_OUT_POISON_BYTE	0xAAU

/*
 * ARG_STRUCT_PTR_OUT: hand the kernel a heap-allocated buffer sized for
 * the cataloged struct at this (syscall, arg) and pre-filled with a
 * recognisable poison byte (0xAA).  The kernel's copy_to_user() lands
 * on a buffer of exactly the right size and the post handler sees the
 * kernel's writes against a known background pattern.
 *
 * Differs from ARG_STRUCT_PTR_IN in two ways: there is no per-field
 * random splat (the kernel writes the bytes, the fuzzer does not read
 * them as input) and the buffer is poison-filled rather than zero-
 * filled so untouched-bytes are visually distinct.
 *
 * Catalog miss: fall back to STRUCT_PTR_OUT_FALLBACK_SIZE bytes of
 * poison.  The slot stays a valid kernel-writable buffer big enough for
 * the largest struct in our migration list (struct statx), so the
 * kernel still copies its full output without truncation; once the
 * catalog learns the syscall, the allocation shrinks to the exact
 * struct size.
 *
 * The allocation is enqueued on the deferred-free queue at generation
 * time, mirroring ARG_STRUCT_PTR_IN: several callers we expect to
 * migrate still carry sanitise/post pairs that snapshot the pointer
 * for re-read in the post handler, and the deferred queue keeps the
 * buffer alive long enough for that re-read while the post handler's
 * own free path remains independent.
 *
 * Follow-up worth flagging: post-validation that checks whether the
 * 0xAA canary was overwritten is out of scope for this commit -- it
 * needs the catalog to land first so the per-slot allocation is
 * actually reaching the kernel before we start asserting on the bytes
 * the kernel wrote back.
 */
static unsigned long gen_arg_struct_ptr_out(struct syscallentry *entry __unused__,
					    struct syscallrecord *rec,
					    unsigned int argnum)
{
	const struct struct_desc *desc;
	unsigned int size;
	unsigned char *buf;

	desc = struct_arg_lookup(rec->nr, argnum, rec->do32bit);
	size = desc ? desc->struct_size : STRUCT_PTR_OUT_FALLBACK_SIZE;

	buf = zmalloc(size);
	memset(buf, STRUCT_PTR_OUT_POISON_BYTE, size);

	deferred_free_enqueue(buf, NULL);
	return (unsigned long) buf;
}

/*
 * Per-struct-name table of older ABI sizes for extensible structs.  The
 * kernel's copy_struct_from_user() path branches heavily on the size
 * word: smaller-than-current is the "old userspace, new kernel" leg, and
 * exact older-ABI sizes (CLONE_ARGS_SIZE_VER0/1/2, SCHED_ATTR_SIZE_VER0
 * etc) walk a different validator than the current sizeof().  Picking
 * these sizes explicitly keeps the old-ABI branches exercised long after
 * the catalog's struct_size has grown past them.
 */
struct struct_old_abi_sizes {
	const char *name;
	const unsigned int *sizes;
	unsigned int num_sizes;
};

static const unsigned int clone_args_old_sizes[] = { 64, 80, 88 };
static const unsigned int sched_attr_old_sizes[] = { 48, 56 };
static const unsigned int mount_attr_old_sizes[] = { 32 };

static const struct struct_old_abi_sizes struct_old_abi_table[] = {
	{ "clone_args",	clone_args_old_sizes,	ARRAY_SIZE(clone_args_old_sizes) },
	{ "sched_attr",	sched_attr_old_sizes,	ARRAY_SIZE(sched_attr_old_sizes) },
	{ "mount_attr",	mount_attr_old_sizes,	ARRAY_SIZE(mount_attr_old_sizes) },
};

static const struct struct_old_abi_sizes *lookup_old_abi(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(struct_old_abi_table); i++) {
		if (strcmp(struct_old_abi_table[i].name, name) == 0)
			return &struct_old_abi_table[i];
	}
	return NULL;
}

/*
 * Find the catalog struct paired with this syscall by scanning its
 * argtype slots for an ARG_STRUCT_PTR_IN / ARG_STRUCT_PTR_OUT and
 * resolving that slot via struct_arg_lookup().  Returns NULL if the
 * syscall has no paired struct ptr slot, or has one but the struct
 * isn't cataloged.
 */
static const struct struct_desc *paired_struct_desc(struct syscallentry *entry,
						    struct syscallrecord *rec)
{
	unsigned int i;

	for (i = 0; i < entry->num_args; i++) {
		enum argtype t = entry->argtype[i];

		if (t == ARG_STRUCT_PTR_IN || t == ARG_STRUCT_PTR_OUT)
			return struct_arg_lookup(rec->nr, i + 1, rec->do32bit);
	}
	return NULL;
}

/*
 * Catalog-gap fallback cap for ARG_STRUCT_SIZE when no paired struct
 * is registered for this syscall.  Keeps the scalar in a plausible
 * size_t range without spraying ULONG_MAX values into a slot the
 * kernel will trivially reject.
 */
#define ARG_STRUCT_SIZE_FALLBACK_CAP	4096U

/*
 * ARG_STRUCT_SIZE: produce a size value for an extensible-struct
 * syscall's size argument.  These syscalls (clone3, sched_setattr/
 * sched_getattr, openat2, statmount, mount_setattr, open_tree_attr ...)
 * are dispatched by copy_struct_from_user(), which branches on the
 * size word before it ever inspects the struct's fields: an undersize
 * value is rejected outright (-E2BIG/-EINVAL), an oversize value walks
 * a zero-padding leg, and exact older-ABI sizes (CLONE_ARGS_SIZE_VER0
 * etc) walk a different validator than the current sizeof().
 *
 * Distribution (when a paired catalog struct exists):
 *   50%  exact current sizeof()         -- the kernel's fast path
 *   20%  known older-ABI size           -- exercises the size-shrink legs
 *   10%  sizeof+/-1 boundary            -- off-by-one in the size check
 *   10%  0 / small / UINT_MAX / huge    -- structural rejection paths
 *   10%  CMP-hint-derived for this nr   -- learned-from-kernel sizes
 *
 * Catalog gap: no paired struct cataloged, so the exact size is not
 * derivable.  Fall back to a bounded random scalar; better than zeroing
 * the slot and starving any field-shape sensitive path of variance.
 */
static unsigned long gen_arg_struct_size(struct syscallentry *entry,
					 struct syscallrecord *rec,
					 unsigned int argnum __unused__)
{
	const struct struct_desc *desc;
	const struct struct_old_abi_sizes *oa;
	unsigned long hint;
	unsigned int roll;

	if (ONE_IN(10) && cmp_hints_try_get(rec->nr, &hint))
		return hint;

	desc = paired_struct_desc(entry, rec);
	if (desc == NULL)
		return (unsigned long) (rand32() % ARG_STRUCT_SIZE_FALLBACK_CAP);

	roll = rand() % 10;

	/* 50%: exact current sizeof() */
	if (roll < 5)
		return desc->struct_size;

	/* 20%: known older-ABI size, else exact sizeof() */
	if (roll < 7) {
		oa = lookup_old_abi(desc->name);
		if (oa != NULL)
			return oa->sizes[rand() % oa->num_sizes];
		return desc->struct_size;
	}

	/* 10%: sizeof +/- 1 boundary */
	if (roll < 8) {
		if (RAND_BOOL())
			return desc->struct_size + 1;
		return desc->struct_size > 0 ? desc->struct_size - 1 : 0;
	}

	/* 20% remaining: structural-rejection stress */
	switch (rand() % 6) {
	case 0: return 0;
	case 1: return 1 + (rand() % 16);
	case 2: return UINT_MAX;
	case 3: return INT_MAX;
	case 4: return ((unsigned long) rand32()) << 16;
	default: return ULONG_MAX;
	}
}

/*
 * Shared cleanup helper for any argtype whose generator hands back a
 * heap allocation that must be released after the syscall returns
 * (ARG_PATHNAME, ARG_IOVEC, ARG_SOCKADDR).
 */
static void cleanup_deferred_free(struct syscallrecord *rec, unsigned int argnum)
{
	deferred_free_enqueue((void *) get_argval(rec, argnum), NULL);
}

/*
 * Per-argtype policy descriptor table.
 *
 * Indexed by enum argtype.  Each entry concentrates everything fill_arg,
 * generic_free_arg, and blanket_address_scrub need to know about that
 * argtype: how to produce a value, how to release it afterwards, whether
 * the slot participates in the fd biases, the blanket address scrub, the
 * numeric-substitute fuzzer technique, and whether it has a paired
 * length slot that follows it in the argument list.
 */
const struct argtype_ops argtype_table[] = {
	[ARG_UNDEFINED] = {
		.name = "ARG_UNDEFINED",
		.generate = gen_undefined_arg,
	},
	[ARG_FD] = {
		.name = "ARG_FD",
		.generate = gen_arg_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_LEN] = {
		.name = "ARG_LEN",
		.generate = gen_arg_len,
	},
	[ARG_ADDRESS] = {
		.name = "ARG_ADDRESS",
		.generate = handle_arg_address,
		.default_address_scrub = true,
	},
	[ARG_MODE_T] = {
		.name = "ARG_MODE_T",
		.generate = handle_arg_mode_t,
	},
	[ARG_NON_NULL_ADDRESS] = {
		.name = "ARG_NON_NULL_ADDRESS",
		.generate = gen_arg_non_null_address,
		.default_address_scrub = true,
	},
	[ARG_PID] = {
		.name = "ARG_PID",
		.generate = gen_arg_pid,
		.accepts_numeric_substitute = true,
	},
	[ARG_KEY_SERIAL] = {
		.name = "ARG_KEY_SERIAL",
		.generate = gen_arg_key_serial,
		.accepts_numeric_substitute = true,
	},
	[ARG_TIMERID] = {
		.name = "ARG_TIMERID",
		.generate = gen_arg_timerid,
		.accepts_numeric_substitute = true,
	},
	[ARG_AIO_CTX] = {
		.name = "ARG_AIO_CTX",
		.generate = gen_arg_aio_ctx,
		.accepts_numeric_substitute = true,
	},
	[ARG_SEM_ID] = {
		.name = "ARG_SEM_ID",
		.generate = gen_arg_sem_id,
		.accepts_numeric_substitute = true,
	},
	[ARG_MSG_ID] = {
		.name = "ARG_MSG_ID",
		.generate = gen_arg_msg_id,
		.accepts_numeric_substitute = true,
	},
	[ARG_SYSV_SHM] = {
		.name = "ARG_SYSV_SHM",
		.generate = gen_arg_sysv_shm,
		.accepts_numeric_substitute = true,
	},
	[ARG_RANGE] = {
		.name = "ARG_RANGE",
		.generate = handle_arg_range,
		.default_address_scrub = true,
	},
	[ARG_OP] = {
		.name = "ARG_OP",
		.generate = handle_arg_op,
	},
	[ARG_LIST] = {
		.name = "ARG_LIST",
		.generate = handle_arg_list,
	},
	[ARG_CPU] = {
		.name = "ARG_CPU",
		.generate = gen_arg_cpu,
	},
	[ARG_NUMA_NODE] = {
		.name = "ARG_NUMA_NODE",
		.generate = gen_arg_numa_node,
		.accepts_numeric_substitute = true,
	},
	[ARG_PATHNAME] = {
		.name = "ARG_PATHNAME",
		.generate = gen_arg_pathname,
		.cleanup = cleanup_deferred_free,
	},
	[ARG_IOVEC] = {
		.name = "ARG_IOVEC",
		.generate = handle_arg_iovec,
		.cleanup = cleanup_deferred_free,
		.paired_length = ARG_IOVECLEN,
	},
	[ARG_IOVECLEN] = {
		.name = "ARG_IOVECLEN",
		.generate = gen_arg_paired_length,
	},
	[ARG_SOCKADDR] = {
		.name = "ARG_SOCKADDR",
		.generate = handle_arg_sockaddr,
		.cleanup = cleanup_deferred_free,
		.paired_length = ARG_SOCKADDRLEN,
	},
	[ARG_SOCKADDRLEN] = {
		.name = "ARG_SOCKADDRLEN",
		.generate = gen_arg_paired_length,
	},
	[ARG_MMAP] = {
		.name = "ARG_MMAP",
		.generate = gen_arg_mmap,
	},
	[ARG_SOCKETINFO] = {
		.name = "ARG_SOCKETINFO",
		.generate = gen_arg_socketinfo,
	},
	[ARG_STRUCT_PTR_IN] = {
		.name = "ARG_STRUCT_PTR_IN",
		.generate = gen_arg_struct_ptr_in,
		.paired_length = ARG_STRUCT_SIZE,
	},
	[ARG_STRUCT_PTR_OUT] = {
		.name = "ARG_STRUCT_PTR_OUT",
		.generate = gen_arg_struct_ptr_out,
		.paired_length = ARG_STRUCT_SIZE,
	},
	[ARG_STRUCT_SIZE] = {
		.name = "ARG_STRUCT_SIZE",
		.generate = gen_arg_struct_size,
	},
	[ARG_FD_BPF_BTF] = {
		.name = "ARG_FD_BPF_BTF",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_LINK] = {
		.name = "ARG_FD_BPF_LINK",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_MAP] = {
		.name = "ARG_FD_BPF_MAP",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_PROG] = {
		.name = "ARG_FD_BPF_PROG",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_EPOLL] = {
		.name = "ARG_FD_EPOLL",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_EVENTFD] = {
		.name = "ARG_FD_EVENTFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_FANOTIFY] = {
		.name = "ARG_FD_FANOTIFY",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_FS_CTX] = {
		.name = "ARG_FD_FS_CTX",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_INOTIFY] = {
		.name = "ARG_FD_INOTIFY",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_IO_URING] = {
		.name = "ARG_FD_IO_URING",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_LANDLOCK] = {
		.name = "ARG_FD_LANDLOCK",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MEMFD] = {
		.name = "ARG_FD_MEMFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MOUNT] = {
		.name = "ARG_FD_MOUNT",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MQ] = {
		.name = "ARG_FD_MQ",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PERF] = {
		.name = "ARG_FD_PERF",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PIDFD] = {
		.name = "ARG_FD_PIDFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PIPE] = {
		.name = "ARG_FD_PIPE",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_SIGNALFD] = {
		.name = "ARG_FD_SIGNALFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_SOCKET] = {
		.name = "ARG_FD_SOCKET",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_TIMERFD] = {
		.name = "ARG_FD_TIMERFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
};

const unsigned int argtype_table_size =
	sizeof(argtype_table) / sizeof(argtype_table[0]);

const struct argtype_ops *argtype_get_ops(enum argtype t)
{
	if ((unsigned int) t >= argtype_table_size)
		BUG("argtype_get_ops: argtype out of range\n");
	if (argtype_table[t].generate == NULL)
		BUG("argtype_get_ops: argtype has no generator\n");
	return &argtype_table[t];
}

/*
 * Build the address-scrub slot bitmap for entry's argtype[] table.
 * Called once per syscallentry at table-init time from copy_syscall_table()
 * in tables.c; the cached mask in entry->address_scrub_mask drives
 * blanket_address_scrub() below without re-walking argtype[] or re-running
 * argtype_get_ops() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype carries the default_address_scrub descriptor flag.
 */
uint8_t compute_address_scrub_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		const struct argtype_ops *ops = argtype_get_ops(entry->argtype[i]);

		if (ops->default_address_scrub)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the cleanup-hook slot bitmap for entry's argtype[] table.  Called
 * once per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->cleanup_arg_mask drives
 * generic_free_arg() below without re-walking argtype[] or re-running
 * argtype_get_ops() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype has a non-NULL .cleanup hook in the descriptor table.
 */
uint8_t compute_cleanup_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		const struct argtype_ops *ops = argtype_get_ops(entry->argtype[i]);

		if (ops->cleanup != NULL)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the fd-arg slot bitmap for entry's argtype[] table.  Called once
 * per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->fd_arg_mask drives the fd-scoreboard
 * update loops in handle_success() / handle_failure() (results.c) without
 * re-running is_fdarg() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype is ARG_FD or any typed-fd argtype.
 */
uint8_t compute_fd_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (is_fdarg(entry->argtype[i]))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the ARG_LEN slot bitmap for entry's argtype[] table.  Called once
 * per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->len_arg_mask drives the
 * successful-length scoreboard update in handle_success() (results.c)
 * without re-running get_argtype() per slot.  Bit k (k=0..5) set means
 * slot (k+1)'s argtype is ARG_LEN.
 */
uint8_t compute_len_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (entry->argtype[i] == ARG_LEN)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

static unsigned long fill_arg(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	const struct argtype_ops *ops;

	if (argnum > entry->num_args)
		return 0;

	ops = argtype_get_ops(get_argtype(entry, argnum));

	/* Pre-generate bias: for fd-typed args, occasionally re-pick a low
	 * fd that previously succeeded for this exact (syscall, argnum)
	 * slot.  Targets the sweet spot where the kernel accepted the fd
	 * last time, so we keep exercising the post-validation path instead
	 * of bouncing off EBADF/EINVAL on a fresh random pick. */
	if (ops->can_use_success_fd_bias && RAND_BOOL()) {
		int fd = pick_successful_fd(&entry->results[argnum - 1]);

		if (fd >= 0)
			return (unsigned long) fd;
	}

	return ops->generate(entry, rec, argnum);
}

/* Default-on scrub: any argtype with default_address_scrub set in the
 * descriptor table (today ARG_ADDRESS / ARG_NON_NULL_ADDRESS / ARG_RANGE)
 * that ended up aliasing shared_regions or the libc heap arena gets
 * redirected to a writable address before the syscall is issued. Catches
 * the coverage-gap class where per-syscall sanitisers either don't call
 * avoid_shared_buffer() or miss specific slots. Length default is
 * page_size (conservative; bare ARG_ADDRESS carries no length info
 * and walking adjacent slots per dispatch is too expensive). */
static void blanket_address_scrub(struct syscallentry *entry, struct syscallrecord *rec)
{
	uint8_t mask = entry->address_scrub_mask;

	/* Most syscalls have no scrub-eligible slots; skip the walk entirely
	 * via the cached mask instead of running argtype_get_ops() per arg. */
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		unsigned long *slot;

		switch (i) {
		case 1: slot = &rec->a1; break;
		case 2: slot = &rec->a2; break;
		case 3: slot = &rec->a3; break;
		case 4: slot = &rec->a4; break;
		case 5: slot = &rec->a5; break;
		case 6: slot = &rec->a6; break;
		default: slot = NULL; break;
		}
		if (slot != NULL)
			avoid_shared_buffer(slot, page_size);
		mask &= (uint8_t)(mask - 1);
	}
}

void generic_sanitise(struct syscallentry *entry, struct syscallrecord *rec)
{
	/* Defensive: zero arg slots so any ARG_UNDEFINED entry doesn't
	 * inherit stale values from the previous syscall's record.  Also
	 * zero the post_state snapshot slot — sanitisers that use it
	 * allocate fresh in this dispatch, and a stale value left by a
	 * previous syscall (e.g. one whose post handler did not reach the
	 * deferred_freeptr) would otherwise survive into a post handler
	 * that now reads it as a live pointer.
	 *
	 * Only zero the slots that won't be overwritten below by fill_arg();
	 * the bulk memset of all six was wasted work for the common case of
	 * 4-6 argument syscalls. Switch fall-through unrolls the per-slot
	 * zero so the compiler can pick an efficient sequence. */
	switch (entry->num_args) {
	case 0: rec->a1 = 0; /* fall through */
	case 1: rec->a2 = 0; /* fall through */
	case 2: rec->a3 = 0; /* fall through */
	case 3: rec->a4 = 0; /* fall through */
	case 4: rec->a5 = 0; /* fall through */
	case 5: rec->a6 = 0; /* fall through */
	default: break;
	}
	rec->post_state = 0;

	/* num_args is the authority for which slots are present.
	 * Don't gate on argtype[i] != 0 — ARG_UNDEFINED is enum value 0,
	 * which would silently skip filling those slots even though
	 * fill_arg() handles ARG_UNDEFINED by returning a random value. */
	if (entry->num_args >= 1)
		rec->a1 = fill_arg(entry, rec, 1);
	if (entry->num_args >= 2)
		rec->a2 = fill_arg(entry, rec, 2);
	if (entry->num_args >= 3)
		rec->a3 = fill_arg(entry, rec, 3);
	if (entry->num_args >= 4)
		rec->a4 = fill_arg(entry, rec, 4);
	if (entry->num_args >= 5)
		rec->a5 = fill_arg(entry, rec, 5);
	if (entry->num_args >= 6)
		rec->a6 = fill_arg(entry, rec, 6);
}

void generic_free_arg(struct syscallentry *entry, struct syscallrecord *rec)
{
	unsigned int i;

	BUG_ON(entry == NULL);

	for_each_arg(entry, i) {
		const struct argtype_ops *ops = argtype_get_ops(get_argtype(entry, i));

		if (ops->cleanup != NULL)
			ops->cleanup(rec, i);
	}
}

void generate_syscall_args(struct syscallrecord *rec)
{
	struct syscallentry *entry;

	lock(&rec->lock);

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	rec->state = PREP;

	/* Reset post_state on every syscall step, before any branch.
	 * generic_sanitise() also clears it, but the minicorpus-replay
	 * path below skips generic_sanitise entirely; without this hoist,
	 * a sanitise-less syscall whose prior post handler did not reach
	 * deferred_freeptr would leave a stale pointer in post_state for
	 * the next syscall's post handler to dereference. */
	rec->post_state = 0;

	/* For syscalls without sanitise callbacks, try replaying a
	 * saved arg set from the mini-corpus. If replay succeeds,
	 * skip generic_sanitise — the args are already populated. */
	if (entry->sanitise == NULL && minicorpus_replay(rec)) {
		rec->rettype = entry->rettype;
		blanket_address_scrub(entry, rec);
		unlock(&rec->lock);
		return;
	}

	generic_sanitise(entry, rec);
	rec->rettype = entry->rettype;
	if (entry->sanitise)
		entry->sanitise(rec);
	blanket_address_scrub(entry, rec);

	unlock(&rec->lock);
}
