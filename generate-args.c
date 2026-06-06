#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "arch.h"
#include "argtype-ops.h"
#ifdef USE_BPF
#include "bpf.h"
#endif
#include "cmp_hints.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd.h"
#include "kcov.h"
#include "maps.h"
#include "minicorpus.h"
#include "net.h"
#include "numa.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "strategy.h"	// plateau_rescue_bias_active_for, RRC_CMP_DERIVED
#include "struct_catalog.h"
#include "syscall.h"
#include "syscall_record.h"
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
	i = rnd_modulo_u32(100);

	switch (i) {
	case 0: return -1;
	case 1: return rnd_modulo_u32(4096);
	case 2: return INT_MAX;
	case 3 ... 99:
		return rnd_modulo_u32(num_online_cpus);
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

	switch (rnd_modulo_u32(4)) {
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
		switch (rnd_modulo_u32(4)) {
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
		i = low + (unsigned long) rnd_modulo_u64(high - low + 1);
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
	    cmp_hints_try_get(call, rec->do32bit, &hint)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hints_injected,
					   1UL, __ATOMIC_RELAXED);
		return hint;
	}

	return values[rnd_modulo_u32(num)];
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
		mask |= shift_flag_bit(values[rnd_modulo_u32(num)]);
		return mask;
	}

	/* ~1 in 16: OR in a CMP hint as an undocumented flag bit.
	 * Bumped to ~1 in 4 inside a SR_PLATEAU_FORCE intervention whose
	 * dominant rescue class is RRC_CMP_DERIVED. */
	if (ONE_IN(cmp_hint_inject_denom()) &&
	    cmp_hints_try_get(call, rec->do32bit, &hint)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hints_injected,
					   1UL, __ATOMIC_RELAXED);
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

/*
 * UIO_FASTIOV / UIO_MAXIOV are the kernel-side fast-path and absolute
 * limits on iovec count.  Local fallback to the canonical 8/1024
 * mirrors the SPLICE_F_* pattern at include/compat.h:120-127, so the
 * file builds against any uapi header vintage without pulling in
 * <sys/uio.h> just for the boundary constants.
 */
#ifndef UIO_FASTIOV
# define UIO_FASTIOV 8
#endif
#ifndef UIO_MAXIOV
# define UIO_MAXIOV 1024
#endif

static unsigned long handle_arg_iovec_dir(struct syscallentry *entry,
					  struct syscallrecord *rec,
					  unsigned int argnum,
					  enum iov_direction dir)
{
	unsigned long num_entries;
	unsigned int bucket = rnd_modulo_u32(100);

	/*
	 * Count buckets.  The old 90/10 split between RAND_RANGE(1, 8) and
	 * RAND_RANGE(1, 256) under-exercised the iov_iter boundary
	 * transitions: UIO_FASTIOV (8) is the stack-vs-heap fallback in
	 * import_iovec(), UIO_MAXIOV (1024) is the kernel's hard cap with
	 * EINVAL the one-past arm.  0 is a legal empty-iov call shape and
	 * 1 dominates real workloads.  The remaining picks split mid-range
	 * counts so neither the small-count common path nor the rare
	 * large-count slow path falls out of coverage.
	 *
	 *   5% 0                            (legal zero-length arm)
	 *  25% 1                            (dominant in real code)
	 *  40% RAND_RANGE(2, UIO_FASTIOV)
	 *  10% UIO_FASTIOV                  (stack/heap boundary)
	 *  10% RAND_RANGE(9, 64)
	 *   5% RAND_RANGE(65, UIO_MAXIOV-1)
	 *   3% UIO_MAXIOV                   (kernel cap)
	 *   2% UIO_MAXIOV+1                 (EINVAL reject arm)
	 */
	if (bucket < 5)
		num_entries = 0;
	else if (bucket < 30)
		num_entries = 1;
	else if (bucket < 70)
		num_entries = RAND_RANGE(2, UIO_FASTIOV - 1);
	else if (bucket < 80)
		num_entries = UIO_FASTIOV;
	else if (bucket < 90)
		num_entries = RAND_RANGE(UIO_FASTIOV + 1, 64);
	else if (bucket < 95)
		num_entries = RAND_RANGE(65, UIO_MAXIOV - 1);
	else if (bucket < 98)
		num_entries = UIO_MAXIOV;
	else
		num_entries = UIO_MAXIOV + 1;

	publish_paired_length(entry, rec, argnum, num_entries);
	return (unsigned long) alloc_iovec(num_entries, dir);
}

static unsigned long handle_arg_iovec(struct syscallentry *entry,
				      struct syscallrecord *rec,
				      unsigned int argnum)
{
	return handle_arg_iovec_dir(entry, rec, argnum, IOV_KERNEL_WRITE);
}

static unsigned long handle_arg_iovec_in(struct syscallentry *entry,
					 struct syscallrecord *rec,
					 unsigned int argnum)
{
	return handle_arg_iovec_dir(entry, rec, argnum, IOV_KERNEL_READ);
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

	count = rnd_modulo_u32(9);

	for (i = 0; i < count; i++) {
		unsigned int j;

		j = rnd_modulo_u32(15);
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

	/* Constant propagation: with low probability pull a value the
	 * kernel just handed us back from a recent syscall.  Sibling
	 * channel to cmp_hints (which surfaces values the *kernel*
	 * compared against); this one surfaces values *trinity* received
	 * as return.  Probability gate lives inside prop_ring_try_get so
	 * the existing 9-way switch weights stay untouched; on an empty
	 * or stale ring we just fall through to the regular mix. */
	{
		struct childdata *child = this_child();
		unsigned long val;

		if (child != NULL && prop_ring_try_get(child, rec, &val)) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->propagation_injected,
						   1UL, __ATOMIC_RELAXED);
			return val;
		}
	}

	switch (rnd_modulo_u32(9)) {
	case 0:
		if (cmp_hints_try_get(call, rec->do32bit, &hint)) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->cmp_hints_injected,
						   1UL, __ATOMIC_RELAXED);
			return hint;
		}
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

	/* Prefer live fds returned by recent syscalls (70% of the time).
	 * Filter out fds in the protected-fd registry (kcov PC/cmp fds,
	 * STDERR_FILENO, the stderr capture memfd) -- the live-fd ring is
	 * fed from RET_FD syscall returns, and a kernel fd slot that was
	 * vacated under us (close-then-reopen-to-same-fd recycle, or a
	 * sibling-driven dup2 that we then re-observed) can produce a
	 * value that aliases one of those slots.  Returning it here would
	 * feed it straight into the next close/dup2 sanitiser. */
	if (rnd_modulo_u32(10) < 7) {
		struct childdata *child = this_child();

		if (child != NULL) {
			int live_fd = get_child_live_fd(child);

			if (live_fd >= 0 && !fd_is_protected(live_fd))
				return live_fd;
		}
	}
	if (RAND_BOOL()) {
		unsigned int i;
		/* If this is the 2nd or more ARG_FD, make it unique */
		for (i = 1; i < argnum; i++) {
			enum argtype arg;
			arg = get_argtype(entry, i);
			if (arg == ARG_FD) {
				for (tries = 0; tries < FAILED_FD_REROLL_LIMIT;
				     tries++) {
					fd = get_new_random_fd();
					if (!fd_is_protected(fd))
						return (unsigned long) fd;
				}
				return (unsigned long) fd;
			}
		}
	}

	/* Same failed_fds re-roll bias as the typed-fd path. */
	filter = rnd_modulo_u32(10) < 7;
	for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
		fd = get_random_fd();
		if (fd_is_protected(fd))
			continue;
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
	bool filter = rnd_modulo_u32(10) < 7;
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
			unsigned int pick = rnd_modulo_u32(range);

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
 * Per-field FT_RAW splat: the historical strategy.  Splats a fresh
 * random value into every addressable field of natural width <= 4
 * bytes.  Wider fields (typically pointers and u64 flags) are left at
 * the buffer's initial fill -- a random 8-byte value in a pointer
 * slot just bounces at copy_from_user with -EFAULT and would starve
 * every other field of fuzz coverage.
 */
static void fill_field_raw(unsigned char *buf, const struct struct_field *f)
{
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
		/* leave wider fields at the buffer's initial fill */
		break;
	}
}

/*
 * FT_FLAGS: OR a random subset of the valid-bit mask into the field
 * slot.  Each bit in u.flags.mask is independently included with 50%
 * probability via a single rnd_u64() draw, so the kernel sees a
 * mask-valid value rather than the splat's random byte pattern.  Bits
 * outside the mask are never set, which keeps the call past the
 * kernel's "unknown flags" rejection on the first iteration.
 */
static void fill_field_flags(unsigned char *buf, const struct struct_field *f)
{
	uint64_t val = f->u.flags.mask & rnd_u64();

	switch (f->size) {
	case 1: {
		uint8_t v = (uint8_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 2: {
		uint16_t v = (uint16_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 4: {
		uint32_t v = (uint32_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 8: {
		uint64_t v = val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	default:
		break;
	}
}

/*
 * Write a 1/2/4/8-byte unsigned value into the field slot.  Wider
 * fields are left untouched -- the same conservative shape as
 * fill_field_flags.  Used by the FT_LEN_* and FT_PTR_* implementations
 * to plant length values and pointer values at the right width
 * without per-call-site size dispatch.
 */
static void write_field_uint(unsigned char *buf, const struct struct_field *f,
			     uint64_t val)
{
	switch (f->size) {
	case 1: {
		uint8_t v = (uint8_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 2: {
		uint16_t v = (uint16_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 4: {
		uint32_t v = (uint32_t) val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	case 8: {
		uint64_t v = val;
		memcpy(buf + f->offset, &v, sizeof(v));
		break;
	}
	default:
		break;
	}
}

/*
 * Read a 1/2/4/8-byte unsigned field as a uint64_t.  Wider fields
 * return 0 -- the only callers (the FT_ADDRESS scrub recursion and the
 * FT_PTR_ARRAY count read) only care about pointer- and length-sized
 * slots, which are at most 8 bytes wide.
 */
static uint64_t read_field_uint(const unsigned char *buf,
				const struct struct_field *f)
{
	switch (f->size) {
	case 1:
		return buf[f->offset];
	case 2: {
		uint16_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	case 4: {
		uint32_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	case 8: {
		uint64_t v;
		memcpy(&v, buf + f->offset, sizeof(v));
		return v;
	}
	default:
		return 0;
	}
}

/* Linear name lookup over a struct's field array. */
static int find_field_index_in(const struct struct_field *fields,
			       unsigned int num_fields, const char *name)
{
	unsigned int i;

	if (name == NULL)
		return -1;
	for (i = 0; i < num_fields; i++) {
		if (strcmp(fields[i].name, name) == 0)
			return (int) i;
	}
	return -1;
}

static int find_field_index(const struct struct_desc *desc, const char *name)
{
	return find_field_index_in(desc->fields, desc->num_fields, name);
}

/*
 * Caps and per-iteration bias for the FT_PTR_* family.  Defaults apply
 * when the field's annotation leaves max_bytes / max_count at zero.
 * OPTIONAL_PRESENT_PCT is the bias toward "buffer present" for fields
 * marked .optional = true; the remainder rolls NULL pointer + 0 length
 * so the NULL-args kernel path also gets exercised.
 */
#define PTR_BYTES_DEFAULT_MAX	4096U
#define PTR_ARRAY_DEFAULT_MAX	16U
#define OPTIONAL_PRESENT_PCT	80U
#define STRUCT_FILL_MAX_FIELDS	64U

/* True ~OPTIONAL_PRESENT_PCT% of the time. */
static bool optional_present(void)
{
	return rnd_modulo_u32(100) < OPTIONAL_PRESENT_PCT;
}

/*
 * Random-byte fill into a freshly-allocated sub-buffer.  Used by
 * FT_PTR_BYTES so cmsg-style parsers see varied bytes rather than the
 * zero fill zmalloc hands back.  When null_terminate is set, the last
 * byte is forced to NUL so the kernel's cstring path (strnlen_user,
 * etc.) sees a terminated buffer rather than walking off the end.
 */
static void random_byte_fill(unsigned char *p, unsigned long nbytes,
			     bool null_terminate)
{
	unsigned long j;

	for (j = 0; j < nbytes; j++)
		p[j] = (unsigned char) rnd_u32();
	if (null_terminate && nbytes > 0)
		p[nbytes - 1] = 0;
}

/*
 * Schema-aware field fill: dispatch on f->tag and produce a
 * tag-respecting value, falling back to the FT_RAW per-field random
 * splat for tags this build does not yet specialise.
 *
 * All catalog entries default to FT_RAW; an unannotated struct
 * therefore produces byte-identical output to the pre-schema
 * struct_field_fill -- the rand32() call sequence is preserved
 * field-for-field, width-for-width.  As individual structs migrate
 * to FIELDX() annotations, their fields begin consuming the per-tag
 * mutators below.
 *
 * Three passes resolve the cross-field coupling between PTR and LEN
 * tags without an init-time topological sort:
 *
 *  1. Scalar pass: FT_FLAGS / FT_RAW / reserved tags.  Order-
 *     independent so we can run it first without observing the
 *     pointer fields the later passes will populate.
 *  2. Pointer pass: FT_PTR_BYTES / FT_PTR_ARRAY / FT_PTR_STRUCT.
 *     Allocate a sub-buffer via zmalloc_tracked, write the pointer
 *     into the slot, remember the chosen size (bytes for BYTES /
 *     STRUCT, element count for ARRAY) keyed by field index.
 *     Optional pointers may roll NULL+0 with OPTIONAL_PRESENT_PCT
 *     bias toward present, so the NULL-args kernel path keeps
 *     coverage too.
 *  3. Length pass: FT_LEN_BYTES / FT_LEN_COUNT.  Resolve the paired
 *     buffer field by name, read the size/count chosen in pass 2,
 *     write it into the slot at the LEN field's natural width.
 *     Coupled fields stay consistent -- the kernel sees a length
 *     that matches the buffer it describes.
 */
static void struct_fill_passes(unsigned char *buf, unsigned int size,
			       const struct struct_field *fields,
			       unsigned int n,
			       struct syscallrecord *rec)
{
	unsigned long chosen_len[STRUCT_FILL_MAX_FIELDS] = {0};
	unsigned int i;

	if (n > STRUCT_FILL_MAX_FIELDS)
		n = STRUCT_FILL_MAX_FIELDS;

	/* Pass 1: scalar tags. */
	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];

		if (f->offset + f->size > size)
			continue;

		switch (f->tag) {
		case FT_PTR_BYTES:
		case FT_PTR_ARRAY:
		case FT_PTR_STRUCT:
		case FT_BPF_PROGRAM:
		case FT_LEN_BYTES:
		case FT_LEN_COUNT:
			continue;	/* deferred to later passes */
		case FT_FLAGS:
			fill_field_flags(buf, f);
			break;
		case FT_ADDRESS:
			continue;	/* deferred to pointer pass */
		case FT_FD: {
			/*
			 * Random fd via the generic pool.  Typed-pool draws
			 * (e.g. OBJ_FD_BPF_MAP) are a later lift; today's
			 * fd consumers in the cataloged structs all accept
			 * a generic fd value and the kernel does its own
			 * subtype check.  Sub-int-width FT_FD falls through
			 * to the raw splat since an fd in <4 bytes cannot
			 * round-trip the kernel-side -1 sentinel.
			 */
			int fd;

			if (f->size != sizeof(int)) {
				fill_field_raw(buf, f);
				break;
			}
			fd = get_random_fd();
			write_field_uint(buf, f, (uint64_t)(uint32_t) fd);
			break;
		}
		case FT_ENUM: {
			const unsigned long *vals = f->u.enum_.vals;
			unsigned int nvals = f->u.enum_.n;
			uint64_t v;

			if (vals == NULL || nvals == 0) {
				fill_field_raw(buf, f);
				break;
			}
			v = (uint64_t) vals[rnd_modulo_u32(nvals)];
			write_field_uint(buf, f, v);
			break;
		}
		case FT_VOCAB: {
			const char *const *vocab = f->u.vocab.vocab;
			unsigned int nv = f->u.vocab.vocab_len;
			unsigned int stride = f->u.vocab.element_stride;
			const char *pick;
			size_t plen;

			if (vocab == NULL || nv == 0 || stride == 0) {
				fill_field_raw(buf, f);
				break;
			}
			if (stride > f->size)
				stride = f->size;
			pick = vocab[rnd_modulo_u32(nv)];
			plen = strnlen(pick, stride - 1);
			memset(buf + f->offset, 0, stride);
			memcpy(buf + f->offset, pick, plen);
			break;
		}
		case FT_RANGE: {
			unsigned long lo = f->u.range.lo;
			unsigned long hi = f->u.range.hi;
			uint64_t v;

			if (hi <= lo) {
				fill_field_raw(buf, f);
				break;
			}
			v = lo + (uint64_t) rnd_modulo_u64(hi - lo + 1);
			write_field_uint(buf, f, v);
			break;
		}
		case FT_MAGIC:
		case FT_VERSION_MAGIC:
		case FT_TAGGED_UNION:
		case FT_RAW:
		default:
			fill_field_raw(buf, f);
			break;
		}
	}

	/*
	 * Pre-pin pass: when a LEN field carries a buf_fields[] list
	 * (multi-pair gating, e.g. kprobe_multi's cnt gating
	 * syms+addrs+cookies), roll one shared count and write it into
	 * chosen_len[] for every listed sibling.  Pass 2 then reads
	 * chosen_len[i] for those pointer fields instead of rolling its
	 * own, so all siblings agree on the same count and the LEN
	 * field's value matches every pointer it gates.
	 *
	 * Cap: minimum across the listed siblings' max_count /
	 * max_bytes; absent any cap, the PTR_ARRAY_DEFAULT_MAX default
	 * applies.  All siblings must therefore set a sensible cap or
	 * accept the conservative default.
	 */
	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];
		unsigned long count;
		unsigned int cap = 0;
		unsigned int j;

		if (f->tag != FT_LEN_BYTES && f->tag != FT_LEN_COUNT)
			continue;
		if (f->u.len_of.buf_fields == NULL ||
		    f->u.len_of.n_buf_fields == 0)
			continue;

		for (j = 0; j < f->u.len_of.n_buf_fields; j++) {
			int p = find_field_index_in(fields, n,
						    f->u.len_of.buf_fields[j]);
			unsigned int c = 0;

			if (p < 0 || (unsigned int) p >= n)
				continue;
			if (fields[p].tag == FT_PTR_ARRAY)
				c = fields[p].u.ptr_array.max_count;
			else if (fields[p].tag == FT_PTR_BYTES)
				c = fields[p].u.ptr_bytes.max_bytes;
			if (c == 0)
				continue;
			if (cap == 0 || c < cap)
				cap = c;
		}
		if (cap == 0)
			cap = PTR_ARRAY_DEFAULT_MAX;

		count = 1 + rnd_modulo_u32(cap);
		for (j = 0; j < f->u.len_of.n_buf_fields; j++) {
			int p = find_field_index_in(fields, n,
						    f->u.len_of.buf_fields[j]);
			if (p < 0 || (unsigned int) p >= n)
				continue;
			chosen_len[p] = count;
		}
	}

	/* Pass 2: pointer tags. */
	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];

		if (f->offset + f->size > size)
			continue;

		switch (f->tag) {
		case FT_PTR_BYTES: {
			unsigned int cap = f->u.ptr_bytes.max_bytes;
			unsigned long nbytes;
			void *sub;

			if (cap == 0)
				cap = PTR_BYTES_DEFAULT_MAX;

			if (f->u.ptr_bytes.optional && !optional_present()) {
				write_field_uint(buf, f, 0);
				break;
			}

			/*
			 * chosen_len[i] != 0 here means a multi-pair LEN
			 * field pre-pinned this buffer's size in the
			 * pin-pass below.  Use the shared value rather
			 * than rolling an independent one.
			 */
			if (chosen_len[i] != 0)
				nbytes = chosen_len[i];
			else
				nbytes = 1 + rnd_modulo_u32(cap);
			sub = zmalloc_tracked(nbytes);
			random_byte_fill(sub, nbytes,
					 f->u.ptr_bytes.null_terminated);
			deferred_free_enqueue_or_leak(sub);
			write_field_uint(buf, f, (uint64_t)(uintptr_t) sub);
			chosen_len[i] = nbytes;
			break;
		}

		case FT_PTR_ARRAY: {
			unsigned int cap = f->u.ptr_array.max_count;
			const struct struct_desc *elem;
			unsigned int elem_size = 0;
			unsigned long count, nbytes;
			void *sub;

			if (cap == 0)
				cap = PTR_ARRAY_DEFAULT_MAX;

			/*
			 * elem_struct (cataloged struct, size from
			 * struct_size) takes precedence; elem_size
			 * (scalar byte width, e.g. 8 for a u64 array)
			 * is the fallback when no struct is named.  At
			 * least one must resolve to a non-zero width
			 * for the allocation to proceed.
			 */
			elem = struct_catalog_lookup(f->u.ptr_array.elem_struct);
			if (elem != NULL && elem->struct_size != 0)
				elem_size = elem->struct_size;
			else if (f->u.ptr_array.elem_size != 0)
				elem_size = f->u.ptr_array.elem_size;

			if (elem_size == 0) {
				/*
				 * Neither a cataloged elem_struct nor an
				 * elem_size override: leave NULL.  Paired
				 * LEN field will read chosen_len == 0 and
				 * plant zero, so the (NULL, 0) shape the
				 * kernel sees is internally consistent.
				 */
				write_field_uint(buf, f, 0);
				break;
			}

			if (chosen_len[i] != 0)
				count = chosen_len[i];
			else
				count = 1 + rnd_modulo_u32(cap);
			nbytes = count * elem_size;
			sub = zmalloc_tracked(nbytes);
			deferred_free_enqueue_or_leak(sub);
			write_field_uint(buf, f, (uint64_t)(uintptr_t) sub);
			chosen_len[i] = count;
			break;
		}

		case FT_BPF_PROGRAM: {
#ifdef USE_BPF
			/*
			 * Marker-only tag: allocate a max-tier-sized sub-buffer
			 * and hand it to ebpf_gen_program_into(), which rolls
			 * its own tier (50/25/25 valid/boundary/chaos) and emits
			 * the instruction stream.  prog_type is read from the
			 * sibling "prog_type" field already populated by the
			 * scalar pass; absent or unreadable, default to UNSPEC
			 * so the universal helper set still applies.  chosen_len
			 * carries the generator's actual emit count so the
			 * paired FT_LEN_COUNT writes a matching insn_cnt.
			 */
			const unsigned int max_insns = EBPF_GEN_PROG_MAX_INSNS;
			unsigned int nbytes = max_insns * (unsigned int) sizeof(struct bpf_insn);
			int pt_idx = find_field_index_in(fields, n, "prog_type");
			unsigned int prog_type = 0;
			int out_count = 0;
			void *sub;

			if (pt_idx >= 0 && (unsigned int) pt_idx < n)
				prog_type = (unsigned int)
					read_field_uint(buf, &fields[pt_idx]);

			sub = zmalloc_tracked(nbytes);
			ebpf_gen_program_into(sub, (int) max_insns,
					      &out_count, prog_type);
			deferred_free_enqueue_or_leak(sub);
			write_field_uint(buf, f, (uint64_t)(uintptr_t) sub);
			chosen_len[i] = (unsigned long) out_count;
#else
			write_field_uint(buf, f, 0);
#endif
			break;
		}

		case FT_PTR_STRUCT: {
			const struct struct_desc *target;
			const struct union_variant *tvariant;
			void *sub;

			if (f->u.ptr_struct.optional && !optional_present()) {
				write_field_uint(buf, f, 0);
				break;
			}

			target = struct_catalog_lookup(f->u.ptr_struct.struct_name);
			if (target == NULL || target->struct_size == 0) {
				write_field_uint(buf, f, 0);
				break;
			}

			sub = zmalloc_tracked(target->struct_size);
			struct_field_fill_schema_aware(sub, target->struct_size,
						       target, rec);
			deferred_free_enqueue_or_leak(sub);
			write_field_uint(buf, f, (uint64_t)(uintptr_t) sub);
			/*
			 * Re-resolve the target's variant now that sub is
			 * populated so the paired length field reports the
			 * per-variant ABI size when one is declared (e.g.
			 * sockaddr_un's 110 vs sockaddr_in's 16).  Falls back
			 * to target->struct_size when no variant resolves or
			 * the variant leaves effective_size at zero.
			 */
			tvariant = struct_desc_resolve_variant(target, rec, sub);
			chosen_len[i] = (tvariant != NULL &&
					 tvariant->effective_size != 0)
					? tvariant->effective_size
					: target->struct_size;
			break;
		}

		case FT_ADDRESS: {
			/*
			 * Plant a get_address() pointer and publish the
			 * companion length so any paired FT_LEN_BYTES field
			 * stays internally consistent.  Length defaults to
			 * page_size when no LEN partner exists -- a NULL
			 * address (~1% via get_address) pins length to 0 so
			 * the (NULL, 0) shape stays coherent for the kernel
			 * sees-NULL-iov-skip arm.
			 */
			void *addr;

			if (f->size != sizeof(unsigned long)) {
				/* sub-pointer-width FT_ADDRESS cannot hold a
				 * useful address; fall back to raw splat. */
				fill_field_raw(buf, f);
				break;
			}
			addr = get_address();
			write_field_uint(buf, f, (uint64_t)(uintptr_t) addr);
			chosen_len[i] = addr ? page_size : 0;
			break;
		}

		default:
			break;
		}
	}

	/* Pass 3: length tags. */
	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];
		int paired;

		if (f->offset + f->size > size)
			continue;

		if (f->tag != FT_LEN_BYTES && f->tag != FT_LEN_COUNT)
			continue;

		/*
		 * Multi-pair: every listed sibling shares the same count
		 * (the pin-pass guaranteed this), so reading from the
		 * first resolvable sibling is sufficient.
		 */
		if (f->u.len_of.buf_fields != NULL) {
			unsigned int j;

			paired = -1;
			for (j = 0; j < f->u.len_of.n_buf_fields; j++) {
				paired = find_field_index_in(fields, n,
					f->u.len_of.buf_fields[j]);
				if (paired >= 0 && (unsigned int) paired < n)
					break;
				paired = -1;
			}
		} else {
			paired = find_field_index_in(fields, n,
						     f->u.len_of.buf_field);
		}
		if (paired < 0 || (unsigned int) paired >= n)
			write_field_uint(buf, f, 0);
		else
			write_field_uint(buf, f, chosen_len[paired]);
	}
}

/*
 * Nested sub-variant overlay: when the outer variant carries a
 * nested_variants table, re-read the sub-discriminator from the
 * just-filled buffer, optionally run the shared base pass, then
 * overlay the matched sub-variant.  Depth-1 only -- the resolver
 * rejects nested-of-nested.  Shared head fields (e.g. link_create's
 * target_btf_id) run once before the specific arm overlays its tail;
 * base is itself a union_variant so the field-fill machinery sees a
 * uniform shape, and we ignore its discrim_value and any (forbidden)
 * nested table.
 */
static void struct_variant_overlay_nested(unsigned char *buf, unsigned int size,
					  const struct union_variant *variant,
					  struct syscallrecord *rec)
{
	const struct union_variant *nested;

	if (variant->nested_variants == NULL)
		return;

	nested = struct_desc_resolve_nested_variant(variant, buf, size);
	if (nested == NULL && variant->base == NULL)
		return;

	if (variant->base != NULL)
		struct_fill_passes(buf, size, variant->base->fields,
				   variant->base->num_fields, rec);

	if (nested != NULL)
		struct_fill_passes(buf, size, nested->fields,
				   nested->num_fields, rec);
}

/*
 * Structure-aware post-fill mutation gate.  After
 * struct_field_fill_schema_aware() writes a schema-valid struct into
 * buf, struct_field_mutate_one() rolls this percentage and, on hit,
 * picks one field and applies a tag-respecting neighbour mutation.
 *
 * 12% (~1-in-8) keeps schema-fill's validator-passing intent dominant
 * while still exploring valid neighbours every few calls; tuned next to
 * OPTIONAL_PRESENT_PCT so the two probability-driven fill knobs live
 * side-by-side.
 */
#define STRUCT_FIELD_MUTATE_PCT		12U

/*
 * True for tags the post-fill mutator may touch.  The skip-list (PTR_*,
 * LEN_*, ADDRESS, FD, BPF_PROGRAM, TAGGED_UNION) is enforced at
 * candidate-collection time so a skip-listed field is never picked --
 * the load-bearing safety property for the whole phase.  FT_MAGIC /
 * FT_VERSION_MAGIC are deliberately excluded today; folding them in is
 * a future curated-tag lift once the per-tag counters confirm we want
 * them.  Other future tags default to non-mutable so the skip-list
 * grows by allow-list, not by deny-list.
 */
static bool field_tag_is_mutable_c2b(enum field_tag tag)
{
	switch (tag) {
	case FT_FLAGS:
	case FT_ENUM:
	case FT_VOCAB:
	case FT_RANGE:
	case FT_RAW:
		return true;
	default:
		return false;
	}
}

/*
 * FT_FLAGS post-fill primitive: single-bit flip within the valid-bits
 * mask.  Unlike fill_field_flags()'s whole-mask 50%-each redraw, this
 * walks exactly one bit -- the kernel sees the same value the schema
 * fill produced with one in-mask bit toggled, so a coverage win
 * attributes to that one bit instead of the eight or sixteen the
 * fill's redraw would have churned in parallel.  Bits outside the mask
 * are never touched, preserving the kernel's "unknown flags reject"
 * guarantee.
 */
static void mutate_field_flags(unsigned char *buf, const struct struct_field *f)
{
	uint64_t mask = f->u.flags.mask;
	uint64_t val;
	unsigned int pop, pick, seen;
	unsigned int i;

	if (mask == 0)
		return;

	pop = (unsigned int) __builtin_popcountll(mask);
	pick = (unsigned int) rnd_modulo_u32(pop);

	val = read_field_uint(buf, f);
	seen = 0;
	for (i = 0; i < 64; i++) {
		uint64_t bit = (uint64_t) 1 << i;

		if ((mask & bit) == 0)
			continue;
		if (seen == pick) {
			val ^= bit;
			break;
		}
		seen++;
	}
	write_field_uint(buf, f, val);
}

/*
 * FT_ENUM post-fill primitive: replace with a different draw from
 * u.enum_.vals so the kernel sees a real "swap to another vocab entry"
 * neighbour move instead of either the same value or a wholly random
 * one.  Reject-samples until a different index is drawn; with n == 1
 * there is no different value to swap to, so the field is left alone.
 * A bounded retry cap guards against pathological vocabs that contain
 * the same value repeated (effective n == 1 with formal n > 1) without
 * spinning the rng forever.
 */
static void mutate_field_enum(unsigned char *buf, const struct struct_field *f)
{
	const unsigned long *vals = f->u.enum_.vals;
	unsigned int n = f->u.enum_.n;
	uint64_t current;
	unsigned int retries;

	if (vals == NULL || n <= 1)
		return;

	current = read_field_uint(buf, f);
	for (retries = 0; retries < 8; retries++) {
		uint64_t cand = (uint64_t) vals[rnd_modulo_u32(n)];

		if (cand != current) {
			write_field_uint(buf, f, cand);
			return;
		}
	}
}

/*
 * FT_VOCAB post-fill primitive: pick a different curated string and
 * splat it NUL-padded across element_stride bytes, mirroring exactly
 * the shape fill_field_vocab() lands in pass 1 -- memset(stride, 0),
 * memcpy(min(strlen, stride - 1)).  Reject-sample on the just-filled
 * string so the kernel sees a fresh entry rather than the same one
 * twice; bounded retries handle the n == 1 / duplicate-vocab cases
 * without burning rng.  String comparison is over the stride-bounded
 * pad to match what's actually written into the buffer (anything
 * beyond stride-1 is truncated identically by both writers, so the
 * "different" check would be a false negative if it compared past the
 * truncation point).
 */
static void mutate_field_vocab(unsigned char *buf, const struct struct_field *f)
{
	const char *const *vocab = f->u.vocab.vocab;
	unsigned int nv = f->u.vocab.vocab_len;
	unsigned int stride = f->u.vocab.element_stride;
	unsigned int retries;

	if (vocab == NULL || nv <= 1 || stride == 0)
		return;
	if (stride > f->size)
		stride = f->size;
	if (stride == 0)
		return;

	for (retries = 0; retries < 8; retries++) {
		const char *pick = vocab[rnd_modulo_u32(nv)];
		size_t plen;

		if (memcmp(buf + f->offset, pick,
			   strnlen(pick, stride - 1)) == 0 &&
		    strnlen(pick, stride - 1) ==
			   strnlen((const char *) (buf + f->offset),
				   stride - 1))
			continue;

		plen = strnlen(pick, stride - 1);
		memset(buf + f->offset, 0, stride);
		memcpy(buf + f->offset, pick, plen);
		return;
	}
}

/*
 * FT_RANGE post-fill primitive: step by ±1 within [lo, hi], clamped at
 * the bounds.  The "small adjacent step" is what makes FT_RANGE
 * mutable distinct from the fill's uniform redraw -- the kernel sees a
 * value one neighbour away from a known-valid base, so size-sensitive
 * branches that the schema fill jumps across uniformly get walked one
 * step at a time.  Out-of-range or degenerate ranges (hi <= lo) are
 * no-ops: there is no neighbour to step to.  Saturating at the bounds
 * rather than wrapping preserves the lo/hi invariant the fill writes.
 */
static void mutate_field_range(unsigned char *buf, const struct struct_field *f)
{
	unsigned long lo = f->u.range.lo;
	unsigned long hi = f->u.range.hi;
	uint64_t current;
	uint64_t next;

	if (hi <= lo)
		return;

	current = read_field_uint(buf, f);
	if (current < lo || current > hi)
		return;

	if (current == lo)
		next = current + 1;
	else if (current == hi)
		next = current - 1;
	else if (rnd_u32() & 1)
		next = current + 1;
	else
		next = current - 1;

	write_field_uint(buf, f, next);
}

/*
 * FT_RAW post-fill primitive: single-bit flip scoped to a random byte
 * inside [f->offset, f->offset + f->size).  The "scoped" part is
 * load-bearing -- a stray byte outside the field would clobber its
 * neighbour, which is precisely the sort of cross-field contamination
 * schema fill exists to prevent.  Width-gated to <= 4 bytes (1/2/4) so
 * the splat shape matches fill_field_raw()'s; wider FT_RAW (pointers,
 * u64 cookies) is left alone, the same conservative shape the fill
 * walks past.
 */
static void mutate_field_raw(unsigned char *buf, const struct struct_field *f)
{
	unsigned int byte_off;
	unsigned int bit;

	if (f->size == 0 || f->size > 4)
		return;

	byte_off = rnd_modulo_u32(f->size);
	bit = rnd_modulo_u32(8);
	buf[f->offset + byte_off] ^= (unsigned char) (1U << bit);
}

/*
 * Build a candidate list of mutable fields reachable from buf via the
 * cataloged struct descriptor, walking FT_PTR_STRUCT children up to a
 * fixed depth.  Skip-list discipline lives here: any tag for which
 * field_tag_is_mutable_c2b() returns false (PTR/LEN/FD/ADDRESS/
 * BPF_PROGRAM/TAGGED_UNION as well as the not-yet-mutable future tags)
 * never becomes a candidate, so the picker can't waste a trial on a
 * "selected then bailed" field.
 *
 * Each candidate remembers the buffer it lives in alongside the field
 * pointer -- after the cross-depth weighted pick, the dispatch needs
 * to know which buffer to mutate.  Bounds-checked at each level
 * against that buffer's size for the same reason struct_fill_passes
 * is: a field whose end lies past the local buffer cannot be safely
 * read or written.  Candidate weights default to one when the catalog
 * leaves mutate_weight at zero so the early scaffolding stays
 * pickable.
 */
struct mutate_candidate {
	unsigned char *buf;
	const struct struct_field *field;
	unsigned int weight;
};

/*
 * Depth cap for the recursive walk: parent + two child levels (depths
 * 0, 1, 2).  Each level can in principle contribute STRUCT_FILL_MAX_FIELDS
 * candidates; multiply for the upper bound on the candidate array.
 * Catalog structs today reach at most 2 levels (msghdr -> iovec); the
 * extra slot is a forward-compat safety margin for future deeper
 * nests.  Bounded recursion is also the cyclic-catalog safety net --
 * a future cyclic entry can't trap the collector beyond the cap.
 */
#define STRUCT_MUTATE_DEPTH_CAP		3U
#define STRUCT_MUTATE_MAX_CANDIDATES	(STRUCT_FILL_MAX_FIELDS * \
					 STRUCT_MUTATE_DEPTH_CAP)

/*
 * Test-only lookup override.  Trinity has no separate unit-test
 * binary, so the depth-walk self-test must drive collect_candidates
 * over a sandbox catalog without polluting the real struct_catalog
 * lookup table.  Setting this pointer redirects the FT_PTR_STRUCT
 * child-desc resolution path; cleared after the test so production
 * callers see struct_catalog_lookup unchanged.  Never set outside the
 * self-test.
 */
static const struct struct_desc *(*mutate_struct_lookup_override)(const char *);

static const struct struct_desc *mutate_lookup_desc(const char *name)
{
	if (mutate_struct_lookup_override != NULL)
		return mutate_struct_lookup_override(name);
	return struct_catalog_lookup(name);
}

static unsigned int collect_mutable_candidates(unsigned char *buf,
					       unsigned int size,
					       const struct struct_desc *desc,
					       struct syscallrecord *rec,
					       unsigned int depth,
					       struct mutate_candidate *out,
					       unsigned int out_max)
{
	const struct union_variant *variant;
	const struct struct_field *fields;
	unsigned int n_fields;
	unsigned int collected = 0;
	unsigned int i;

	if (buf == NULL || desc == NULL)
		return 0;
	if (depth >= STRUCT_MUTATE_DEPTH_CAP)
		return 0;

	variant = struct_desc_resolve_variant(desc, rec, buf);
	if (variant != NULL) {
		fields = variant->fields;
		n_fields = variant->num_fields;
	} else {
		fields = desc->fields;
		n_fields = desc->num_fields;
	}
	if (n_fields > STRUCT_FILL_MAX_FIELDS)
		n_fields = STRUCT_FILL_MAX_FIELDS;

	for (i = 0; i < n_fields && collected < out_max; i++) {
		const struct struct_field *f = &fields[i];

		if (f->offset + f->size > size)
			continue;

		if (field_tag_is_mutable_c2b(f->tag)) {
			out[collected].buf = buf;
			out[collected].field = f;
			out[collected].weight =
				f->mutate_weight ? f->mutate_weight : 1U;
			collected++;
			continue;
		}

		/*
		 * Walk FT_PTR_STRUCT children to depth STRUCT_MUTATE_DEPTH_CAP.
		 * NULL child pointer (optional rolled absent at fill time)
		 * has nothing to mutate; uncataloged or zero-sized target
		 * has no schema to walk.  Both skip silently rather than
		 * fail loud -- a depth-walk that aborts on a single
		 * missing leaf would starve every other reachable field.
		 */
		if (f->tag == FT_PTR_STRUCT) {
			const struct struct_desc *child_desc;
			unsigned char *child_buf;

			child_desc = mutate_lookup_desc(f->u.ptr_struct.struct_name);
			if (child_desc == NULL || child_desc->struct_size == 0)
				continue;

			child_buf = (unsigned char *)(uintptr_t)
				read_field_uint(buf, f);
			if (child_buf == NULL)
				continue;

			collected += collect_mutable_candidates(
				child_buf, child_desc->struct_size,
				child_desc, rec, depth + 1,
				out + collected, out_max - collected);
		}
	}
	return collected;
}

/*
 * Weighted pick over the collected candidate set.  Same uniform-falls-
 * out-when-equal-weights behaviour as the other weighted pickers in the
 * codebase; an all-zero weight set is impossible because the collector
 * substitutes 1 for an unset mutate_weight.  Returns a pointer into the
 * caller's candidate array; the (buf, field) pair both come from there.
 */
static const struct mutate_candidate *
weighted_pick_candidate(const struct mutate_candidate *cands, unsigned int n)
{
	unsigned long total = 0;
	unsigned long r, accum;
	unsigned int i;

	for (i = 0; i < n; i++)
		total += cands[i].weight;
	if (total == 0)
		return NULL;

	r = (unsigned long) rnd_modulo_u32((uint32_t) total);
	accum = 0;
	for (i = 0; i < n; i++) {
		accum += cands[i].weight;
		if (r < accum)
			return &cands[i];
	}
	return &cands[n - 1];
}

/*
 * Apply one per-tag primitive to one already-picked field.  Split out
 * from the gated public entry point so the self-test can drive the
 * dispatch deterministically without rolling against
 * STRUCT_FIELD_MUTATE_PCT thousands of times to land enough trials.
 */
static void mutate_dispatch_one(unsigned char *buf,
				const struct struct_field *winner)
{
	switch (winner->tag) {
	case FT_FLAGS:
		mutate_field_flags(buf, winner);
		break;
	case FT_ENUM:
		mutate_field_enum(buf, winner);
		break;
	case FT_VOCAB:
		mutate_field_vocab(buf, winner);
		break;
	case FT_RANGE:
		mutate_field_range(buf, winner);
		break;
	case FT_RAW:
		mutate_field_raw(buf, winner);
		break;
	default:
		/*
		 * Skip-listed and not-yet-mutable tags should never reach
		 * the dispatch -- collect_mutable_candidates filters them
		 * upstream.  A stray dispatch here is a bug in the filter,
		 * not a write to attempt; stay silent.
		 */
		break;
	}
}

/*
 * Variant-resolve at each level, collect mutable candidates across the
 * nested struct chain (depth cap STRUCT_MUTATE_DEPTH_CAP), weight-pick
 * one, dispatch against the winning candidate's buffer (which may be a
 * child sub-buffer reachable via FT_PTR_STRUCT, not the top-level buf).
 * Bumps the per-tag attribution stash before returning so the next
 * minicorpus_mut_attrib_commit folds the trial into the per-tag
 * histogram.  No gate roll -- callers (public entry point +
 * self-test) own the gating decision.  Returns the winning candidate
 * for the self-test's invariant assertions; NULL when no mutable
 * candidate existed across the whole reachable chain.
 */
static const struct mutate_candidate *
mutate_one_unconditional(unsigned char *buf, unsigned int size,
			 const struct struct_desc *desc,
			 struct syscallrecord *rec)
{
	struct mutate_candidate cands[STRUCT_MUTATE_MAX_CANDIDATES];
	const struct mutate_candidate *winner;
	unsigned int n_cands;

	n_cands = collect_mutable_candidates(buf, size, desc, rec, 0,
					     cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n_cands == 0)
		return NULL;

	winner = weighted_pick_candidate(cands, n_cands);
	if (winner == NULL)
		return NULL;

	mutate_dispatch_one(winner->buf, winner->field);
	minicorpus_struct_field_attrib(winner->field->tag);
	return winner;
}

/*
 * Post-fill struct-buffer mutation.  Called immediately after
 * struct_field_fill_schema_aware() at the two top-level ARG_STRUCT
 * call sites; runs at most one tag-respecting neighbour mutation per
 * invocation.  Variant resolution receives the live post-fill buf so
 * buffer-derived discriminators (sockaddr_storage's ss_family,
 * bpf_attr's cmd) scope to the correct variant -- passing NULL would
 * silently mis-scope every tagged-union mutation.
 *
 * One field per call keeps the change atomic so a coverage win
 * attributes to a single (tag, field) pair instead of being smeared
 * across a whole-buffer re-roll.  Depth 1 here -- the recursive
 * candidate collection for FT_PTR_STRUCT children lands in a follow-up
 * commit with the per-tag counter histogram that justifies the wider
 * surface area.
 */
void struct_field_mutate_one(unsigned char *buf, unsigned int size,
			     const struct struct_desc *desc,
			     struct syscallrecord *rec)
{
	if (rnd_modulo_u32(100) >= STRUCT_FIELD_MUTATE_PCT)
		return;
	(void) mutate_one_unconditional(buf, size, desc, rec);
}

/*
 * Self-test for the per-tag primitives and the skip-list discipline.
 *
 * Trinity has no separate unit-test binary -- the harness only runs on
 * an isolated fuzz host, so structural and behavioural invariants
 * shipped with new code have to be asserted at process start instead.
 * Same pattern as shared_bitmap_self_check(): one-shot, called from
 * the parent before any child forks, BUG() on failure so a regression
 * fails the run loudly instead of silently producing wrong outputs.
 *
 * Each primitive is exercised with a hand-built struct_field over a
 * sandbox buffer (i.e. zero coupling to the production catalog) so the
 * assertions don't depend on catalog field choices that may shift.
 * Iteration counts are large enough that reject-sampling primitives
 * (FT_ENUM / FT_VOCAB) get many independent draws; rng coverage of
 * sub-byte cases (FT_RAW bit picks, FT_RANGE direction) is hit by the
 * same loop count without needing a separate sweep.
 */
#define STRUCT_MUTATE_SELFTEST_ITERS	256U

static void selftest_flags(void)
{
	uint64_t mask = 0x0000000000ABCDEFULL;
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_flags",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_FLAGS,
		.mutate_weight	= 1,
		.u.flags	= { .mask = (unsigned long) mask },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = (uint32_t) (rnd_u32() & (uint32_t) mask);
		uint32_t after;
		uint32_t diff;
		uint32_t bits;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_flags(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if ((after & ~(uint32_t) mask) != 0)
			BUG("mutate_field_flags wrote outside mask");

		diff = before ^ after;
		bits = (uint32_t) __builtin_popcount(diff);
		if (bits != 1)
			BUG("mutate_field_flags toggled != 1 bit");
		if ((diff & ~(uint32_t) mask) != 0)
			BUG("mutate_field_flags toggled out-of-mask bit");
	}
}

static void selftest_enum(void)
{
	static const unsigned long vals[] = { 1, 7, 42, 100, 9999 };
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_enum",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_ENUM,
		.mutate_weight	= 1,
		.u.enum_	= { .vals = vals, .n = ARRAY_SIZE(vals) },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = (uint32_t) vals[rnd_modulo_u32(ARRAY_SIZE(vals))];
		uint32_t after;
		unsigned int j;
		bool in_vocab = false;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_enum(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if (after == before)
			BUG("mutate_field_enum failed to swap value");
		for (j = 0; j < ARRAY_SIZE(vals); j++) {
			if ((uint32_t) vals[j] == after) {
				in_vocab = true;
				break;
			}
		}
		if (!in_vocab)
			BUG("mutate_field_enum wrote non-vocab value");
	}
}

static void selftest_vocab(void)
{
	static const char *const vocab[] = { "alpha", "beta", "gamma", "delta" };
	unsigned char field_buf[16];
	struct struct_field f = {
		.name		= "selftest_vocab",
		.offset		= 0,
		.size		= sizeof(field_buf),
		.tag		= FT_VOCAB,
		.mutate_weight	= 1,
		.u.vocab	= {
			.vocab		= vocab,
			.vocab_len	= ARRAY_SIZE(vocab),
			.element_stride	= sizeof(field_buf),
		},
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		const char *start = vocab[rnd_modulo_u32(ARRAY_SIZE(vocab))];
		unsigned int j;
		bool in_vocab = false;

		memset(field_buf, 0, sizeof(field_buf));
		memcpy(field_buf, start, strlen(start));
		mutate_field_vocab(field_buf, &f);

		if (field_buf[sizeof(field_buf) - 1] != 0)
			BUG("mutate_field_vocab dropped trailing NUL");

		for (j = 0; j < ARRAY_SIZE(vocab); j++) {
			if (strcmp((const char *) field_buf, vocab[j]) == 0) {
				in_vocab = true;
				break;
			}
		}
		if (!in_vocab)
			BUG("mutate_field_vocab wrote non-vocab string");
	}
}

static void selftest_range(void)
{
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_range",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_RANGE,
		.mutate_weight	= 1,
		.u.range	= { .lo = 10, .hi = 20 },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = 10 + rnd_modulo_u32(11);
		uint32_t after;
		int32_t delta;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_range(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if (after < 10 || after > 20)
			BUG("mutate_field_range stepped outside [lo, hi]");
		delta = (int32_t) after - (int32_t) before;
		if (delta < -1 || delta > 1 || delta == 0)
			BUG("mutate_field_range step != +/- 1");
	}
}

static void selftest_raw(void)
{
	unsigned char ring[8];
	struct struct_field f = {
		.name		= "selftest_raw",
		.offset		= 2,
		.size		= 4,
		.tag		= FT_RAW,
		.mutate_weight	= 1,
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		unsigned char before[sizeof(ring)];
		unsigned int j;
		unsigned int touched = 0;

		for (j = 0; j < sizeof(ring); j++)
			ring[j] = (unsigned char) rnd_u32();
		memcpy(before, ring, sizeof(ring));

		mutate_field_raw(ring, &f);

		/*
		 * Bytes outside [f->offset, f->offset + f->size) must be
		 * byte-identical -- the field-scope guarantee is the whole
		 * point of FT_RAW's "do not contaminate the neighbour" rule.
		 */
		for (j = 0; j < sizeof(ring); j++) {
			if (j >= f.offset && j < f.offset + f.size)
				continue;
			if (ring[j] != before[j])
				BUG("mutate_field_raw touched out-of-field byte");
		}
		for (j = f.offset; j < f.offset + f.size; j++)
			if (ring[j] != before[j])
				touched++;
		if (touched != 1)
			BUG("mutate_field_raw flipped != 1 byte");
	}
}

/*
 * Skip-list invariant: a struct whose only fields carry skip-listed
 * tags must round-trip byte-identical across many gated invocations
 * of struct_field_mutate_one().  The candidate collector should yield
 * zero candidates and the gated entry point should short-circuit; any
 * regression that promoted a coupled tag (PTR_*, LEN_*, ADDRESS, FD,
 * BPF_PROGRAM) into the candidate set would re-introduce the
 * (ptr, len) / address / fd desync the schema fill exists to prevent.
 *
 * The mutation rate is high enough that 10k * STRUCT_FIELD_MUTATE_PCT
 * gate passes is on the order of 1200 -- a single mistakenly-allowed
 * skip-list candidate would flip a byte with overwhelming probability.
 */
static void selftest_skiplist(void)
{
	unsigned char buf[64];
	unsigned char snapshot[sizeof(buf)];
	struct struct_field skiplist_fields[] = {
		{
			.name		= "ptr",
			.offset		= 0,
			.size		= 8,
			.tag		= FT_PTR_BYTES,
			.mutate_weight	= 100,
			.u.ptr_bytes	= { .max_bytes = 16 },
		},
		{
			.name		= "len",
			.offset		= 8,
			.size		= 4,
			.tag		= FT_LEN_BYTES,
			.mutate_weight	= 100,
			.u.len_of	= { .buf_field = "ptr" },
		},
		{
			.name		= "fd",
			.offset		= 16,
			.size		= 4,
			.tag		= FT_FD,
			.mutate_weight	= 100,
		},
		{
			.name		= "addr",
			.offset		= 24,
			.size		= 8,
			.tag		= FT_ADDRESS,
			.mutate_weight	= 100,
		},
	};
	struct struct_desc desc = {
		.name		= "selftest_skiplist",
		.struct_size	= sizeof(buf),
		.fields		= skiplist_fields,
		.num_fields	= ARRAY_SIZE(skiplist_fields),
	};
	unsigned int i;

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (unsigned char) rnd_u32();
	memcpy(snapshot, buf, sizeof(buf));

	for (i = 0; i < 10000U; i++)
		struct_field_mutate_one(buf, sizeof(buf), &desc, NULL);

	if (memcmp(buf, snapshot, sizeof(buf)) != 0)
		BUG("struct_field_mutate_one mutated a skip-listed field");
}

/*
 * Variant-scope invariant: when the resolved desc carries variants
 * keyed off a buffer-derived discriminator, collect_mutable_candidates
 * must only emit fields from the resolved variant -- never the parent's
 * shared field list, never sibling variants.  A regression that
 * forgot to resolve the variant (passing NULL buf, or skipping the
 * resolver entirely) would silently splatter mutations across the
 * dead union envelope.
 *
 * Builds a sandbox tagged-union desc with two variants keyed on byte
 * zero (1 -> "alpha" variant, 2 -> "beta" variant); flips the
 * discriminator and asserts the candidate set names the matching
 * field exclusively.
 */
static void selftest_variant_scope(void)
{
	static const struct struct_field alpha_fields[] = {
		{
			.name		= "alpha",
			.offset		= 4,
			.size		= 4,
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	};
	static const struct struct_field beta_fields[] = {
		{
			.name		= "beta",
			.offset		= 4,
			.size		= 4,
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	};
	static const struct union_variant variants[] = {
		{
			.discrim_value	= 1,
			.name		= "alpha_v",
			.fields		= alpha_fields,
			.num_fields	= ARRAY_SIZE(alpha_fields),
		},
		{
			.discrim_value	= 2,
			.name		= "beta_v",
			.fields		= beta_fields,
			.num_fields	= ARRAY_SIZE(beta_fields),
		},
	};
	struct struct_desc desc = {
		.name			= "selftest_variant",
		.struct_size		= 16,
		.variants		= variants,
		.num_variants		= ARRAY_SIZE(variants),
		.buffer_discrim_offset	= 0,
		.buffer_discrim_size	= 1,
	};
	struct mutate_candidate cands[STRUCT_MUTATE_MAX_CANDIDATES];
	unsigned char buf[16];
	unsigned int n;

	memset(buf, 0, sizeof(buf));
	buf[0] = 1;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 1 || strcmp(cands[0].field->name, "alpha") != 0)
		BUG("variant scope failed for alpha discriminator");

	buf[0] = 2;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 1 || strcmp(cands[0].field->name, "beta") != 0)
		BUG("variant scope failed for beta discriminator");

	/*
	 * Unknown discriminator: no variant resolves, the collector
	 * falls back to desc->fields[] -- which is empty here -- so
	 * the candidate set must be zero.  Catches a regression that
	 * leaked sibling variant fields into the no-match arm.
	 */
	buf[0] = 99;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 0)
		BUG("variant no-match leaked candidates");
}

/*
 * Depth-cap invariant: the recursive walk reaches the parent and its
 * first two FT_PTR_STRUCT descendants (depths 0, 1, 2) and stops
 * before depth 3.  Catches a regression that lifted or removed the
 * cap (unbounded recursion) or applied it off-by-one (only depths
 * 0/1 contribute).
 *
 * Builds a 4-deep sandbox chain via the mutate_struct_lookup_override
 * hook so the test desc resolves without polluting the production
 * struct_catalog.  Each level has one FT_FLAGS leaf; a working depth
 * cap of 3 yields exactly 3 candidates.
 */
struct selftest_depth_chain {
	unsigned char *next;
	uint32_t       leaf;
} __attribute__((packed));

static const struct struct_field selftest_depth_fields[4][2] = {
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_1" },
		},
		{
			.name		= "leaf0",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_2" },
		},
		{
			.name		= "leaf1",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_3" },
		},
		{
			.name		= "leaf2",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_unreached" },
		},
		{
			.name		= "leaf3",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
};

static const struct struct_desc selftest_depth_descs[4] = {
	{
		.name		= "selftest_depth_0",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[0],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_1",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[1],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_2",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[2],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_3",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[3],
		.num_fields	= 2,
	},
};

static const struct struct_desc *selftest_depth_lookup(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(selftest_depth_descs); i++)
		if (strcmp(selftest_depth_descs[i].name, name) == 0)
			return &selftest_depth_descs[i];
	return NULL;
}

static void selftest_depth_cap(void)
{
	struct selftest_depth_chain chain[4];
	struct mutate_candidate cands[STRUCT_MUTATE_MAX_CANDIDATES];
	unsigned int n;
	unsigned int i;
	unsigned int leaf_seen = 0;

	memset(chain, 0, sizeof(chain));
	chain[0].next = (unsigned char *) &chain[1];
	chain[1].next = (unsigned char *) &chain[2];
	chain[2].next = (unsigned char *) &chain[3];
	chain[3].next = NULL;
	for (i = 0; i < 4; i++)
		chain[i].leaf = 0;

	mutate_struct_lookup_override = selftest_depth_lookup;
	n = collect_mutable_candidates((unsigned char *) &chain[0],
				       sizeof(chain[0]),
				       &selftest_depth_descs[0], NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	mutate_struct_lookup_override = NULL;

	if (n != 3)
		BUG("depth-walk did not contribute exactly 3 candidates");

	for (i = 0; i < n; i++) {
		if (strncmp(cands[i].field->name, "leaf", 4) != 0)
			BUG("depth-walk emitted a non-leaf candidate");
		/*
		 * leaf3 lives in chain[3], which is depth 3 -- past the
		 * cap.  Its name must never appear in the candidate set.
		 */
		if (strcmp(cands[i].field->name, "leaf3") == 0)
			BUG("depth-walk reached depth-3 field");
		leaf_seen |= 1U << (cands[i].field->name[4] - '0');
	}
	/* leaf0 (bit 0), leaf1 (bit 1), leaf2 (bit 2) all present. */
	if (leaf_seen != 0x7U)
		BUG("depth-walk did not visit all three reachable leaves");
}

void struct_field_mutate_self_check(void)
{
	selftest_flags();
	selftest_enum();
	selftest_vocab();
	selftest_range();
	selftest_raw();
	selftest_skiplist();
	selftest_variant_scope();
	selftest_depth_cap();
}

void struct_field_fill_schema_aware(unsigned char *buf, unsigned int size,
				    const struct struct_desc *desc,
				    struct syscallrecord *rec)
{
	const struct union_variant *variant;

	/*
	 * Arg-derived discriminator resolves up-front from rec; nested
	 * FT_PTR_STRUCT calls thread rec through so a child struct under
	 * a tagged-union parent reads the same syscall args.  Buffer-
	 * derived discriminators can't resolve here -- the buffer is empty
	 * -- so the shared desc->fields[] head pass runs first and writes
	 * the discriminator (e.g. sockaddr_storage's ss_family).  The
	 * per-AF variant fill then runs on the now-populated buffer.
	 */
	variant = struct_desc_resolve_variant(desc, rec, NULL);
	if (variant != NULL) {
		struct_fill_passes(buf, size, variant->fields,
				   variant->num_fields, rec);
		struct_variant_overlay_nested(buf, size, variant, rec);
		return;
	}

	struct_fill_passes(buf, size, desc->fields, desc->num_fields, rec);

	if (desc->buffer_discrim_size == 0)
		return;

	variant = struct_desc_resolve_variant(desc, rec, buf);
	if (variant != NULL) {
		struct_fill_passes(buf, size, variant->fields,
				   variant->num_fields, rec);
		struct_variant_overlay_nested(buf, size, variant, rec);
	}
}

/*
 * ARG_STRUCT_PTR_IN: hand the kernel a heap-allocated buffer sized for
 * the cataloged struct at this (syscall, arg), then per-field
 * schema-aware fill via struct_field_fill_schema_aware().  For
 * unannotated structs every field is FT_RAW and the output matches
 * the historical per-field random splat byte-for-byte.
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

	buf = zmalloc_tracked(size);

	if (desc != NULL) {
		struct_field_fill_schema_aware(buf, size, desc, rec);
		struct_field_mutate_one(buf, size, desc, rec);
	}

	deferred_free_enqueue_or_leak(buf);
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

	buf = zmalloc_tracked(size);
	memset(buf, STRUCT_PTR_OUT_POISON_BYTE, size);

	deferred_free_enqueue_or_leak(buf);
	return (unsigned long) buf;
}

/*
 * ARG_STRUCT_PTR_INOUT: ioctl-shaped slots where the kernel reads input
 * fields off the buffer and then writes output bytes back to it.  The
 * input half needs the same schema-aware fill as ARG_STRUCT_PTR_IN
 * -- a poison-filled buffer makes every input field look like 0xAAAA...
 * and the kernel rejects the call before it ever exercises the output
 * path.  Field-fill via struct_field_fill_schema_aware(), then hand
 * the buffer over; the kernel's writes land on whatever fields it
 * chooses to overwrite.
 *
 * Catalog miss: fall back to STRUCT_PTR_IN_FALLBACK_SIZE bytes of zeros,
 * same as the IN path -- zeros are a valid input shape for most
 * extensible structs (size-word-first ABIs treat zero as "minimum
 * version") and keep the kernel past its first copy_from_user() bounds
 * check.
 *
 * Output-side validation (canary on the written-back bytes, so a post
 * handler can tell touched-bytes from untouched-bytes) is deliberately
 * out of scope here -- it needs the catalog to learn the input shape
 * first, and conflating the two changes makes the per-field splat
 * unreviewable.  This commit's only job is to stop sending all-0xAA as
 * INOUT input.
 *
 * Deferred-free / sanitise-overwrite handling matches the IN path.
 */
static unsigned long gen_arg_struct_ptr_inout(struct syscallentry *entry __unused__,
					      struct syscallrecord *rec,
					      unsigned int argnum)
{
	const struct struct_desc *desc;
	unsigned int size;
	unsigned char *buf;

	desc = struct_arg_lookup(rec->nr, argnum, rec->do32bit);
	size = desc ? desc->struct_size : STRUCT_PTR_IN_FALLBACK_SIZE;

	buf = zmalloc_tracked(size);

	if (desc != NULL) {
		struct_field_fill_schema_aware(buf, size, desc, rec);
		struct_field_mutate_one(buf, size, desc, rec);
	}

	deferred_free_enqueue_or_leak(buf);
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

		if (t == ARG_STRUCT_PTR_IN || t == ARG_STRUCT_PTR_OUT ||
		    t == ARG_STRUCT_PTR_INOUT)
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

	if (ONE_IN(10) && cmp_hints_try_get(rec->nr, rec->do32bit, &hint)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hints_injected,
					   1UL, __ATOMIC_RELAXED);
		return hint;
	}

	desc = paired_struct_desc(entry, rec);
	if (desc == NULL)
		return (unsigned long) rnd_modulo_u32(ARG_STRUCT_SIZE_FALLBACK_CAP);

	roll = rnd_modulo_u32(10);

	/* 50%: exact current sizeof() */
	if (roll < 5)
		return desc->struct_size;

	/* 20%: known older-ABI size, else exact sizeof() */
	if (roll < 7) {
		oa = lookup_old_abi(desc->name);
		if (oa != NULL)
			return oa->sizes[rnd_modulo_u32(oa->num_sizes)];
		return desc->struct_size;
	}

	/* 10%: sizeof +/- 1 boundary */
	if (roll < 8) {
		if (RAND_BOOL())
			return desc->struct_size + 1;
		return desc->struct_size > 0 ? desc->struct_size - 1 : 0;
	}

	/* 20% remaining: structural-rejection stress */
	switch (rnd_modulo_u32(6)) {
	case 0: return 0;
	case 1: return 1 + rnd_modulo_u32(16);
	case 2: return UINT_MAX;
	case 3: return INT_MAX;
	case 4: return ((unsigned long) rand32()) << 16;
	default: return ULONG_MAX;
	}
}

/*
 * Shared cleanup helper for any argtype whose generator hands back a
 * heap allocation that must be released after the syscall returns
 * (ARG_PATHNAME, ARG_SOCKADDR).
 */
static void cleanup_deferred_free(struct syscallrecord *rec, unsigned int argnum)
{
	deferred_free_enqueue((void *) get_argval(rec, argnum));
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
		.paired_length = ARG_IOVECLEN,
	},
	[ARG_IOVEC_IN] = {
		.name = "ARG_IOVEC_IN",
		.generate = handle_arg_iovec_in,
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
	[ARG_STRUCT_PTR_INOUT] = {
		.name = "ARG_STRUCT_PTR_INOUT",
		.generate = gen_arg_struct_ptr_inout,
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
 * Bit k set means slot (k+1)'s argtype is ARG_STRUCT_PTR_IN/OUT/INOUT
 * AND the cataloged struct for that (syscall, arg) reaches an
 * FT_ADDRESS field via the pointer chain.  Resolved once at table-init
 * time so the per-dispatch nested_address_scrub() walk short-circuits
 * with a single masked load on the bulk of syscalls (no cataloged
 * struct, or no address-shaped field inside it).
 */
uint8_t compute_nested_address_scrub_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL || entry->name == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		enum argtype t = entry->argtype[i];
		const struct struct_desc *desc;

		if (t != ARG_STRUCT_PTR_IN &&
		    t != ARG_STRUCT_PTR_OUT &&
		    t != ARG_STRUCT_PTR_INOUT)
			continue;

		desc = struct_arg_lookup_by_name(entry->name, i + 1);
		if (desc != NULL && struct_desc_has_address_field(desc))
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
 * avoid_shared_buffer_out() or miss specific slots. Length default is
 * page_size (conservative; bare ARG_ADDRESS carries no length info
 * and walking adjacent slots per dispatch is too expensive). */

/*
 * Bounded recursion depth for the nested-address walker.  Real
 * cataloged structs are flat or one level deep (msghdr -> iovec); the
 * cap mirrors STRUCT_ADDRESS_SCAN_MAX_DEPTH in struct_catalog.c so a
 * future cyclic catalog entry cannot drive infinite recursion at
 * dispatch time.
 */
#define NESTED_ADDRESS_SCRUB_MAX_DEPTH	4

static void scrub_struct_addresses(unsigned char *buf, unsigned int size,
				   const struct struct_desc *desc,
				   unsigned int depth);

/*
 * Walk one cataloged-struct buffer and scrub every FT_ADDRESS field,
 * recursing into FT_PTR_STRUCT targets and FT_PTR_ARRAY elements whose
 * element struct is itself cataloged.  FT_PTR_BYTES and the FT_PTR_*
 * pointers themselves are trinity-allocated via zmalloc_tracked() and
 * cannot alias shared_regions[] or the libc brk arena; they are not
 * scrub targets, only recursion edges.
 */
static void scrub_struct_addresses(unsigned char *buf, unsigned int size,
				   const struct struct_desc *desc,
				   unsigned int depth)
{
	unsigned int i;

	if (buf == NULL || desc == NULL ||
	    depth >= NESTED_ADDRESS_SCRUB_MAX_DEPTH)
		return;

	/*
	 * Range-gate the whole walk before touching @buf.  At depth 0
	 * @buf is the caller-supplied syscall slot (rec->aN); at depth
	 * >= 1 it is a pointer value read out of a parent struct.  Both
	 * are the exact class of value a sibling scribble can replace
	 * with garbage between sanitise and dispatch -- defending
	 * against which is the entire reason the scrub exists.  The
	 * field walk below dereferences @buf in two ways that fault on
	 * a stale pointer with no recovery: read_field_uint() does a
	 * memcpy out of buf+offset, and avoid_shared_buffer_out() ->
	 * asb_relocate() reads *addr at the top of its body (the
	 * asb_copy_active sigsetjmp guard covers only the inner
	 * memcpy, not this outer deref).  The per-field bound check
	 * (f->offset + f->size > size) only constrains the walk within
	 * an assumed-valid @size-byte allocation; it does nothing when
	 * @buf itself is unmapped.
	 *
	 * range_readable_user() proves @buf is mapped from cached
	 * state (tracked shared regions + libc heap snapshot) -- a
	 * pure in-process lookup, no deref, cannot fault.  Legit
	 * zmalloc_tracked() targets live in the heap snapshot and
	 * pass; scribbled garbage that aliases neither snapshot fails.
	 * Skip-the-scrub on false is safe: the scrub is purely
	 * defensive, the fuzzed syscall has not yet fired, and falling
	 * through means the kernel sees the pre-scrub argument -- the
	 * exact gap the scrub narrows, not a regression.
	 */
	if (!range_readable_user(buf, size))
		return;

	for (i = 0; i < desc->num_fields; i++) {
		const struct struct_field *f = &desc->fields[i];
		const struct struct_desc *target;
		unsigned long ptr;

		if (f->offset + f->size > size)
			continue;

		switch (f->tag) {
		case FT_ADDRESS: {
			/*
			 * Scrub at the field's natural pointer width.
			 * Sub-pointer-sized FT_ADDRESS fields cannot hold a
			 * useful address; skip them rather than scribble
			 * adjacent bytes.
			 */
			if (f->size != sizeof(unsigned long))
				break;
			avoid_shared_buffer_out(
				(unsigned long *)(buf + f->offset), page_size);
			break;
		}
		case FT_PTR_STRUCT:
			ptr = (unsigned long) read_field_uint(buf, f);
			if (ptr == 0)
				break;
			target = struct_catalog_lookup(f->u.ptr_struct.struct_name);
			if (target == NULL || target->struct_size == 0)
				break;
			scrub_struct_addresses((unsigned char *) ptr,
					       target->struct_size,
					       target, depth + 1);
			break;
		case FT_PTR_ARRAY: {
			unsigned long count = 0;
			unsigned long cap;
			int paired;
			unsigned long j;

			ptr = (unsigned long) read_field_uint(buf, f);
			if (ptr == 0)
				break;
			target = struct_catalog_lookup(f->u.ptr_array.elem_struct);
			if (target == NULL || target->struct_size == 0)
				break;

			paired = find_field_index(desc, f->u.ptr_array.len_field);
			if (paired >= 0)
				count = (unsigned long) read_field_uint(
					buf, &desc->fields[paired]);

			/*
			 * Cap the iteration at the catalog's declared
			 * max_count (or PTR_ARRAY_DEFAULT_MAX) so a sibling-
			 * scribbled len field cannot drive a walk past the
			 * allocation's tail and SEGV the sanitiser.
			 */
			cap = f->u.ptr_array.max_count;
			if (cap == 0)
				cap = PTR_ARRAY_DEFAULT_MAX;
			if (count > cap)
				count = cap;

			for (j = 0; j < count; j++) {
				unsigned char *elem = (unsigned char *) ptr
					+ j * target->struct_size;

				scrub_struct_addresses(elem,
						       target->struct_size,
						       target, depth + 1);
			}
			break;
		}
		default:
			break;
		}
	}
}

static void nested_address_scrub(struct syscallentry *entry,
				 struct syscallrecord *rec)
{
	uint8_t mask = entry->nested_address_scrub_mask;

	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		const struct struct_desc *desc;
		unsigned long slot;

		switch (i) {
		case 1: slot = rec->a1; break;
		case 2: slot = rec->a2; break;
		case 3: slot = rec->a3; break;
		case 4: slot = rec->a4; break;
		case 5: slot = rec->a5; break;
		case 6: slot = rec->a6; break;
		default: slot = 0; break;
		}

		desc = struct_arg_lookup(rec->nr, i, rec->do32bit);
		if (slot != 0 && desc != NULL)
			scrub_struct_addresses((unsigned char *) slot,
					       desc->struct_size, desc, 0);
		mask &= (uint8_t)(mask - 1);
	}
}

void blanket_address_scrub(struct syscallentry *entry, struct syscallrecord *rec)
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
			avoid_shared_buffer_out(slot, page_size);
		mask &= (uint8_t)(mask - 1);
	}

	nested_address_scrub(entry, rec);
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
	uint8_t mask;

	BUG_ON(entry == NULL);

	/* Most syscalls own no freeable resources in any slot; the cached
	 * cleanup_arg_mask lets us skip the per-arg argtype_get_ops() walk
	 * outright in that common case. */
	mask = entry->cleanup_arg_mask;
	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		enum argtype t = get_argtype(entry, i);
		const struct argtype_ops *ops = argtype_get_ops(t);

		deferred_free_set_cleanup_argtype(t);
		ops->cleanup(rec, i);
		deferred_free_set_cleanup_argtype(ARG_UNDEFINED);
		mask &= (uint8_t)(mask - 1);
	}
}

void generate_syscall_args(struct syscallrecord *rec)
{
	struct syscallentry *entry;

	srec_publish_begin(rec);

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry == NULL) {
		srec_publish_end(rec);
		return;
	}
	__atomic_store_n(&rec->state, PREP, __ATOMIC_RELAXED);

	/* Reset post_state on every syscall step, before any branch.
	 * generic_sanitise() also clears it, but the minicorpus-replay
	 * path below skips generic_sanitise entirely; without this hoist,
	 * a sanitise-less syscall whose prior post handler did not reach
	 * deferred_freeptr would leave a stale pointer in post_state for
	 * the next syscall's post handler to dereference. */
	rec->post_state = 0;
	/* Same hoist for arg_snapshot_mask: defaults to "nothing shadowed"
	 * so get_arg_snapshot() in any unrelated handler that somehow gets
	 * called against this rec (e.g. an early validate_arg_coupling
	 * rejection in __do_syscall before the dispatch-time snapshot
	 * runs) sees the live slot instead of a stale shadow from a
	 * previous dispatch.  The real snapshot is taken in __do_syscall
	 * after the second blanket_address_scrub, from the local a1..a6
	 * values that are actually passed to the kernel. */
	rec->arg_snapshot_mask = 0;

	/* For syscalls without sanitise callbacks, try replaying a
	 * saved arg set from the mini-corpus. If replay succeeds,
	 * skip generic_sanitise — the args are already populated. */
	if (entry->sanitise == NULL && minicorpus_replay(rec)) {
		rec->rettype = entry->rettype;
		blanket_address_scrub(entry, rec);
		srec_publish_end(rec);
		return;
	}

	generic_sanitise(entry, rec);
	rec->rettype = entry->rettype;
	if (entry->sanitise)
		entry->sanitise(rec);
	blanket_address_scrub(entry, rec);

	srec_publish_end(rec);
}
