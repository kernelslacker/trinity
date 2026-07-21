#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "arg-len-semantics.h"
#include "args-internal.h"
#include "argtype-ops.h"
#include "child.h"
#include "cmp_hints.h"
#include "debug.h"
#include "kcov.h"
#include "maps.h"
#include "net.h"
#include "prop_ring.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"		// min

unsigned long handle_arg_address(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
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

unsigned long handle_arg_range(struct syscallentry *entry,
				      struct syscallrecord *rec,
				      unsigned int argnum)
{
	unsigned long i;
	unsigned long low = entry->arg_params[argnum - 1].range.low;
	unsigned long high = entry->arg_params[argnum - 1].range.hi;
	unsigned long hint;

	if (high == 0) {
		outputerr("%s forgets to set hirange!\n", entry->name);
		BUG("Fix syscall definition!\n");
	}

	if (low >= high) {
		outputerr("%s has invalid range: low(%lu) >= high(%lu)!\n",
			entry->name, low, high);
		BUG("Fix syscall definition!\n");
	}

	/* Low-probability CMP boundary-hint pull, mirroring the ARG_OP /
	 * ARG_LIST gates: occasionally swap the random pick for a kernel-
	 * observed comparison constant rotated through {C-1, C, C+1}.  The
	 * declared [low, high] range is a hard contract for ARG_RANGE
	 * consumers, so a hint that falls outside that interval is rejected
	 * and we fall through to the existing distribution unchanged.  No
	 * hint, an out-of-range hint, or chaos-gate suppression all leave the
	 * historical mix in place.
	 *
	 * Opts into the typed-hypothesis live inject arm: ARG_RANGE is on
	 * the typed-safe consumer set because the declared [low, high]
	 * accept-range pushed into cmp_hints_try_get_ex() catches any
	 * derived value that strays outside the consumer's hard bound, so
	 * the worst case of an out-of-bound derived constant is the same
	 * fall-through as an out-of-bound raw pool constant -- but now
	 * the rejected value also stops bumping the inject-arm denominator
	 * and stash, which previously fired before the callsite's
	 * post-return range check ran. */
	{
		struct cmp_accept_range range = { low, high };

		if (cmp_hint_baseline_should_inject() &&
		    cmp_hints_try_get_ex(rec->nr, rec->do32bit,
					 CMP_HINT_BOUNDARY, 0, true,
					 &range, argnum,
					 CMP_HINT_CALLSITE_ARG_RANGE, &hint)) {
			credit_cmp_hint_injection(rec, CMP_HINT_CALLSITE_ARG_RANGE);
			return hint;
		}
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
unsigned long handle_arg_op(struct syscallentry *entry,
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
	 * dominant rescue class is RRC_CMP_DERIVED, or inside any plateau
	 * window the parent's hypothesis tick has flagged as
	 * CMP_RISING_PC_FLAT.
	 *
	 * CMP_HINT_EXACT, not the default BOUNDARY: command codes are
	 * point-equality slots (ioctl selectors, prctl subops, undocumented
	 * subcommands) whose kernel gate is a straight `switch (cmd)` or
	 * `if (cmd == FOO)`.  The historical {C-1, C, C+1} rotation missed
	 * two out of three draws by construction -- only bare C can satisfy
	 * an equality check.  allow_hyp_inject stays false because ARG_OP
	 * is not on the typed-safe consumer set (broad selector, no
	 * declared range for a derived value to be bounded against). */
	if (cmp_hint_baseline_should_inject() &&
	    cmp_hints_try_get_ex(call, rec->do32bit, CMP_HINT_EXACT, 0,
				 false, NULL, argnum,
				 CMP_HINT_CALLSITE_ARG_OP, &hint)) {
		credit_cmp_hint_injection(rec, CMP_HINT_CALLSITE_ARG_OP);
		return hint;
	}

	/* Constant propagation: with low probability pull a value the kernel
	 * just handed us back from a recent syscall and try it as an ARG_OP
	 * command code.  Sibling channel to the cmp_hints try above (which
	 * surfaces values the kernel compared against); this one surfaces
	 * values trinity received as return.  A/B-gated by prop_ring_argop_
	 * arm_b: Arm A (control) skips the pull so the handle_arg_op RNG
	 * sequence stays byte-identical to the pre-row behaviour, Arm B
	 * attempts the pull.  Probability gate lives inside prop_ring_try_get
	 * so the existing case mix stays untouched; on an empty or stale ring
	 * we just fall through to the regular values[] pick.  Sits AFTER the
	 * cmp_hints try so the cmp_hint baseline A/B path is unaffected. */
	{
		struct childdata *child = this_child();
		unsigned long val;

		if (child != NULL && child->prop_ring_argop_arm_b &&
		    prop_ring_try_get(child, rec, &val)) {
			if (kcov_shm != NULL) {
				__atomic_fetch_add(&kcov_shm->cohorts.prop_ring_argop_arm_b_fires,
						   1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(&kcov_shm->hints_flat.propagation_injected,
						   1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(&kcov_shm->hints_flat.propagation_injected_callsite[PROP_INJECTED_CALLSITE_ARG_OP],
						   1UL, __ATOMIC_RELAXED);
			}
			return val;
		}
	}

	return values[rnd_modulo_u32(num)];
}

/*
 * OR a random number of bits from the list of values into a bitmask, and return it.
 */
unsigned long handle_arg_list(struct syscallentry *entry,
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
	 * dominant rescue class is RRC_CMP_DERIVED, or inside any plateau
	 * window the parent's hypothesis tick has flagged as
	 * CMP_RISING_PC_FLAT.
	 *
	 * Pull CMP_HINT_EXACT to see the raw constant, then decide the mix
	 * from its bit population:
	 *
	 *   popcount(hint) == 1  -- real flag bit.  Build a base mask from
	 *     the declared flag vocabulary and rotate uniformly over
	 *     {mask | hint, mask & ~hint, mask ^ hint}, mirroring the
	 *     CMP_HINT_FLAG_MASK transform in cmp_hints/collect.c so the
	 *     callsite still probes multi-flag combinations (OR adds an
	 *     undocumented bit, AND-NOT probes "must-not-be-set" pairs,
	 *     XOR probes mutual-exclusion pairs).
	 *
	 *   popcount(hint) != 1  -- composite constant, not a flag bit.
	 *     Return it unchanged (CMP_HINT_EXACT semantics): ORing a
	 *     multi-bit constant into a random mask would smear it across
	 *     unrelated flag positions and lose the exact-match signal
	 *     the kernel comparison recorded.
	 *
	 * The pre-fix path routed through CMP_HINT_BOUNDARY and then ORed
	 * the possibly-shifted (C-1 or C+1) value into the mask -- boundary
	 * arithmetic on a flag constant produces garbage adjacent bits with
	 * no relation to any real gate, so those draws were self-inflicted
	 * misses.  allow_hyp_inject stays false: ARG_LIST is a broad
	 * bitmask consumer, not on the typed-safe set. */
	if (cmp_hint_baseline_should_inject() &&
	    cmp_hints_try_get_ex(call, rec->do32bit, CMP_HINT_EXACT, 0,
				 false, NULL, argnum,
				 CMP_HINT_CALLSITE_ARG_LIST, &hint)) {
		credit_cmp_hint_injection(rec, CMP_HINT_CALLSITE_ARG_LIST);
		if (__builtin_popcountl(hint) != 1)
			return hint;
		mask = set_rand_bitmask(num, values);
		switch (rnd_modulo_u32(3)) {
		case 0:  return mask | hint;
		case 1:  return mask & ~hint;
		default: return mask ^ hint;
		}
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
void publish_paired_length(struct syscallentry *entry,
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
 * mirrors the SPLICE_F_* fallback constants in include/kernel/splice.h, so the
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
	 *  40% RAND_RANGE(2, UIO_FASTIOV - 1)
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

unsigned long handle_arg_iovec(struct syscallentry *entry,
				      struct syscallrecord *rec,
				      unsigned int argnum)
{
	return handle_arg_iovec_dir(entry, rec, argnum, IOV_KERNEL_WRITE);
}

unsigned long handle_arg_iovec_in(struct syscallentry *entry,
					 struct syscallrecord *rec,
					 unsigned int argnum)
{
	return handle_arg_iovec_dir(entry, rec, argnum, IOV_KERNEL_READ);
}

unsigned long handle_arg_sockaddr(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	struct sockaddr *sockaddr = NULL;
	socklen_t sockaddrlen = 0;

	generate_sockaddr((struct sockaddr **)&sockaddr, &sockaddrlen, PF_NOHINT);

	publish_paired_length(entry, rec, argnum, sockaddrlen);
	return (unsigned long) sockaddr;
}

unsigned long handle_arg_mode_t(struct syscallentry *entry __unused__,
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
