#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "arg-len-semantics.h"
#include "args-internal.h"
#include "child.h"
#include "cmp_hints.h"
#include "fd.h"
#include "fstype.h"
#include "kcov.h"
#include "maps.h"
#include "numa.h"
#include "pathnames.h"
#include "prop_ring.h"
#include "random.h"
#include "results.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"		// num_online_cpus
#include "utils.h"		// shared_region_size_for
#include "xattr.h"

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

unsigned long gen_undefined_arg(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec,
				       unsigned int argnum)
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
			if (kcov_shm != NULL) {
				__atomic_fetch_add(&kcov_shm->propagation_injected,
						   1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(&kcov_shm->propagation_injected_callsite[PROP_INJECTED_CALLSITE_ARG_UNDEFINED],
						   1UL, __ATOMIC_RELAXED);
			}
			return val;
		}
	}

	/* CMP-hint shortcut.  ARG_UNDEFINED has no declared contract (it
	 * otherwise takes rand64()), so it opts into the LIVE typed-
	 * hypothesis inject arm with an accept-all range: a kernel-observed
	 * constant strictly beats uniform random for a slot we have no model
	 * for, and there is no bound a derived value could violate.  EXACT
	 * not BOUNDARY -- the gate is unknown, and an equality test is met by
	 * the observed constant itself, which a +/-1 rotation would miss.
	 * The denom helper still lifts the attempt rate from ~1/9 to ~1/4
	 * under CMP_RISING_PC_FLAT; argnum feeds the fill-slot placement
	 * histogram. */
	if (ONE_IN(cmp_hint_inject_denom(9)) &&
	    cmp_hints_try_get_ex(call, rec->do32bit, CMP_HINT_EXACT, 0,
				 true, NULL, argnum,
				 CMP_HINT_CALLSITE_ARG_UNDEFINED, &hint)) {
		credit_cmp_hint_injection(rec, CMP_HINT_CALLSITE_ARG_UNDEFINED);
		return hint;
	}

	switch (rnd_modulo_u32(9)) {
	case 0: return mutate_value(get_boundary_value());
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

unsigned long gen_arg_fd(struct syscallentry *entry,
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

unsigned long gen_arg_typed_fd(struct syscallentry *entry,
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
		__atomic_fetch_add(&shm->stats.arg.wrong_fd_type_substitutions,
				   1UL, __ATOMIC_RELAXED);
		if (ONE_IN(4)) {
			use_generic = true;
			__atomic_fetch_add(&shm->stats.arg.wrong_fd_type_subst_generic,
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

/*
 * ARG_LEN generator.  Default-OFF: gen_arg_len calls get_len() verbatim
 * and draws no extra RNG, so the per-call arg stream is byte-identical
 * to a build without --arg-len-semantics.
 *
 * ON: if the immediately-preceding slot is ARG_ADDRESS / ARG_NON_NULL_
 * ADDRESS, look up the writable extent at that address in the shared-
 * region tracker and draw an object-size-relative boundary length
 * capped by that extent.  The adjacency rule is the op-discriminator:
 * a syscall whose ARG_LEN slot follows a buffer in its signature
 * (read / pread / write / pwrite / send / recv / ...) pairs cleanly;
 * a syscall whose ARG_LEN is in a different position (futex op-
 * multiplexed semantics, ioctl-style scalar) falls through to the
 * size-agnostic get_len() path because the preceding slot is not a
 * buffer.  No companion / no resolvable region size -> same fallback,
 * so the helper never produces a length larger than the writable
 * region (the kernel-WRITES-buffer safety class).
 */
unsigned long gen_arg_len(struct syscallentry *entry,
				 struct syscallrecord *rec,
				 unsigned int argnum)
{
	enum arg_len_semantics_mode mode;
	enum argtype prev_t;
	unsigned long objaddr;
	unsigned long objsize;

	mode = __atomic_load_n(&arg_len_semantics_mode, __ATOMIC_RELAXED);
	if (mode == ARG_LEN_SEMANTICS_OFF)
		return (unsigned long) get_len();

	__atomic_add_fetch(&shm->stats.arg.len_semantics_draws, 1,
			   __ATOMIC_RELAXED);

	if (entry == NULL || rec == NULL || argnum < 2 || argnum > 6)
		goto fallback;

	prev_t = entry->argtype[argnum - 2];
	if (prev_t != ARG_ADDRESS && prev_t != ARG_NON_NULL_ADDRESS)
		goto fallback;

	objaddr = get_argval(rec, argnum - 1);
	if (objaddr == 0)
		goto fallback;

	objsize = shared_region_size_for(objaddr);
	if (objsize == 0)
		goto fallback;

	return get_len_relative(objsize);

fallback:
	__atomic_add_fetch(&shm->stats.arg.len_objrelative_nosize, 1,
			   __ATOMIC_RELAXED);
	return (unsigned long) get_len();
}

unsigned long gen_arg_non_null_address(struct syscallentry *entry __unused__,
					      struct syscallrecord *rec __unused__,
					      unsigned int argnum __unused__)
{
	return (unsigned long) get_non_null_address();
}

unsigned long gen_arg_mmap(struct syscallentry *entry __unused__,
				  struct syscallrecord *rec __unused__,
				  unsigned int argnum __unused__)
{
	return (unsigned long) get_map();
}

unsigned long gen_arg_pid(struct syscallentry *entry __unused__,
				 struct syscallrecord *rec __unused__,
				 unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_pid_from_pool();
}

unsigned long gen_arg_key_serial(struct syscallentry *entry __unused__,
					struct syscallrecord *rec,
					unsigned int argnum __unused__)
{
	/* Typed prop_ring consumer.  Sibling to the gen_undefined_arg /
	 * handle_arg_op untyped consumers, but kind-disciplined: only a
	 * SCALAR_KEY_SERIAL slot (or, with low probability, any slot
	 * via the chaos escape hatch inside prop_ring_try_get_kind)
	 * commits, so the kernel keyring API path gets fed recent
	 * keyring serials trinity actually received instead of either a
	 * raw random or a stale pool draw.  A/B-gated on
	 * prop_ring_typed_arm_b: Arm A skips the pull so the per-call
	 * RNG sequence stays byte-identical to the pre-typing baseline,
	 * Arm B attempts it after first roll-of-eligibility (the per-
	 * call probability gate lives inside prop_ring_try_get_kind so
	 * the existing case mix below stays untouched on an empty or
	 * stale ring). */
	{
		struct childdata *child = this_child();
		unsigned long val;

		if (child != NULL && child->prop_ring_typed_arm_b &&
		    prop_ring_try_get_kind(child, rec, SCALAR_KEY_SERIAL,
					   &val))
			return val;
	}

	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_key_serial();
}

unsigned long gen_arg_timerid(struct syscallentry *entry __unused__,
				     struct syscallrecord *rec,
				     unsigned int argnum __unused__)
{
	/* Typed prop_ring consumer.  Mirrors the SCALAR_SYSV_SEM
	 * exemplar in gen_arg_sem_id: only a SCALAR_TIMER_ID slot (or,
	 * with low probability, any slot via the chaos escape hatch
	 * inside prop_ring_try_get_kind) commits, so
	 * timer_settime/_gettime/_getoverrun/_delete get fed timer ids
	 * timer_create just published instead of either a raw random or
	 * a stale pool draw.  A/B-gated on prop_ring_typed_arm_b: Arm A
	 * skips the pull so the per-call RNG sequence stays
	 * byte-identical to the pre-typing baseline; Arm B attempts it.
	 * The per-call probability gate lives inside
	 * prop_ring_try_get_kind so the case mix below stays untouched
	 * on an empty or stale ring. */
	{
		struct childdata *child = this_child();
		unsigned long val;

		if (child != NULL && child->prop_ring_typed_arm_b &&
		    prop_ring_try_get_kind(child, rec, SCALAR_TIMER_ID,
					   &val))
			return val;
	}

	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_timerid();
}

unsigned long gen_arg_aio_ctx(struct syscallentry *entry __unused__,
				     struct syscallrecord *rec __unused__,
				     unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) rand64();
	return get_random_aio_ctx();
}

unsigned long gen_arg_sem_id(struct syscallentry *entry __unused__,
				    struct syscallrecord *rec,
				    unsigned int argnum __unused__)
{
	/* Typed prop_ring consumer.  Mirrors the SCALAR_KEY_SERIAL
	 * exemplar above: only a SCALAR_SYSV_SEM slot (or, with low
	 * probability, any slot via the chaos escape hatch inside
	 * prop_ring_try_get_kind) commits, so semop / semctl /
	 * semtimedop get fed semids semget just published instead of
	 * either a raw random or a stale pool draw.  A/B-gated on
	 * prop_ring_typed_arm_b: Arm A skips the pull so the per-call
	 * RNG sequence stays byte-identical to the pre-typing baseline;
	 * Arm B attempts it.  The per-call probability gate lives
	 * inside prop_ring_try_get_kind so the case mix below stays
	 * untouched on an empty or stale ring. */
	{
		struct childdata *child = this_child();
		unsigned long val;

		if (child != NULL && child->prop_ring_typed_arm_b &&
		    prop_ring_try_get_kind(child, rec, SCALAR_SYSV_SEM,
					   &val))
			return val;
	}

	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_sem();
}

unsigned long gen_arg_msg_id(struct syscallentry *entry __unused__,
				    struct syscallrecord *rec,
				    unsigned int argnum __unused__)
{
	/* Typed prop_ring consumer.  Mirrors the SCALAR_KEY_SERIAL
	 * exemplar above: only a SCALAR_SYSV_MSG slot (or, with low
	 * probability, any slot via the chaos escape hatch inside
	 * prop_ring_try_get_kind) commits, so msgctl / msgsnd /
	 * msgrcv get fed msqids msgget just published instead of
	 * either a raw random or a stale pool draw.  A/B-gated on
	 * prop_ring_typed_arm_b: Arm A skips the pull so the per-call
	 * RNG sequence stays byte-identical to the pre-typing baseline;
	 * Arm B attempts it.  The per-call probability gate lives
	 * inside prop_ring_try_get_kind so the case mix below stays
	 * untouched on an empty or stale ring. */
	{
		struct childdata *child = this_child();
		unsigned long val;

		if (child != NULL && child->prop_ring_typed_arm_b &&
		    prop_ring_try_get_kind(child, rec, SCALAR_SYSV_MSG,
					   &val))
			return val;
	}

	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_msg();
}

unsigned long gen_arg_sysv_shm(struct syscallentry *entry __unused__,
				      struct syscallrecord *rec,
				      unsigned int argnum __unused__)
{
	/* Typed prop_ring consumer.  Mirrors the SCALAR_KEY_SERIAL
	 * exemplar above: only a SCALAR_SYSV_SHM slot (or, with low
	 * probability, any slot via the chaos escape hatch inside
	 * prop_ring_try_get_kind) commits, so shmat / shmctl get fed
	 * shmids shmget just published instead of either a raw random
	 * or a stale pool draw.  A/B-gated on prop_ring_typed_arm_b:
	 * Arm A skips the pull so the per-call RNG sequence stays
	 * byte-identical to the pre-typing baseline; Arm B attempts
	 * it.  The per-call probability gate lives inside
	 * prop_ring_try_get_kind so the case mix below stays untouched
	 * on an empty or stale ring. */
	{
		struct childdata *child = this_child();
		unsigned long val;

		if (child != NULL && child->prop_ring_typed_arm_b &&
		    prop_ring_try_get_kind(child, rec, SCALAR_SYSV_SHM,
					   &val))
			return val;
	}

	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_shm();
}

unsigned long gen_arg_cpu(struct syscallentry *entry __unused__,
				 struct syscallrecord *rec __unused__,
				 unsigned int argnum __unused__)
{
	return (unsigned long) get_cpu();
}

unsigned long gen_arg_numa_node(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec __unused__,
				       unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (rand32() & 0xFFFF);
	return (unsigned long) random_numa_node();
}

unsigned long gen_arg_pathname(struct syscallentry *entry __unused__,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum __unused__)
{
	return (unsigned long) generate_pathname();
}

/*
 * ARG_XATTR_NAME: a writable pool buffer filled with a namespace-shaped
 * xattr name ("user.foo", "security.selinux", ...).  Wraps the existing
 * pooled name generator so any syscall that takes a `const char __user *
 * name` argument in the xattr family gets resolver-passing names by
 * declaration instead of by remembering to call the bespoke helper.
 *
 * Pool buffer (get_writable_struct) -- no .cleanup, no
 * default_address_scrub: the pool lives off the shared buffer / libc
 * heap so the blanket scrub is a no-op anyway.
 */
unsigned long gen_arg_xattr_name(struct syscallentry *entry __unused__,
					struct syscallrecord *rec __unused__,
					unsigned int argnum __unused__)
{
	char *name;

	name = (char *) get_writable_struct(XATTR_NAME_BUFSZ);
	if (name == NULL)
		return 0;
	memset(name, 0, XATTR_NAME_BUFSZ);
	gen_xattr_name_pooled(name, XATTR_NAME_BUFSZ);
	return (unsigned long) name;
}

/*
 * ARG_FSTYPE_NAME: a writable pool buffer filled with a filesystem-
 * type name ("ext4", "tmpfs", "9p", ...) drawn from the loaded /
 * builtin / autoload / garbage / long / empty mix in
 * gen_fstype_name_pooled().  Random bytes virtually never spell out a
 * registered filesystem name, so the mount(2) / fsopen(2) handler
 * dispatch path stays cold without this pool.  Promote that mix to a
 * first-class argtype so any name slot in the fs-context family gets
 * it by declaration instead of by remembering to call a bespoke
 * helper.
 *
 * Pool buffer (get_writable_struct) -- no .cleanup, no
 * default_address_scrub: the pool lives off the shared buffer / libc
 * heap so the blanket scrub is a no-op anyway.
 */
unsigned long gen_arg_fstype_name(struct syscallentry *entry __unused__,
					 struct syscallrecord *rec __unused__,
					 unsigned int argnum __unused__)
{
	char *name;

	name = (char *) get_writable_struct(FSTYPE_NAME_BUFSZ);
	if (name == NULL)
		return 0;
	memset(name, 0, FSTYPE_NAME_BUFSZ);
	gen_fstype_name_pooled(name, FSTYPE_NAME_BUFSZ);
	return (unsigned long) name;
}
