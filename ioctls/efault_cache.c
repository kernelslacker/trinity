/*
 * EFAULT-probe cache for ioctls whose request number carries no arg shape
 * (legacy raw constants, _IO() requests taking a pointer): ioctl the fd with a
 * bogus arg, classify by errno, and cache the verdict fleet-wide in shm
 * (classes and capacity: include/efault_cache.h).  Groups whose dispatch path
 * allocates kernel state before validating args are opted out below.
 */

#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>

#include "efault_cache.h"
#include "ioctls.h"
#include "shm.h"
#include "utils.h"		/* ARRAY_SIZE */

/*
 * Slot encoding (LSB to MSB):
 *   bits  0..31 — request          (32 bits — the ioctl request number)
 *   bits 32..47 — group_idx        (16 bits — IOCTL_GROUPS_MAX is 64)
 *   bits 48..55 — state            (8 bits, zero = empty slot)
 *
 * IOCTL_ARG_UNKNOWN (state == 0) is never stored, so packed == 0 is an
 * unambiguous empty-slot sentinel even when request 0 / group_idx 0 are
 * legitimate keys.
 */
#define EFAULT_PACK(g, r, s)	(((uint64_t)(s) << 48) | \
				 ((uint64_t)((g) & 0xffffu) << 32) | \
				 ((uint64_t)((r) & 0xffffffffu)))
#define EFAULT_REQ(p)		((unsigned int)((p) & 0xffffffffu))
#define EFAULT_GRP(p)		((unsigned int)(((p) >> 32) & 0xffffu))
#define EFAULT_STATE(p)		((unsigned char)(((p) >> 48) & 0xffu))

#define EFAULT_CACHE_MASK	(IOCTL_EFAULT_CACHE_SIZE - 1u)

#define EFAULT_PROBE_CAP	64

/*
 * Second bogus arg.  Distinct bit pattern from ~0UL so a transient
 * deferred fault landing on the first probe doesn't propagate into the
 * verdict.  Both values are above TASK_SIZE_MAX on every supported
 * arch, so access_ok() rejects them on the same fast path.
 */
#if __SIZEOF_LONG__ >= 8
# define EFAULT_PROBE_BOGUS_2	0xdeadbeef00000000UL
#else
# define EFAULT_PROBE_BOGUS_2	0xdeadbeefUL
#endif

static unsigned int efault_hash(unsigned int group_idx, unsigned int request)
{
	/*
	 * group_idx changes slowly (~50 distinct values), request changes
	 * fast and clusters by driver (sockios all start 0x89..).  A
	 * multiplicative mix on each component plus a final xorshift gives
	 * an even spread across 4096 slots; the alternative of just
	 * xor-ing low bits of request bunches collisions hard for the
	 * clustered groups.
	 */
	uint32_t h = (uint32_t) group_idx * 2654435761u;
	h ^= request * 2246822519u;
	h ^= h >> 16;
	return h & EFAULT_CACHE_MASK;
}

static enum ioctl_arg_class cache_lookup(unsigned int group_idx,
					 unsigned int request)
{
	unsigned int h = efault_hash(group_idx, request);
	unsigned int i;

	for (i = 0; i < EFAULT_PROBE_CAP; ++i) {
		unsigned int slot = (h + i) & EFAULT_CACHE_MASK;
		uint64_t packed = __atomic_load_n(&shm->ioctl_efault_cache[slot],
						  __ATOMIC_ACQUIRE);
		if (packed == 0)
			return IOCTL_ARG_UNKNOWN;
		if (EFAULT_REQ(packed) == request &&
		    EFAULT_GRP(packed) == group_idx)
			return (enum ioctl_arg_class) EFAULT_STATE(packed);
	}
	return IOCTL_ARG_UNKNOWN;
}

static void cache_store(unsigned int group_idx, unsigned int request,
			enum ioctl_arg_class state)
{
	uint64_t want;
	unsigned int h, i;

	if (state == IOCTL_ARG_UNKNOWN)
		return;

	want = EFAULT_PACK(group_idx, request, (unsigned int) state);
	h = efault_hash(group_idx, request);

	for (i = 0; i < EFAULT_PROBE_CAP; ++i) {
		unsigned int slot = (h + i) & EFAULT_CACHE_MASK;
		uint64_t expected = 0;

		if (__atomic_compare_exchange_n(&shm->ioctl_efault_cache[slot],
						&expected, want, false,
						__ATOMIC_RELEASE,
						__ATOMIC_ACQUIRE))
			return;

		/* Another child filled this slot.  If they were caching the
		 * same key, accept their verdict — the kernel's classification
		 * is global, both children should agree. */
		if (EFAULT_REQ(expected) == request &&
		    EFAULT_GRP(expected) == group_idx)
			return;
	}
	/*
	 * Cache full.  4096 slots is ~10x the registered ioctl count so
	 * this should not happen in practice.  Silently drop — the next
	 * call will simply reprobe.  A stderr warning here would fork-storm
	 * the log.
	 */
}

/*
 * Per-driver opt-outs.  These groups have at least one ioctl that
 * allocates kernel state on the dispatch path before any arg validation
 * happens, so the "kernel rejects ~0UL at access_ok()" trick still
 * leaves residue.  Identified by the /dev names trinity matches against
 * in find_ioctl_group(); a group that fd_test alone claims has none, and
 * sets no_efault_probe.
 */
static const char * const efault_optout_devs[] = {
	"vhost-net",		/* vhost ring/queue setup before validation */
	"vhost-vsock",
	"vhost-scsi",
	"vhost-vdpa",
	"iommu",		/* iommufd ALLOC ioctls create containers */
	"vfio",			/* vfio group/container setup */
	"loop-control",		/* LOOP_CTL_GET_FREE allocates a loop dev */
};

/*
 * Precomputed opt-out verdicts indexed by ioctl_group_index().  Filled
 * in once per group from register_ioctl_group() via
 * ioctl_efault_register_group() so ioctl_efault_classify() doesn't
 * rescan the string lists on every UNKNOWN classification — a hot path
 * for legacy raw-constant ioctls and _IO()-encoded pointer ioctls.
 * BSS-zero default of `false` is safe: a group whose verdict was never
 * recorded just falls through to the legacy 50/50 generator instead of
 * probing, which is the conservative choice for an unregistered key.
 */
static bool efault_probe_allowed_by_group[IOCTL_GROUPS_MAX];

static bool compute_efault_probe_allowed(const struct ioctl_group *grp)
{
	size_t i, j;

	if (grp == NULL || grp->no_efault_probe)
		return false;

	for (i = 0; i < grp->devs_cnt; ++i) {
		if (grp->devs[i] == NULL)
			continue;
		for (j = 0; j < ARRAY_SIZE(efault_optout_devs); ++j) {
			if (strcmp(grp->devs[i], efault_optout_devs[j]) == 0)
				return false;
		}
	}

	return true;
}

void ioctl_efault_register_group(const struct ioctl_group *grp, int group_idx)
{
	efault_probe_allowed_by_group[group_idx] =
		compute_efault_probe_allowed(grp);
}

static enum ioctl_arg_class probe_one(int fd, unsigned int request,
				      unsigned long bogus)
{
	int err, ret;

	errno = 0;
	ret = ioctl(fd, request, bogus);
	if (ret == 0)
		return IOCTL_ARG_SCALAR;

	err = errno;
	/*
	 * EFAULT: the kernel tried copy_from_user() on the arg, so it is a
	 * pointer.  EINVAL/ENOTTY/ENOSYS (or success): it took the arg as a
	 * scalar or did not recognise the cmd.  Anything else is
	 * inconclusive, and memoised like a verdict so the cmd is not
	 * reprobed on every call.
	 */
	switch (err) {
	case EFAULT:
		return IOCTL_ARG_POINTER;
	case EINVAL:
	case ENOTTY:
	case ENOSYS:
		return IOCTL_ARG_SCALAR;
	case EBADF:
	case ENXIO:
		/* fd doesn't actually back this driver (the 1-in-100
		 * random-group path in sanitise_ioctl pairs an arbitrary fd
		 * with an unrelated group) — sentinel that the caller treats
		 * as "don't cache, just defer". */
		return IOCTL_ARG_UNKNOWN;
	default:
		return IOCTL_ARG_INCONCLUSIVE;
	}
}

static enum ioctl_arg_class run_probe(int fd, unsigned int request)
{
	enum ioctl_arg_class a, b;

	a = probe_one(fd, request, ~0UL);
	if (a == IOCTL_ARG_UNKNOWN)
		return IOCTL_ARG_UNKNOWN;

	b = probe_one(fd, request, EFAULT_PROBE_BOGUS_2);
	if (b == IOCTL_ARG_UNKNOWN)
		return IOCTL_ARG_UNKNOWN;

	if (a == b)
		return a;

	/* Disagreement.  Could be a state-dependent handler or noise from
	 * concurrent fuzz traffic; we can't tell, so don't pretend we
	 * know — let the legacy generator try its luck. */
	return IOCTL_ARG_INCONCLUSIVE;
}

enum ioctl_arg_class ioctl_efault_classify(const struct ioctl_group *grp,
					   int fd, unsigned int request)
{
	int idx;
	enum ioctl_arg_class state;

	if (fd < 0)
		return IOCTL_ARG_UNKNOWN;

	idx = ioctl_group_index(grp);
	if (idx < 0)
		return IOCTL_ARG_UNKNOWN;

	state = cache_lookup((unsigned int) idx, request);
	if (state != IOCTL_ARG_UNKNOWN)
		return state;

	if (!efault_probe_allowed_by_group[idx])
		return IOCTL_ARG_UNKNOWN;

	state = run_probe(fd, request);
	cache_store((unsigned int) idx, request, state);
	return state;
}
