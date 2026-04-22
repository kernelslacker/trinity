/*
 * EFAULT-probe cache for ioctls whose arg shape can't be inferred
 * from the request number alone.
 *
 * The decoded fast path in ioctl_arg_for_request() handles ioctls
 * defined via the _IO*() macro family — the _IOC_DIR / _IOC_SIZE bits
 * baked into the request tell us pointer-vs-scalar plus the buffer
 * size, and that covers the bulk of trinity's tables.  The remaining
 * surface (legacy raw constants like TCGETS / sockios, plus _IO()-
 * defined ioctls that secretly treat arg as a user pointer) carries no
 * shape information in the request.  For those, learn the shape by
 * actually calling the ioctl with an obviously-bogus arg and watching
 * the errno:
 *
 *   EFAULT                 — kernel tried copy_from_user on arg →
 *                            pointer arg.  ~0UL is well above
 *                            TASK_SIZE_MAX on every supported arch, so
 *                            access_ok() rejects it on the fast path
 *                            and no real fault is taken.
 *   EINVAL/ENOTTY/ENOSYS/0 — kernel treated arg as scalar (or didn't
 *                            recognise the cmd) → scalar arg.
 *   EBADF/ENXIO            — fd doesn't actually back this driver
 *                            after all (the 1-in-100 random-group path
 *                            in sanitise_ioctl pairs an arbitrary fd
 *                            with an unrelated group).  Return
 *                            UNKNOWN so the caller skips caching.
 *   anything else          — inconclusive.  Memoise so we don't keep
 *                            reprobing, but the lookup path treats it
 *                            the same as UNKNOWN — fall through to the
 *                            legacy 50/50 generator.
 *
 * We probe twice with different bogus values.  Only commit to a verdict
 * if both rounds agree; otherwise classify INCONCLUSIVE.  The second
 * value guards against the case where a deferred fault from earlier
 * fuzz activity happens to fold into the first probe and dirty the
 * verdict.
 *
 * The cache is shm-resident.  The kernel's ioctl driver tables are
 * global — a verdict reached by one child applies fleet-wide — so per-
 * child caches would re-pay the side-effecting probe cost on every
 * fork for no benefit.  Open-addressing with linear probe over 4096
 * slots; each slot is one 64-bit atomic encoding both the (group_idx,
 * request) key and the verdict, written lock-free via CAS.  A
 * duplicate insert from a racing child is benign — both children
 * compute the same verdict.
 *
 * Side-effect avoidance: groups whose ioctls allocate kernel state on
 * the dispatch path (before any arg validation) are listed in
 * efault_optout_devs and skip the probe entirely.  The bogus-arg trick
 * still exercises the dispatch path, so a "rejected" probe on those
 * drivers would slowly leak vcpus / vhost rings / vfio containers /
 * loop devices over a long fuzz run.  Default for every other group is
 * probe-enabled; expanding the opt-out list is one string per entry.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "efault_cache.h"
#include "ioctls.h"
#include "shm.h"
#include "utils.h"		/* ARRAY_SIZE */

/*
 * Slot encoding (LSB to MSB):
 *   bits  0..31 — request          (32 bits — the ioctl request number)
 *   bits 32..47 — group_idx        (16 bits — IOCTL_GROUPS_MAX is 48)
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

	for (i = 0; i < IOCTL_EFAULT_CACHE_SIZE; ++i) {
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

	for (i = 0; i < IOCTL_EFAULT_CACHE_SIZE; ++i) {
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
 * in find_ioctl_group().
 */
static const char * const efault_optout_devs[] = {
	"kvm",			/* KVM_CREATE_VCPU/IRQCHIP/PIT allocate state */
	"vhost-net",		/* vhost ring/queue setup before validation */
	"vhost-vsock",
	"vhost-scsi",
	"vhost-vdpa",
	"iommu",		/* iommufd ALLOC ioctls create containers */
	"vfio",			/* vfio group/container setup */
	"loop-control",		/* LOOP_CTL_GET_FREE allocates a loop dev */
};

bool ioctl_efault_probe_allowed(const struct ioctl_group *grp)
{
	size_t i, j;

	if (grp == NULL)
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

static enum ioctl_arg_class probe_one(int fd, unsigned int request,
				      unsigned long bogus)
{
	int err, ret;

	errno = 0;
	ret = ioctl(fd, request, bogus);
	if (ret == 0)
		return IOCTL_ARG_SCALAR;

	err = errno;
	switch (err) {
	case EFAULT:
		return IOCTL_ARG_POINTER;
	case EINVAL:
	case ENOTTY:
	case ENOSYS:
		return IOCTL_ARG_SCALAR;
	case EBADF:
	case ENXIO:
		/* fd doesn't actually back this driver — sentinel that the
		 * caller treats as "don't cache, just defer". */
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

	if (!ioctl_efault_probe_allowed(grp))
		return IOCTL_ARG_UNKNOWN;

	state = run_probe(fd, request);
	cache_store((unsigned int) idx, request, state);
	return state;
}
