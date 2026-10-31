/*
 * The arg an ioctl request takes: the three tiers ioctl_arg_for_request()
 * picks from (the request's own size, the EFAULT probe's verdict, a coin
 * flip), and the random arg pick_random_ioctl() also gives a4 to a6.
 */

#include <linux/ioctl.h>

#include "arch.h"		/* page_size */
#include "efault_cache.h"
#include "ioctls.h"
#include "random.h"
#include "sanitise.h"

unsigned long random_ioctl_arg(void)
{
	if (RAND_BOOL()) {
		return (unsigned long) rand64();
	} else {
		void *page;

		page = get_writable_address(page_size);
		if (page == NULL)
			return (unsigned long) rand64();
		generate_random_page(page);

		return (unsigned long) page;
	}
}

/*
 * Pick an arg shape for the given ioctl request, in three tiers.
 *
 *   Tier 1 — decoded path.  Ioctls defined via _IO*() with a non-zero
 *     _IOC_TYPE and non-NONE _IOC_DIR carry their arg size in the
 *     request number.  Trust it: hand the kernel a properly-sized
 *     buffer, seeded with random bytes for the _IOW / _IOWR families.
 *     Covers the bulk of V4L2, btrfs, binder, DRM, vhost, ...
 *
 *   Tier 2 — EFAULT-probe cache.  Legacy raw-constant ioctls
 *     (TCGETS-style 0x5401, sockios) and _IO()-encoded ioctls that
 *     secretly take a pointer carry no shape information in the
 *     request.  Probe at runtime by calling with a bogus arg and
 *     watching errno; cache the verdict per (group, request) in shm
 *     so every other child reuses it.  See efault_cache.c.
 *
 *   Tier 3 — legacy 50/50.  When the probe is opted out (vhost,
 *     vfio, iommufd, loop-control all allocate kernel state on
 *     dispatch), inconclusive, or transiently failed (EBADF on a
 *     mismatched fd), fall back to the historical coin flip between
 *     a random scalar and a writable page.
 */
unsigned long ioctl_arg_for_request(const struct ioctl_group *grp, int fd,
				    unsigned int request)
{
	unsigned int dir, size;
	void *buf;
	enum ioctl_arg_class cls;

	/* Tier 1. */
	if (_IOC_TYPE(request) != 0) {
		dir = _IOC_DIR(request);
		if (dir != _IOC_NONE) {
			size = _IOC_SIZE(request);
			/*
			 * _IOC_SIZE == 0 with a _IOC_WRITE / _IOC_READ
			 * direction is legitimate for ioctls that predate
			 * the size-encoding convention: the arg is a raw
			 * scalar in the register, not a pointer to a
			 * buffer.  Handing the kernel a page-sized random
			 * blob dereferences an interior "pointer" from
			 * garbage and produces EFAULT storms that block
			 * deep-path coverage.  Fall through to Tier 2 and
			 * let the EFAULT probe classify the shape.
			 */
			if (size != 0) {
				if (size > page_size)
					size = page_size;

				buf = get_writable_address(size);
				if (buf == NULL)
					return random_ioctl_arg();

				/*
				 * _IOC_WRITE means userland writes / kernel
				 * reads (the _IOW and _IOWR families).
				 * Without meaningful contents the kernel
				 * usually rejects on first-field validation,
				 * so seed the buffer with random bytes.
				 * Pure _IOC_READ ioctls have the kernel
				 * writing back into the buffer — we just
				 * needed a writable dest.
				 */
				if (dir & _IOC_WRITE)
					generate_rand_bytes(
						(unsigned char *) buf, size);

				return (unsigned long) buf;
			}
		}
	}

	/* Tier 2. */
	cls = ioctl_efault_classify(grp, fd, request);
	switch (cls) {
	case IOCTL_ARG_SCALAR:
		return (unsigned long) rand64();
	case IOCTL_ARG_POINTER:
		size = _IOC_SIZE(request);
		/*
		 * The probe confirmed the kernel dereferences arg, but
		 * a size==0 request carries no width hint.  Rather than
		 * fabricate a page-sized buffer of random bytes (which
		 * the kernel treats as garbage after its first field
		 * check), fall back to a raw scalar — the next probe
		 * cycle will re-classify.
		 */
		if (size == 0)
			return (unsigned long) rand64();
		if (size > page_size)
			size = page_size;
		buf = get_writable_address(size);
		if (buf == NULL)
			return random_ioctl_arg();
		generate_rand_bytes((unsigned char *) buf, size);
		return (unsigned long) buf;
	case IOCTL_ARG_INCONCLUSIVE:
	case IOCTL_ARG_UNKNOWN:
	default:
		/* Tier 3. */
		return random_ioctl_arg();
	}
}
