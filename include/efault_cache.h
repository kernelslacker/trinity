#pragma once

#include <stdbool.h>
#include <stdint.h>

struct ioctl_group;

/*
 * Capacity of the (group_idx, request) cache that backs the EFAULT
 * probe.  Open-addressing with linear probe; defined here because the
 * shm-resident array lives in struct shm_s and the access path lives
 * in ioctls/efault_cache.c.  4096 slots covers ~10x the registered
 * ioctl count across all groups, with comfortable headroom for
 * collision chains.
 */
#define IOCTL_EFAULT_CACHE_SIZE	4096u

/*
 * Classification produced by the EFAULT-probe pass over (group, request).
 * Cached values live in shm so a verdict reached by one child applies
 * to every other child without re-running the side-effecting probe.
 *
 *   IOCTL_ARG_UNKNOWN       — never probed.  Doubles as the empty-slot
 *                             sentinel and the "transient probe failure
 *                             we don't want to memoise" return (e.g.
 *                             EBADF on an fd whose group affinity
 *                             didn't actually match).
 *   IOCTL_ARG_SCALAR        — probe rejected the bogus arg without any
 *                             attempt to dereference it (EINVAL/ENOTTY/
 *                             ENOSYS, or success).  Hand the kernel a
 *                             scalar.
 *   IOCTL_ARG_POINTER       — probe rejected the bogus arg with EFAULT
 *                             on both rounds.  Hand the kernel a
 *                             writable buffer.
 *   IOCTL_ARG_INCONCLUSIVE  — probe rounds disagreed or returned an
 *                             unexpected errno.  Caller falls back to
 *                             the legacy 50/50 generator.
 */
enum ioctl_arg_class {
	IOCTL_ARG_UNKNOWN = 0,
	IOCTL_ARG_SCALAR = 1,
	IOCTL_ARG_POINTER = 2,
	IOCTL_ARG_INCONCLUSIVE = 3,
};

/*
 * Look up the cached classification for (grp, request); on miss, run
 * the EFAULT probe (with side effects), memoise the result, and return
 * it.  Returns IOCTL_ARG_UNKNOWN when the group is on the side-effect
 * opt-out list, when no stable group identity is available, or when
 * the probe itself failed in a way we don't want to cache (e.g. EBADF
 * on a mismatched fd).  The caller treats UNKNOWN and INCONCLUSIVE the
 * same way — fall through to the legacy generator.
 */
enum ioctl_arg_class ioctl_efault_classify(const struct ioctl_group *grp,
					   int fd, unsigned int request);

/*
 * True if this group is eligible for the EFAULT probe.  Default-on; the
 * opt-out list inside efault_cache.c covers groups whose ioctls allocate
 * kernel state on dispatch (KVM CREATE_*, vhost ring setup, vfio /
 * iommufd container allocation, loop-control device creation) where
 * even a "rejected" probe leaks resources.
 */
bool ioctl_efault_probe_allowed(const struct ioctl_group *grp);

/*
 * Index of grp in the registered-groups table, or -1 if not registered.
 * Stable after constructor-time registration, so usable as a cache key.
 * Defined in ioctls/ioctls.c next to the table itself.
 */
int ioctl_group_index(const struct ioctl_group *grp);
