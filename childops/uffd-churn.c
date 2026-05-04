/*
 * uffd_churn - rapid userfaultfd create/register/unregister/close cycles
 * to exercise the UFFD allocator and the per-context state machine.
 *
 * Trinity's normal random_syscall path can issue userfaultfd(2) and
 * UFFDIO_REGISTER/UFFDIO_UNREGISTER ioctls, but always against
 * pre-allocated long-lived fds owned by fds/userfaultfd.c.  That keeps
 * sustained pressure on the ioctl arg-handling paths but barely touches
 * the lifecycle code: userfaultfd_ctx alloc/free, the
 * userfaultfd_register/userfaultfd_unregister VMA walks, the
 * userfaultfd_release teardown, and the recently-rewritten UFFD context
 * state machine.  uffd_churn closes that gap by driving the lifecycle
 * directly: each cycle creates a fresh fd, performs the UFFDIO_API
 * handshake, mmaps a small anonymous region, registers it,
 * unregisters it, munmaps, and closes the fd.
 *
 * Per invocation: 1..MAX_CYCLES cycles.  Each cycle picks a random subset
 * of the UFFDIO_REGISTER mode bits the kernel reports as supported via
 * the UFFDIO_API features handshake (MISSING is always supported once
 * the handshake succeeds; WP and MINOR depend on kernel version, mm
 * config, and the feature bits we negotiate).  Region size is randomised
 * to 1..MAX_PAGES pages so the VMA walks see varying lengths instead of
 * a single hot path.
 *
 * Self-bounding: the inner loop is hard-capped at MAX_CYCLES, every
 * mmap is matched by an unconditional munmap, every register by an
 * unregister attempt, and the alarm(1) the parent arms before dispatch
 * bounds wall-clock time.  No signal handler is installed for the uffd
 * itself — we never write to the registered region from this thread, so
 * no fault is ever delivered and the kernel's userfault_wait path is
 * never entered.  All we exercise is the registration churn.
 *
 * Many systems run trinity unprivileged or with
 * vm.unprivileged_userfaultfd=0 and no CAP_SYS_PTRACE; in those cases
 * userfaultfd(2) returns EPERM, and on kernels built without
 * CONFIG_USERFAULTFD it returns ENOSYS.  Either latches a per-process
 * ns_unsupported flag and subsequent invocations no-op — there's no
 * point spinning on a permission denial that won't change for the life
 * of the process.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/userfaultfd.h>

#include "arch.h"		/* page_size */
#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* Hard cap on uffd lifecycle cycles per invocation.  Kept modest so a
 * single op completes well inside the alarm(1) window even when sibling
 * churners are also pounding the VMA / userfaultfd_ctx allocators. */
#define MAX_CYCLES	16

/* Upper bound on mmap region size in pages.  Small on purpose: the
 * point of this op is registration churn against the VMA walk, not
 * stressing the allocator with large mappings — fs_lifecycle and
 * memory_pressure already cover the latter. */
#define MAX_PAGES	8

/* Latched per-child: userfaultfd(2) returned EPERM/ENOSYS once.
 * Unprivileged + vm.unprivileged_userfaultfd=0, or the kernel was built
 * without CONFIG_USERFAULTFD — neither flips during this process's
 * lifetime, so further attempts are pure overhead. */
static bool ns_unsupported;

static int do_userfaultfd(int flags)
{
#ifdef SYS_userfaultfd
	return (int)syscall(SYS_userfaultfd, flags);
#else
	(void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

/* Pick a random non-empty subset of the register modes the kernel
 * reports as supported via the UFFDIO_API ioctls bitmap.  Always
 * fall back to MISSING if the intersection is empty — MISSING is
 * the original mode and is always supported once the handshake
 * succeeds. */
static uint64_t pick_register_mode(uint64_t supported_ioctls)
{
	uint64_t mode = 0;

	(void)supported_ioctls;	/* the kernel doesn't report register-mode
				 * support bits in api.ioctls — that's the
				 * per-fd ioctl bitmap.  Mode-bit support
				 * comes from api.features, but we don't
				 * gate on it here: the kernel rejects
				 * unsupported mode bits with -EINVAL,
				 * which is fine — we just count the
				 * register call as failed and move on. */

	if (RAND_BOOL())
		mode |= UFFDIO_REGISTER_MODE_MISSING;
#ifdef UFFDIO_REGISTER_MODE_WP
	if (RAND_BOOL())
		mode |= UFFDIO_REGISTER_MODE_WP;
#endif
#ifdef UFFDIO_REGISTER_MODE_MINOR
	if (RAND_BOOL())
		mode |= UFFDIO_REGISTER_MODE_MINOR;
#endif
	if (mode == 0)
		mode = UFFDIO_REGISTER_MODE_MISSING;
	return mode;
}

bool uffd_churn(struct childdata *child)
{
	unsigned int cycles;
	unsigned int i;

	(void)child;

	__atomic_add_fetch(&shm->stats.uffd_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	cycles = 1 + ((unsigned int)rand() % MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct uffdio_api api;
		struct uffdio_register reg;
		struct uffdio_range range;
		void *region;
		size_t len;
		unsigned int npages;
		int fd;

		/* 1-in-RAND_NEGATIVE_RATIO sub the curated valid flag mix
		 * for a curated edge value — exercises do_sys_userfaultfd's
		 * (flags & ~UFFD_USER_VALID_FLAGS) rejection path which the
		 * O_CLOEXEC|O_NONBLOCK pair above never reaches. */
		fd = do_userfaultfd(
			(int)RAND_NEGATIVE_OR(O_CLOEXEC | O_NONBLOCK));
		if (fd < 0) {
			/* EPERM: vm.unprivileged_userfaultfd=0 and we lack
			 * CAP_SYS_PTRACE.  ENOSYS: kernel built without
			 * CONFIG_USERFAULTFD.  Neither changes for the life
			 * of this process — latch and bail so subsequent
			 * invocations no-op. */
			if (errno == EPERM || errno == ENOSYS) {
				ns_unsupported = true;
				return true;
			}
			__atomic_add_fetch(&shm->stats.uffd_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}

		memset(&api, 0, sizeof(api));
		api.api = UFFD_API;
		api.features = 0;
		if (ioctl(fd, UFFDIO_API, &api) < 0) {
			__atomic_add_fetch(&shm->stats.uffd_failed,
					   1, __ATOMIC_RELAXED);
			close(fd);
			continue;
		}

		npages = 1 + ((unsigned int)rand() % MAX_PAGES);
		len = (size_t)npages * page_size;

		region = mmap(NULL, len, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (region == MAP_FAILED) {
			__atomic_add_fetch(&shm->stats.uffd_failed,
					   1, __ATOMIC_RELAXED);
			close(fd);
			continue;
		}

		memset(&reg, 0, sizeof(reg));
		reg.range.start = (uintptr_t)region;
		reg.range.len = len;
		reg.mode = pick_register_mode(api.ioctls);

		if (ioctl(fd, UFFDIO_REGISTER, &reg) == 0) {
			__atomic_add_fetch(&shm->stats.uffd_registers,
					   1, __ATOMIC_RELAXED);

			range.start = (uintptr_t)region;
			range.len = len;
			if (ioctl(fd, UFFDIO_UNREGISTER, &range) == 0) {
				__atomic_add_fetch(&shm->stats.uffd_unregisters,
						   1, __ATOMIC_RELAXED);
			} else {
				__atomic_add_fetch(&shm->stats.uffd_failed,
						   1, __ATOMIC_RELAXED);
				/* Region still registered; munmap below
				 * will tear down the mapping and the
				 * kernel will drop the registration as
				 * a side effect. */
			}
		} else {
			__atomic_add_fetch(&shm->stats.uffd_failed,
					   1, __ATOMIC_RELAXED);
			/* EINVAL: mode bits we picked aren't supported on
			 * this kernel/mm combo (e.g. WP without
			 * UFFD_FEATURE_PAGEFAULT_FLAG_WP, or MINOR on a
			 * non-shmem/hugetlbfs mapping).  Move on; next
			 * iteration picks a different subset. */
		}

		(void)munmap(region, len);
		close(fd);
	}

	return true;
}
