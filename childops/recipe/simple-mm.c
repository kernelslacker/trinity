/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <linux/userfaultfd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "syscall-gate.h"
#include "maps.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "childops/recipe/internal.h"

#include "kernel/eventfd.h"
#include "kernel/fcntl.h"
#include "kernel/timerfd.h"
#include "kernel/memfd.h"
/*
 * Recipe 6: memfd seal lifecycle.
 *
 * Creates a sealable memfd, writes a page of data, ftruncates to a
 * page size, mmaps it RW, dirties the mapping, then munmaps and seals
 * with F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE.  This is the canonical
 * sequence that exercises the seal-vs-active-mapping accounting and
 * the writable-mapping refcount the seal path checks.
 */
bool recipe_memfd_seal(bool *unsupported __unused__)
{
	int fd = -1;
	void *p = MAP_FAILED;
	char data[64];
	bool ok = false;

	fd = (int)trinity_raw_syscall(__NR_memfd_create, "trinity-recipe",
			  MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd < 0)
		goto out;

	memset(data, 'r', sizeof(data));
	if (write(fd, data, sizeof(data)) != (ssize_t)sizeof(data))
		goto out;

	if (ftruncate(fd, page_size) < 0)
		goto out;

	p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		goto out;

	((volatile char *)p)[0] = (char)(rnd_u32() & 0xff);

	if (munmap(p, page_size) < 0)
		goto out;
	p = MAP_FAILED;

	if (fcntl(fd, F_ADD_SEALS,
		  F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) < 0)
		goto out;

	ok = true;
out:
	if (p != MAP_FAILED)
		munmap(p, page_size);
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 14: futex lifecycle on a shared anonymous mapping.
 *
 * Draw a region from the parent's inherited mapping pool (built once in
 * setup_initial_mappings as MAP_SHARED | MAP_ANONYMOUS) → futex(FUTEX_WAIT)
 * with a short timeout (expected to return EAGAIN immediately because
 * the value doesn't match) → futex(FUTEX_WAKE) on the same address.
 * Exercises the futex hash-bucket lookup, the timeout path, and the
 * cleanup of the futex queue.
 *
 * The shared-anon pool entries put the futex on the shared key path
 * inside the kernel, which is the more interesting variant — the private
 * path is what most application code hits.
 *
 * Restrict the draw to the OBJ_MMAP_ANON pool, and filter further on
 * PROT_READ | PROT_WRITE: the recipe writes the value word before the
 * FUTEX_WAIT and the kernel reads it during the cmpxchg in
 * futex_wait_setup.  A PROT_READ-only or PROT_NONE entry would SEGV on
 * the value-word store before the futex syscall; a FILE/TESTFILE-backed
 * entry can be prot-RW yet have an un-faultable first page (a sibling
 * truncate / hole-punch / fallocate range-zero left a hole behind a
 * still-RW VMA), so the store would SIGBUS BUS_ADRERR before the futex
 * syscall.  Anon-pool entries are zero-fill with no backing file, so
 * the first-page store is always faultable.
 *
 * The pool owns the mapping: do NOT munmap on cleanup.  Sibling recipes
 * draw from the same pool, so they will sometimes target the same futex
 * word — the cross-sibling collision on the value and on the kernel's
 * shared-key hash bucket is the cross-vector behaviour we want to
 * exercise.  The 1 ms timeout bounds any worst-case wait if a sibling
 * happens to have raced *futex_addr to the expected value of 1 between
 * our store and the FUTEX_WAIT.
 */
bool recipe_futex(bool *unsupported __unused__)
{
	struct timespec ts;
	struct map *m = NULL;
	uint32_t *futex_addr = NULL;
	bool ok = false;

	m = get_anon_map_with_prot(PROT_READ | PROT_WRITE);
	if (m == NULL)
		goto out;
	futex_addr = (uint32_t *)m->ptr;

	*futex_addr = 0;

	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;	/* 1 ms */
	/* Pass an expected value of 1, but the actual value is 0 — the
	 * kernel returns EAGAIN immediately without queuing.  This still
	 * exercises the hash lookup and the futex_wait_setup path. */
	(void)trinity_raw_syscall(__NR_futex, futex_addr, FUTEX_WAIT, 1, &ts,
		      NULL, 0);

	(void)trinity_raw_syscall(__NR_futex, futex_addr, FUTEX_WAKE, INT_MAX,
		      NULL, NULL, 0);

	ok = true;
out:
	return ok;
}

/*
 * Recipe 16: userfaultfd lifecycle.
 *
 * userfaultfd → ioctl(UFFDIO_API) → mmap a private region →
 * ioctl(UFFDIO_REGISTER) for missing-page faults → ioctl
 * (UFFDIO_UNREGISTER) → munmap → close.  We deliberately don't
 * touch the registered region from the same thread (that would block
 * forever waiting for a userfaultfd handler to fill the page).
 *
 * userfaultfd may be off (vm.unprivileged_userfaultfd=0 plus no
 * CAP_SYS_PTRACE, or kernel built without CONFIG_USERFAULTFD) —
 * EPERM/ENOSYS latches the recipe off.
 */
bool recipe_userfaultfd(bool *unsupported)
{
	struct uffdio_api api;
	struct uffdio_register reg;
	struct uffdio_range range;
	void *region = MAP_FAILED;
	int fd = -1;
	bool registered = false;
	bool ok = false;

	fd = (int)trinity_raw_syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		if (errno == EPERM || errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe.unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	memset(&api, 0, sizeof(api));
	api.api = UFFD_API;
	if (ioctl(fd, UFFDIO_API, &api) < 0)
		goto out;

	region = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		goto out;

	memset(&reg, 0, sizeof(reg));
	reg.range.start = (uintptr_t)region;
	reg.range.len = page_size;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(fd, UFFDIO_REGISTER, &reg) < 0)
		goto out;
	registered = true;

	range.start = (uintptr_t)region;
	range.len = page_size;
	if (ioctl(fd, UFFDIO_UNREGISTER, &range) < 0)
		goto out;
	registered = false;

	ok = true;
out:
	if (registered) {
		range.start = (uintptr_t)region;
		range.len = page_size;
		(void)ioctl(fd, UFFDIO_UNREGISTER, &range);
	}
	if (region != MAP_FAILED)
		(void)munmap(region, page_size);
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 18: anon-VMA split-and-coalesce lifecycle.
 *
 * mmap a 4-page private anonymous region → dirty every page so the
 * VMA owns populated PTEs → mprotect the middle two pages to PROT_READ
 * (splits one VMA into three: [RW][R][RW]) → mprotect them back to
 * RW (vma_merge collapses the three into one again) → munmap the
 * single middle page (re-splits with an unmapped hole) → munmap the
 * full original range (kernel walks the residual head + tail VMAs
 * across the punched gap).
 *
 * Exercises split_vma, vma_merge, and the munmap-with-hole path in
 * one sequence — all three are common UAF/refcount fault sites that
 * isolated random mmap/munmap calls rarely reach because they need a
 * specific multi-VMA layout to begin with.  The existing
 * mprotect-split childop drives the split path with random
 * arguments; this recipe forces the deterministic split→merge→hole
 * trajectory the random caller almost never hits.
 */
bool recipe_mm_vma(bool *unsupported __unused__)
{
	void *region = MAP_FAILED;
	size_t total = (size_t)page_size * 4;
	char *base;
	bool ok = false;

	region = mmap(NULL, total, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		goto out;
	base = region;

	base[0 * page_size] = 'a';
	base[1 * page_size] = 'b';
	base[2 * page_size] = 'c';
	base[3 * page_size] = 'd';

	/* Split: middle two pages drop to PROT_READ.  Single VMA
	 * becomes three: [RW][R][RW]. */
	if (mprotect(base + page_size, (size_t)page_size * 2,
		     PROT_READ) < 0)
		goto out;

	/* Coalesce: promote middle back to RW.  vma_merge should fold
	 * all three fragments back into one VMA. */
	if (mprotect(base + page_size, (size_t)page_size * 2,
		     PROT_READ | PROT_WRITE) < 0)
		goto out;

	/* Punch a hole — splits the (now-merged) VMA again, this time
	 * with a real unmapped gap between the surviving fragments. */
	if (munmap(base + page_size, page_size) < 0)
		goto out;

	/* Tear down everything that's left.  munmap across an unmapped
	 * region is well-defined; the kernel just unmaps what's still
	 * present.  This is the path we want to drive. */
	if (munmap(region, total) < 0)
		goto out;
	region = MAP_FAILED;

	ok = true;
out:
	if (region != MAP_FAILED)
		(void)munmap(region, total);
	return ok;
}

/*
 * Recipe 19: memfd-as-mmap-source lifecycle.
 *
 * memfd_create(MFD_CLOEXEC) → ftruncate to 4 pages → mmap MAP_SHARED
 * over the whole file → write a distinct byte to each page (faulting
 * in four shmem pages) → read each one back to verify the page-cache
 * round-trip → munmap → close.
 *
 * Distinct from recipe_memfd_seal: that recipe targets the seal
 * accounting path (sealable memfd, write-then-seal); this one drives
 * the plain memfd-as-anon-file mmap/fault path so the shmem fault
 * handler, page-cache insertion, and mapping teardown all run in one
 * sequence.  Together they cover both the storage and the locking
 * faces of memfd.
 *
 * memfd_create may be missing on stripped-down kernels (very old, or
 * built without CONFIG_MEMFD_CREATE) — ENOSYS latches the recipe off.
 */
bool recipe_mm_memfd(bool *unsupported)
{
	int fd = -1;
	void *p = MAP_FAILED;
	size_t total = (size_t)page_size * 4;
	char *base;
	size_t i;
	bool ok = false;

	fd = (int)trinity_raw_syscall(__NR_memfd_create, "trinity-recipe-mm-memfd",
			  MFD_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe.unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (ftruncate(fd, (off_t)total) < 0)
		goto out;

	p = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		goto out;
	base = p;

	for (i = 0; i < total; i += page_size)
		base[i] = (char)('m' + (i / page_size));

	for (i = 0; i < total; i += page_size)
		if (((volatile char *)base)[i] !=
		    (char)('m' + (i / page_size)))
			goto out;

	if (munmap(p, total) < 0)
		goto out;
	p = MAP_FAILED;

	ok = true;
out:
	if (p != MAP_FAILED)
		(void)munmap(p, total);
	if (fd >= 0)
		close(fd);
	return ok;
}
