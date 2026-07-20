/* memfd FDs */

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "child.h"
#include "deferred-free.h"
#include "fd.h"
#include "memfd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/memfd.h"
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

static void arm_memfd(int fd)
{
	static const unsigned int seal_flags[] = {
		F_SEAL_SEAL,
		F_SEAL_SHRINK,
		F_SEAL_GROW,
		F_SEAL_WRITE,
		F_SEAL_FUTURE_WRITE,
	};
	unsigned int seals = 0;
	unsigned int i, count;

	count = 1 + rnd_modulo_u32(3);
	for (i = 0; i < count; i++)
		seals |= seal_flags[rnd_modulo_u32(ARRAY_SIZE(seal_flags))];

	fcntl(fd, F_ADD_SEALS, seals);
}

static void memfd_destructor(struct object *obj)
{
	close(obj->memfdobj.fd);
}

static void memfd_dump(struct object *obj, enum obj_scope scope)
{
	struct memfdobj *mo = &obj->memfdobj;

	output(2, "memfd fd:%d flags:%x scope:%d\n",
		mo->fd, mo->flags, scope);
}

/*
 * Parent-side setup: wire the OBJ_GLOBAL head's destroy + dump slots so
 * init_object_lists(OBJ_LOCAL, child) inherits them into every child's
 * per-pool objhead (same shape as setup_kvm_heads() in fds/kvm.c).  The
 * OBJ_GLOBAL memfd pool stays empty for the run -- every memfd we track
 * is created per-child from memfd_child_init() into that child's private
 * OBJ_LOCAL pool.
 *
 * Pre-refactor init created the 7 flag-variant memfds parent-side and
 * added them to OBJ_GLOBAL, so the parent kept the fds open for the
 * whole run.  Children wrote / ftruncate'd them via the fuzz loop,
 * allocating tmpfs pages anchored to the shared memfd inodes; child
 * death did not close the fds (the parent still held them) so the
 * inodes never dropped their last reference and the tmpfs pages were
 * never reclaimed.  Sustained fuzz on MFD_HUGETLB especially bled
 * Shmem past 8 GiB and tripped a global OOM.  Per-child OBJ_LOCAL
 * memfds are opened in the child, closed by the kernel on child exit,
 * and the tmpfs pages are reclaimed immediately with the inode.
 */
static int init_memfd_fds(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MEMFD);
	head->destroy = &memfd_destructor;
	head->dump = &memfd_dump;

	return true;
}

/*
 * Per-child seed: create the 7 flag-variant memfds in the calling
 * child's OBJ_LOCAL OBJ_FD_MEMFD pool.  Wired to the fd_provider
 * child_init hook so the fds are opened in child context after
 * init_object_lists(OBJ_LOCAL, ...) has brought the local pool up.
 * The name passed to memfd_create() stays the "memfd<n>" tag so
 * /proc/self/fd links remain identifiable; the memfdobj.name slot is
 * left NULL (alloc_object zeroes) because per-child names would leak
 * alloc_shared_strdup() bytes across the millions of child lifetimes
 * a fuzz run rolls through -- OBJ_LOCAL has no child-exit destructor
 * walk, so the child's death only reclaims its private heap, not any
 * shm the destructor never got to free.
 */
static void memfd_child_init(struct childdata *child __attribute__((unused)))
{
	static const unsigned int flags[] = {
		0,
		MFD_CLOEXEC,
		MFD_CLOEXEC | MFD_ALLOW_SEALING,
		MFD_ALLOW_SEALING,
		MFD_HUGETLB,
		MFD_NOEXEC_SEAL,
		MFD_EXEC,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		char namestr[] = "memfdN";
		int fd;

		snprintf(namestr, sizeof(namestr), "memfd%u", i + 1);

		fd = memfd_create(namestr, flags[i]);
		if (fd < 0)
			continue;

		if (flags[i] & MFD_ALLOW_SEALING)
			arm_memfd(fd);

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			continue;
		}
		obj->memfdobj.fd = fd;
		obj->memfdobj.flags = flags[i];
		add_object(obj, OBJ_LOCAL, OBJ_FD_MEMFD);
	}
}

/*
 * Per-child (OBJ_LOCAL) memfd picker.  Every memfd tracked as an
 * object lives in the calling child's OBJ_LOCAL pool -- seeded by
 * memfd_child_init() and not exposed to the OBJ_GLOBAL lockless-reader
 * UAF window (single-writer / single-reader inside one child).  We
 * still run objpool_check() and cap the retry loop to match the shape
 * used by the KVM per-child pickers.
 */
static int get_rand_memfd_fd(void)
{
	if (objects_pool_empty(OBJ_LOCAL, OBJ_FD_MEMFD) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_MEMFD, OBJ_LOCAL);
		if (!objpool_check(obj, OBJ_FD_MEMFD))
			continue;

		fd = obj->memfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

/*
 * Periodic child-tick top-up.  See the block comment above
 * epoll_try_replenish() (fds/epoll.c) for the general contract.
 * memfd_child_init() seeds one memfd per @flags entry once into the
 * child's OBJ_LOCAL pool; a child that has closed most of them via
 * fuzz-driven close/dup2 hits stops seeing ARG_FD_MEMFD picks.  Push
 * fresh memfds into the live-fd ring to restore gen_arg_fd() hits
 * without going through the OBJ_LOCAL objhead again.
 *
 * Reuse the same flag set the seed used so the topped-up fds carry the
 * same MFD_CLOEXEC / MFD_ALLOW_SEALING / MFD_HUGETLB / MFD_NOEXEC_SEAL
 * / MFD_EXEC distribution rather than one fixed flavour, and mirror
 * the seed's arm step so MFD_ALLOW_SEALING fds get the same F_ADD_SEALS
 * mask applied before publish.
 */
static void memfd_try_replenish(unsigned int budget)
{
	struct childdata *child = this_child();
	unsigned int i;
	static const unsigned int flags[] = {
		0,
		MFD_CLOEXEC,
		MFD_CLOEXEC | MFD_ALLOW_SEALING,
		MFD_ALLOW_SEALING,
		MFD_HUGETLB,
		MFD_NOEXEC_SEAL,
		MFD_EXEC,
	};
	/*
	 * Bound the memfds this provider mints.  child_fd_ring_push() is a
	 * hint cache that does NOT own the fds it evicts -- it is shared, so
	 * other providers push fds tracked elsewhere and it cannot close on
	 * evict.  Every memfd we mint past live_fds's window would then stay
	 * open forever in a long-lived child (canary / D-state-wedged),
	 * pinning its tmpfs pages until the box OOMs.  Keep a per-child ring
	 * of the memfds WE created and close the one that ages out before
	 * reusing its slot.  32 > live_fds's 16 slots, so the fd we close is
	 * already long gone from live_fds and no consumer still holds it.
	 * Per-child via fork-COW (replenish runs child-side only; the parent
	 * never populates this, so created_head starts 0 in every child and
	 * the head >= size guard never closes an unwritten slot -- avoiding a
	 * close(0) on the zero-initialised array).  NOTE: this reclaims pages
	 * only for memfds not still mmap'd; an mmap'd memfd's pages are held
	 * by the VMA (OBJ_MMAP_FILE) until munmap.
	 */
	static int created_fds[32];
	static unsigned int created_head;

	if (child == NULL)
		return;

	for (i = 0; i < budget; i++) {
		char namestr[16];
		unsigned int idx = rnd_modulo_u32(ARRAY_SIZE(flags));
		int fd;

		snprintf(namestr, sizeof(namestr), "memfd%u", idx + 1);

		fd = memfd_create(namestr, flags[idx]);
		if (fd < 0)
			return;

		if (flags[idx] & MFD_ALLOW_SEALING)
			arm_memfd(fd);

		if (created_head >= ARRAY_SIZE(created_fds))
			close(created_fds[created_head % ARRAY_SIZE(created_fds)]);
		created_fds[created_head % ARRAY_SIZE(created_fds)] = fd;
		created_head++;

		child_fd_ring_push(&child->live_fds, fd);
	}
}

static const struct fd_provider memfd_fd_provider = {
	.name = "memfd",
	.objtype = OBJ_FD_MEMFD,
	.enabled = true,
	.init = &init_memfd_fds,
	.child_init = &memfd_child_init,
	.get = &get_rand_memfd_fd,
	.try_replenish = &memfd_try_replenish,
};

REG_FD_PROV(memfd_fd_provider);
