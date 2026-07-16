/* memfd_secret FD provider.
 *
 * memfd_secret(2) returns an fd to an anonymous "secret" memory area
 * backed by mm/secretmem.c.  Pages mapped from this fd are removed
 * from the kernel direct map, so the kernel surface is distinct from
 * regular memfd_create(2) (mm/memfd.c + tmpfs/shmem) — different fops,
 * different fault path, different write/seal semantics.  Worth tracking
 * separately so syscalls that take an fd (mmap, ftruncate, fcntl seals,
 * read/write, splice, sendfile, etc.) can be aimed at it directly.
 *
 * The syscall is unprivileged but the kernel may have it disabled
 * (CONFIG_SECRETMEM=n, or secretmem.enable_secretmem=0 boot param) —
 * init returns false in that case and the provider is dropped, the
 * same way other optional providers degrade.
 */

#include <errno.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "child.h"
#include "fd.h"
#include "syscall-gate.h"
#include "list.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#define NR_MEMFD_SECRET_FDS 4

/*
 * Latched per-process: memfd_secret(2) returned ENOSYS (CONFIG_SECRETMEM=n
 * or syscall not wired on this arch) or EINVAL with the only flag values
 * we ever pass (0 / O_CLOEXEC, both unconditionally valid when the syscall
 * is supported -- so EINVAL here means the kernel disabled the feature at
 * runtime, e.g. secretmem.enable_secretmem=0).  Neither flips during this
 * process, so init / regen / consumers all fast-path past the syscall
 * once latched.  Mirrors the unsupported_<name> shape used by kvm /
 * landlock / mq.
 */
static bool unsupported_memfd_secret;

static int memfd_secret(unsigned int flags)
{
#ifdef __NR_memfd_secret
	return trinity_raw_syscall(__NR_memfd_secret, flags);
#else
	(void) flags;
	errno = ENOSYS;
	return -1;
#endif
}

/*
 * Cross-process safe: only reads obj->memfd_secretobj scalar fields
 * and the scope scalar.  These survive fork/COW and no process-local
 * pointers are dereferenced — head->dump runs from dump_childdata() in
 * the parent on a child-triggered crash.
 */
static void memfd_secret_dump(struct object *obj, enum obj_scope scope)
{
	struct memfd_secretobj *mso = &obj->memfd_secretobj;

	output(2, "memfd_secret fd:%d flags:%x scope:%d\n",
		mso->fd, mso->flags, scope);
}

static int open_memfd_secret_fd(void)
{
	struct object *obj;
	unsigned int flags;
	int fd;

	if (unsupported_memfd_secret)
		return false;

	flags = RAND_BOOL() ? O_CLOEXEC : 0;

	fd = memfd_secret(flags);
	if (fd < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			outputerr("open_memfd_secret_fd: memfd_secret(flags=%x) failed: %s -- latching unsupported_memfd_secret\n",
				flags, strerror(errno));
			unsupported_memfd_secret = true;
		}
		return false;
	}

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->memfd_secretobj.fd = fd;
	obj->memfd_secretobj.flags = flags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_MEMFD_SECRET);
	return true;
}

static int init_memfd_secret_fds(void)
{
	struct objhead *head;
	unsigned int i;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MEMFD_SECRET);
	head->destroy = &close_fd_destructor;
	head->dump = &memfd_secret_dump;

	for (i = 0; i < NR_MEMFD_SECRET_FDS; i++) {
		if (open_memfd_secret_fd())
			ret = true;
	}

	return ret;
}

static int get_rand_memfd_secret_fd(void)
{
	if (unsupported_memfd_secret)
		return -1;

	if (objects_empty(OBJ_FD_MEMFD_SECRET) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->memfd_secretobj.fd deref.  A version-validated object-slot
	 * read guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the memfd_secret fd routed into mmap/ftruncate via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_MEMFD_SECRET, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_MEMFD_SECRET))
			continue;

		fd = obj->memfd_secretobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

/*
 * Periodic child-tick top-up.  See the block comment above
 * memfd_try_replenish() (fds/memfd.c) for the general contract.
 * init_memfd_secret_fds() seeds NR_MEMFD_SECRET_FDS once; a child that
 * has drained them via fuzz-driven close/dup2/close_range hits stops
 * seeing ARG_FD_MEMFD_SECRET picks.  Push fresh secretmem fds into the
 * live-fd ring to restore gen_arg_fd() hits without touching the
 * OBJ_GLOBAL pool the parent owns.
 *
 * Honour the unsupported_memfd_secret latch: on a kernel without
 * CONFIG_SECRETMEM or with secretmem.enable_secretmem=0, the syscall
 * has already failed once and further calls would just burn budget on
 * ENOSYS/EINVAL.
 */
static void memfd_secret_try_replenish(unsigned int budget)
{
	struct childdata *child = this_child();
	unsigned int i;
	/*
	 * Bound the secretmem fds this provider mints.  child_fd_ring_push()
	 * is a hint cache that does NOT own the fds it evicts -- it is
	 * shared, so other providers push fds tracked elsewhere and it cannot
	 * close on evict.  Every secretmem fd we mint past live_fds's window
	 * would then stay open forever in a long-lived child (canary /
	 * D-state-wedged); worse than memfd, secretmem pages are unswappable
	 * and removed from the kernel direct map, so the pinned pages are
	 * unreclaimable.  Keep a per-child ring of the secretmem fds WE
	 * created and close the one that ages out before reusing its slot.
	 * 32 > live_fds's 16 slots, so the fd we close is already long gone
	 * from live_fds and no consumer still holds it.  Per-child via
	 * fork-COW (replenish runs child-side only; the parent never
	 * populates this, so created_head starts 0 in every child and the
	 * head >= size guard never closes an unwritten slot -- avoiding a
	 * close(0) on the zero-initialised array).
	 */
	static int created_fds[32];
	static unsigned int created_head;

	if (child == NULL)
		return;
	if (unsupported_memfd_secret)
		return;

	for (i = 0; i < budget; i++) {
		unsigned int flags = RAND_BOOL() ? O_CLOEXEC : 0;
		int fd = memfd_secret(flags);

		if (fd < 0)
			return;

		if (created_head >= ARRAY_SIZE(created_fds))
			close(created_fds[created_head % ARRAY_SIZE(created_fds)]);
		created_fds[created_head % ARRAY_SIZE(created_fds)] = fd;
		created_head++;

		child_fd_ring_push(&child->live_fds, fd);
	}
}

static const struct fd_provider memfd_secret_fd_provider = {
	.name = "memfd_secret",
	.objtype = OBJ_FD_MEMFD_SECRET,
	.enabled = true,
	.init = &init_memfd_secret_fds,
	.get = &get_rand_memfd_secret_fd,
	.try_replenish = &memfd_secret_try_replenish,
};

REG_FD_PROV(memfd_secret_fd_provider);
