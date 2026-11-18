/*
 * memfd_secret FD provider.  memfd_secret(2) returns an fd to anonymous
 * "secret" memory (mm/secretmem.c) whose pages leave the kernel direct map:
 * a different surface from memfd_create(2), with its own fops, fault path and
 * write/seal semantics.  Where it fails ENOSYS (no CONFIG_SECRETMEM, boot
 * param secretmem.enable=0, no direct-map editing) the provider is dropped.
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
#include "owned-fd-ring.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#define NR_MEMFD_SECRET_FDS 4

/*
 * Latched by the parent's probe: memfd_secret(2) returned ENOSYS
 * (CONFIG_SECRETMEM=n, syscall not wired on this arch, secretmem.enable=0
 * or no direct-map editing: the kernel gives the last two the same
 * -ENOSYS) or EINVAL, which it gives only for flag bits we never pass (we
 * send 0 / O_CLOEXEC) and which is latched as a safety net.  Neither
 * flips during the run, so the replenish tick skips the syscall once
 * latched.  Mirrors the unsupported_<name> shape used by landlock / mq.
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

static void memfd_secret_dump(struct object *obj, enum obj_scope scope)
{
	struct memfd_secretobj *mso = &obj->memfd_secretobj;

	output(2, "memfd_secret fd:%d flags:%x scope:%d\n",
		mso->fd, mso->flags, scope);
}

static void open_memfd_secret_fd(void)
{
	struct object *obj;
	unsigned int flags;
	int fd;

	flags = RAND_BOOL() ? O_CLOEXEC : 0;

	fd = memfd_secret(flags);
	if (fd < 0)
		return;

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		return;
	}
	obj->memfd_secretobj.fd = fd;
	obj->memfd_secretobj.flags = flags;
	add_object(obj, OBJ_LOCAL, OBJ_FD_MEMFD_SECRET);
}

/*
 * Parent-side setup: wire the OBJ_GLOBAL head's destroy and dump slots,
 * which init_object_lists(OBJ_LOCAL, child) copies into every child's
 * pool, and probe that memfd_secret(2) works; the probe fd is closed at
 * once.  The global pool stays empty.  A secretmem page a fault allocates
 * is charged to the locked_vm of the user who created the file, against
 * the faulting task's RLIMIT_MEMLOCK, until the file is released
 * (mm/secretmem.c), so fds the parent held for the run would pile every
 * child's faults onto it.  Each child makes its own instead, in
 * memfd_secret_child_init(), released when it exits.
 */
static int init_memfd_secret_fds(void)
{
	struct objhead *head;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MEMFD_SECRET);
	head->destroy = &close_fd_destructor;
	head->dump = &memfd_secret_dump;

	fd = memfd_secret(0);
	if (fd < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			outputerr("init_memfd_secret_fds: memfd_secret() failed: %s -- latching unsupported_memfd_secret\n",
				strerror(errno));
			unsupported_memfd_secret = true;
		}
		return false;
	}
	close(fd);
	return true;
}

/* Per-child seed: the pool's secretmem fds, made in the child's context
 * after init_object_lists(OBJ_LOCAL, ...) has brought its pool up. */
static void memfd_secret_child_init(struct childdata *child __attribute__((unused)))
{
	unsigned int i;

	for (i = 0; i < NR_MEMFD_SECRET_FDS; i++)
		open_memfd_secret_fd();
}

/*
 * Per-child (OBJ_LOCAL) picker: every secretmem fd the pool holds was made
 * by memfd_secret_child_init() in this child, out of the OBJ_GLOBAL
 * lockless-reader window.
 */
static int get_rand_memfd_secret_fd(void)
{
	if (objects_pool_empty(OBJ_LOCAL, OBJ_FD_MEMFD_SECRET) == true)
		return -1;

	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_MEMFD_SECRET, OBJ_LOCAL);
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
 * memfd_secret_child_init() seeds NR_MEMFD_SECRET_FDS once into the
 * child's pool; a child that has drained them via fuzz-driven
 * close/dup2/close_range hits stops seeing ARG_FD_MEMFD_SECRET picks.
 * Push fresh secretmem fds into the live-fd ring to restore gen_arg_fd()
 * hits without growing that pool.
 *
 * Honour the unsupported_memfd_secret latch: on a kernel without
 * CONFIG_SECRETMEM or with secretmem.enable=0, the syscall has already
 * failed once and further calls would just burn budget on ENOSYS.
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
	 * MAX_OWNED_FDS exceeds CHILD_FD_RING_SIZE, so the fd we close is
	 * already long gone from live_fds and no consumer still holds it.
	 * Per-child via fork-COW (replenish runs child-side only; the parent
	 * never populates this, so every child starts with an empty ring).
	 */
	static struct owned_fd_ring created_fds;

	if (child == NULL)
		return;
	if (unsupported_memfd_secret)
		return;

	for (i = 0; i < budget; i++) {
		unsigned int flags = RAND_BOOL() ? O_CLOEXEC : 0;
		int fd = memfd_secret(flags);

		if (fd < 0)
			return;

		owned_fd_ring_record(&created_fds, fd);

		child_fd_ring_push(&child->live_fds, fd);
	}
}

static const struct fd_provider memfd_secret_fd_provider = {
	.name = "memfd_secret",
	.objtype = OBJ_FD_MEMFD_SECRET,
	.enabled = true,
	.init = &init_memfd_secret_fds,
	.child_init = &memfd_secret_child_init,
	.get = &get_rand_memfd_secret_fd,
	.try_replenish = &memfd_secret_try_replenish,
	.local_pool = true,
};

REG_FD_PROV(memfd_secret_fd_provider);
