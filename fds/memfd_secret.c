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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "fd.h"
#include "list.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define NR_MEMFD_SECRET_FDS 4

static int memfd_secret(unsigned int flags)
{
#ifdef __NR_memfd_secret
	return syscall(__NR_memfd_secret, flags);
#else
	(void) flags;
	errno = ENOSYS;
	return -1;
#endif
}

static void memfd_secret_destructor(struct object *obj)
{
	close(obj->memfd_secretobj.fd);
}

/*
 * Cross-process safe: only reads obj->memfd_secretobj fields (in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, matching the pidfd template — head->dump
 * runs from dump_childdata() in the parent on a child-triggered crash.
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

	flags = RAND_BOOL() ? O_CLOEXEC : 0;

	fd = memfd_secret(flags);
	if (fd < 0)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
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
	head->destroy = &memfd_secret_destructor;
	head->dump = &memfd_secret_dump;
	/*
	 * Opt this provider into the shared obj heap so post-fork regen
	 * via try_regenerate_fd() → open_memfd_secret_fd produces obj
	 * structs that already-forked children can see.  memfd_secretobj
	 * has no pointer members, so this is a mechanical conversion
	 * matching the pidfd/fanotify template.
	 */
	head->shared_alloc = true;

	for (i = 0; i < NR_MEMFD_SECRET_FDS; i++) {
		if (open_memfd_secret_fd())
			ret = true;
	}

	return ret;
}

static int get_rand_memfd_secret_fd(void)
{
	if (objects_empty(OBJ_FD_MEMFD_SECRET) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->memfd_secretobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the memfd_secret fd routed into mmap/ftruncate via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_MEMFD_SECRET, OBJ_GLOBAL,
						  &slot_idx, &slot_version);
		if (obj == NULL)
			continue;

		/*
		 * Heap pointers land at >= 0x10000 and below the 47-bit
		 * user/kernel boundary; anything outside that window can't
		 * be a real obj struct.  Reject before deref.
		 */
		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_memfd_secret_fd: bogus obj %p in "
				  "OBJ_FD_MEMFD_SECRET pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_MEMFD_SECRET, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->memfd_secretobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider memfd_secret_fd_provider = {
	.name = "memfd_secret",
	.objtype = OBJ_FD_MEMFD_SECRET,
	.enabled = true,
	.init = &init_memfd_secret_fds,
	.get = &get_rand_memfd_secret_fd,
	.open = &open_memfd_secret_fd,
};

REG_FD_PROV(memfd_secret_fd_provider);
