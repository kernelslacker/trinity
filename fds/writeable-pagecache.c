/*
 * Writeable page-cache scratch fd pool.
 *
 * Independent provider that publishes a small pool of trinity-owned
 * scratch files opened O_RDWR so positioned-write sanitisers
 * (pwrite64/pwritev/pwritev2 and future writer paths that need a
 * seekable destination) have a real source of seekable, writable,
 * page-cache-backed fds to draw from.  The existing OBJ_FD_PAGECACHE
 * pool opens its picks O_RDONLY by construction, so a fuzzed write
 * routed through one of those fds returns EBADF in the VFS prologue
 * and never reaches generic_file_write_iter / per-fs ->write_iter;
 * this pool fills that gap on the write side, mirroring the role
 * the read-side OBJ_FD_PAGECACHE pool already plays for pread/preadv.
 *
 * Safety invariant: every file backing this pool is created fresh
 * under trinity's tmp dir at init time, lives only for the run, and
 * has no shared meaning with any other pool.  In particular this
 * pool is DELIBERATELY scribble-able and MUST NEVER overlap the
 * canary pool — canary's content-verification oracle assumes its
 * files are never written by fuzzed syscalls, and a basename
 * collision would turn a positioned-write hit into a canary false
 * alarm.  The "trinity-writepc-" basename prefix is reserved for
 * this pool's private use.  Open flags are plain O_RDWR; the buffered
 * page-cache write path is the whole point, so no O_DIRECT / O_DSYNC
 * / O_SYNC — the testfile pool already varies through those modes
 * for the broader filesystem coverage matrix.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "fd.h"
#include "files.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define NR_WRITEABLE_PAGECACHE_FDS	8

/*
 * Pre-populated per-slot file size.  Mix of single-page, multi-page,
 * a larger multi-extent file, and one odd non-page-aligned size so a
 * positioned write picks both the "within existing extent" path
 * (offset < size) and the past-EOF append/extend path
 * (offset >= size), and so the partial-tail handling in
 * generic_file_write_iter and per-fs ->write_iter sees both
 * page-aligned and non-page-aligned tails.
 */
static const size_t writeable_pagecache_sizes[NR_WRITEABLE_PAGECACHE_FDS] = {
	4096,
	4096,
	16384,
	16384,
	65536,
	65536,
	131072,
	8192 + 1024,
};

static void writeable_pagecache_destructor(struct object *obj)
{
	if (obj->fileobj.fd >= 0)
		close(obj->fileobj.fd);
	if (obj->fileobj.filename != NULL) {
		(void)unlink(obj->fileobj.filename);
		free_shared_str((void *)obj->fileobj.filename, 64);
		obj->fileobj.filename = NULL;
	}
}

static void writeable_pagecache_dump(struct object *obj, enum obj_scope scope)
{
	struct fileobj *fo = &obj->fileobj;

	output(2, "writeable-pagecache fd:%d filename:%s flags:%x scope:%d\n",
		fo->fd, fo->filename, fo->flags, scope);
}

static bool writeable_pagecache_create_one(unsigned int idx)
{
	struct object *obj;
	char *filename;
	off_t size;
	int fd;

	filename = alloc_shared_str(64);
	if (filename == NULL)
		return false;

	/*
	 * Reserved basename prefix.  Keep this in sync with the safety
	 * invariant in the file header — any rename here also has to
	 * stay disjoint from canary/<idx> and every other trinity-owned
	 * scratch path.
	 */
	snprintf(filename, 64, "trinity-writepc-%u", idx);
	(void)unlink(filename);

	fd = open(filename, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		free_shared_str(filename, 64);
		return false;
	}

	size = (off_t)writeable_pagecache_sizes[idx];
	if (ftruncate(fd, size) < 0) {
		close(fd);
		(void)unlink(filename);
		free_shared_str(filename, 64);
		return false;
	}

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		(void)unlink(filename);
		free_shared_str(filename, 64);
		return false;
	}

	obj->fileobj.filename = filename;
	obj->fileobj.flags = O_RDWR;
	obj->fileobj.fd = fd;
	obj->fileobj.fopened = false;
	obj->fileobj.pagecache_backed = true;
	obj->fileobj.is_setuid = false;
	obj->fileobj.fcntl_flags = 0;
	obj->fileobj.obj_flags = 0;

	add_object(obj, OBJ_GLOBAL, OBJ_FD_WRITEABLE_PAGECACHE);
	return true;
}

static int init_writeable_pagecache_fds(void)
{
	struct objhead *head;
	unsigned int i;
	unsigned int opened = 0;
	int last_errno = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_WRITEABLE_PAGECACHE);
	head->destroy = &writeable_pagecache_destructor;
	head->dump = &writeable_pagecache_dump;

	for (i = 0; i < NR_WRITEABLE_PAGECACHE_FDS; i++) {
		if (writeable_pagecache_create_one(i))
			opened++;
		else
			last_errno = errno;
	}

	if (opened == 0) {
		outputerr("writeable-pagecache: opened 0/%u scratch files (last errno %d: %s)\n",
			  NR_WRITEABLE_PAGECACHE_FDS, last_errno,
			  strerror(last_errno));
		fd_provider_init_fail(FD_INIT_REASON_RESOURCE, last_errno,
				      "pool empty");
		return false;
	}

	return true;
}

int get_rand_writeable_pagecache_fd(void)
{
	if (objects_empty(OBJ_FD_WRITEABLE_PAGECACHE) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->fileobj.fd deref.  Same OBJ_GLOBAL lockless-reader UAF
	 * window the canary / pagecache / sparse-files providers close:
	 * between the slot pick and the consumer's read of the fd, the
	 * parent can destroy the obj, release_obj() zeroes the chunk
	 * and routes it through deferred-free, so a stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_WRITEABLE_PAGECACHE, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_WRITEABLE_PAGECACHE))
			continue;

		fd = obj->fileobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider writeable_pagecache_fd_provider = {
	.name = "writeable-pagecache",
	.objtype = OBJ_FD_WRITEABLE_PAGECACHE,
	.enabled = true,
	.init = &init_writeable_pagecache_fds,
	.get = &get_rand_writeable_pagecache_fd,
};

REG_FD_PROV(writeable_pagecache_fd_provider);
