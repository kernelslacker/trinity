/*
 * Page-cache-backed fd pool.
 *
 * Independent provider: walks the global fileindex (already populated by
 * generate_filelist()) and opens regular files that live on whitelisted
 * cache-backed filesystems.  Files on procfs/sysfs/cgroupfs etc. are
 * deliberately excluded — those backing stores don't engage the page
 * cache code paths the consumer (splice substitution) is trying to
 * exercise.
 *
 * When the fileindex scan yields zero pagecache-backed regular files
 * (the default run walks /dev,/proc,/sys and finds none), a small
 * private RO scratch corpus is self-seeded so consumers biased toward
 * this pool still hit a real page-cache substrate rather than silently
 * falling back to a random fd.  Mirrors the sibling write-side pool in
 * fds/writeable-pagecache.c: create fresh under trinity's tmp dir,
 * ftruncate to a size ladder, reopen O_RDONLY, unlink in the
 * destructor.  The "trinity-pcro-" basename prefix is reserved for
 * this pool's private use.
 *
 * A parallel small index array of "interesting" objects (currently:
 * setuid binaries) is maintained alongside the per-objhead pool so
 * get_rand_pagecache_fd() can bias picks towards them without scanning
 * the full pool on every call.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fd.h"
#include "files.h"
#include "objects.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC	0x794c7630
#endif
#ifndef ZFS_SUPER_MAGIC
#define ZFS_SUPER_MAGIC		0x2fc12fc1
#endif

#define NR_PAGECACHE_FDS	64
#define NR_PAGECACHE_SETUID	16
#define SETUID_BIAS_PCT		25

#define NR_PAGECACHE_SELFSEED_FDS	4

/*
 * Size ladder for the self-seed fallback: single-page, multi-page,
 * larger multi-extent, and a multi-MB file so a consumer that biases
 * offset picks by file size sees a spread across the page-cache /
 * readahead code paths (single-page hit, cross-page span, readahead
 * window, and past-EOF pick).  Filenames are trinity-owned scratch
 * under the run's tmp dir; the destructor closes and unlinks them.
 */
static const size_t pagecache_selfseed_sizes[NR_PAGECACHE_SELFSEED_FDS] = {
	4096,
	65536,
	524288,
	4 * 1024 * 1024,
};

/*
 * Indices into the OBJ_FD_PAGECACHE objhead->array of objects whose
 * underlying file was setuid.  Populated as we open; consumed by
 * get_rand_pagecache_fd() when the bias coin comes up.
 */
static unsigned int setuid_indices[NR_PAGECACHE_SETUID];
static unsigned int nr_setuid;

static bool fs_is_pagecache_backed(int fd)
{
	struct statfs sfs;

	if (fstatfs(fd, &sfs) != 0)
		return false;

	switch ((unsigned long) sfs.f_type) {
	case TMPFS_MAGIC:
	case EXT2_SUPER_MAGIC:	/* same magic for ext2/3/4 */
	case XFS_SUPER_MAGIC:
	case BTRFS_SUPER_MAGIC:
	case F2FS_SUPER_MAGIC:
	case OVERLAYFS_SUPER_MAGIC:
	case ZFS_SUPER_MAGIC:
		return true;
	default:
		return false;
	}
}

static void pagecache_dump(struct object *obj, enum obj_scope scope)
{
	struct fileobj *fo = &obj->fileobj;

	output(2, "pagecache fd:%d filename:%s flags:%x setuid:%d scope:%d\n",
		fo->fd, fo->filename, fo->flags, fo->is_setuid, scope);
}

/*
 * Destructor for the self-seed fallback path.  The fileindex scan
 * borrows filenames from the global fileindex (const, not owned), but
 * self-seeded files own their basename via alloc_shared_str and their
 * on-disk inode via unlink.  The fallback path is all-or-nothing —
 * either the scan populated the pool (borrowed names, close-only) or
 * this destructor is installed (owned names, close + unlink + free) —
 * so the two lifecycles never coexist in a single pool.
 */
static void pagecache_selfseed_destructor(struct object *obj)
{
	if (obj->fileobj.fd >= 0)
		close(obj->fileobj.fd);
	if (obj->fileobj.filename != NULL) {
		(void)unlink(obj->fileobj.filename);
		free_shared_str((void *)obj->fileobj.filename, 64);
		obj->fileobj.filename = NULL;
	}
}

static bool pagecache_selfseed_create_one(unsigned int idx)
{
	struct object *obj;
	char *filename;
	off_t size;
	int fd;

	filename = alloc_shared_str(64);
	if (filename == NULL)
		return false;

	snprintf(filename, 64, "trinity-pcro-%u", idx);
	(void)unlink(filename);

	fd = open(filename, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		free_shared_str(filename, 64);
		return false;
	}

	size = (off_t)pagecache_selfseed_sizes[idx];
	if (ftruncate(fd, size) < 0) {
		close(fd);
		(void)unlink(filename);
		free_shared_str(filename, 64);
		return false;
	}
	close(fd);

	fd = open(filename, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
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
	obj->fileobj.flags = O_RDONLY;
	obj->fileobj.fd = fd;
	obj->fileobj.fopened = false;
	obj->fileobj.fcntl_flags = 0;
	obj->fileobj.pagecache_backed = true;
	obj->fileobj.is_setuid = false;

	add_object(obj, OBJ_GLOBAL, OBJ_FD_PAGECACHE);
	return true;
}

static unsigned int pagecache_selfseed(struct objhead *head)
{
	unsigned int i;
	unsigned int opened = 0;

	head->destroy = &pagecache_selfseed_destructor;

	for (i = 0; i < NR_PAGECACHE_SELFSEED_FDS; i++) {
		if (pagecache_selfseed_create_one(i))
			opened++;
	}

	return opened;
}

static int init_pagecache_fds(void)
{
	struct objhead *head;
	unsigned int attempts;
	unsigned int max_attempts;
	unsigned int opened = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PAGECACHE);
	head->destroy = &close_fd_destructor;
	head->dump = &pagecache_dump;

	generate_filelist();

	if (fileindex == NULL || files_in_index == 0) {
		outputerr("init_pagecache_fds: empty fileindex (generate_filelist produced no files)\n");
		fd_provider_init_fail(FD_INIT_REASON_RESOURCE, 0,
				      "empty fileindex");
		return false;
	}

	nr_setuid = 0;

	/* Bounded sample to keep init time predictable on huge fileindexes.
	 * Cap at NR_PAGECACHE_FDS * 32 candidates regardless of fileindex
	 * size — without the ceiling, a million-file index turns init into
	 * a 4M-attempt stall when no regular files match. */
	max_attempts = files_in_index * 4;
	if (max_attempts > NR_PAGECACHE_FDS * 32)
		max_attempts = NR_PAGECACHE_FDS * 32;
	for (attempts = 0;
	     attempts < max_attempts && opened < NR_PAGECACHE_FDS;
	     attempts++) {
		const char *filename = fileindex[rnd_modulo_u32(files_in_index)];
		struct stat sb;
		struct object *obj;
		int fd;
		bool setuid;

		if (lstat(filename, &sb) != 0)
			continue;
		if (!S_ISREG(sb.st_mode))
			continue;

		fd = open(filename, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;

		if (!fs_is_pagecache_backed(fd)) {
			close(fd);
			continue;
		}

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			break;
		}

		setuid = (sb.st_mode & S_ISUID) != 0;

		obj->fileobj.filename = filename;
		obj->fileobj.flags = O_RDONLY;
		obj->fileobj.fd = fd;
		obj->fileobj.fopened = false;
		obj->fileobj.fcntl_flags = 0;
		obj->fileobj.pagecache_backed = true;
		obj->fileobj.is_setuid = setuid;

		add_object(obj, OBJ_GLOBAL, OBJ_FD_PAGECACHE);

		if (setuid && nr_setuid < NR_PAGECACHE_SETUID)
			setuid_indices[nr_setuid++] = opened;

		opened++;
	}

	if (opened == 0) {
		unsigned int seeded;
		int seed_errno;

		output(1, "init_pagecache_fds: fileindex scan yielded no pagecache-backed regular files after %u attempts, self-seeding scratch corpus\n",
			attempts);

		seeded = pagecache_selfseed(head);
		if (seeded == 0) {
			seed_errno = errno;
			outputerr("init_pagecache_fds: self-seed produced 0/%u scratch files (last errno %d: %s)\n",
				  NR_PAGECACHE_SELFSEED_FDS, seed_errno,
				  strerror(seed_errno));
			fd_provider_init_fail(FD_INIT_REASON_RESOURCE, seed_errno,
					      "self-seed empty");
			return false;
		}

		return true;
	}

	return true;
}

int get_rand_pagecache_fd(void)
{
	struct objhead *head;

	if (objects_empty(OBJ_FD_PAGECACHE) == true)
		return -1;

	/* Setuid bias: when we have at least one setuid file in the pool,
	 * prefer it SETUID_BIAS_PCT% of the time so the consumer sees the
	 * privileged-content code paths more often than the natural
	 * distribution would yield.
	 *
	 * The setuid_indices[] shortcut bypasses get_random_object() and
	 * indexes head->array directly, so the version-check pattern the
	 * random-pick loop below relies on has to be reproduced by hand:
	 * objpool_check() to filter wild / cross-pool / OBJ_NONE reads,
	 * plus a slot_version snapshot and object_slot_alive() recheck to
	 * catch the "same address, same type, recycled identity" case
	 * objpool_check() cannot see (see include/objects.h:606-609).
	 *
	 * Snapshot num_entries / array_capacity / array together before the
	 * bound check and the deref so a sibling value-result syscall whose
	 * buffer aliases this child's objhead can't scribble those fields
	 * between the bound check and the slot deref.  Same TOCTOU shape
	 * the parent-side fixes close in add_object,
	 * get_random_object_versioned, __destroy_object/destroy_objects,
	 * the for_each_obj iterator and __prune_objects. */
	if (nr_setuid > 0 && (int)rnd_modulo_u32(100) < SETUID_BIAS_PCT) {
		unsigned int slot = setuid_indices[rnd_modulo_u32(nr_setuid)];

		head = get_objhead(OBJ_GLOBAL, OBJ_FD_PAGECACHE);
		if (head != NULL && slot < head->num_entries &&
		    head->array != NULL && head->array[slot] != NULL) {
			struct object *obj = head->array[slot];
			unsigned int captured;
			int fd;

			/* Layered defense mirroring get_rand_socketinfo() in
			 * fds/sockets.c: objpool_check() filters wild VAs,
			 * cross-pool pointers written by a sibling stomp,
			 * and recycled chunks reading OBJ_NONE; the
			 * slot_version snapshot below plus the
			 * object_slot_alive() recheck just before return
			 * catches the recycled-identity race where the
			 * setuid slot is destroyed and re-added under a
			 * fresh obj between the bound check and the
			 * caller's later use of the returned fd.  Capture
			 * the version before reading fileobj.fd so a
			 * mid-deref destroy shows up as a version mismatch
			 * and the possibly stale fd value is discarded. */
			if (objpool_check(obj, OBJ_FD_PAGECACHE)) {
				captured = obj->slot_version;
				fd = obj->fileobj.fd;
				if (fd >= 0 &&
				    object_slot_alive(obj, captured))
					return fd;
			}
			/* fall through to the unbiased random-pick loop
			 * rather than returning -1 on a bias miss so the
			 * caller still gets a fd for this iteration. */
		}
	}

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->fileobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of the
	 * pagecache fd routed into mmap/read/write, the parent can destroy
	 * the obj; release_obj() zeroes the chunk and routes it through
	 * deferred-free, so the stale slot pointer can read a zeroed or
	 * recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_PAGECACHE, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_PAGECACHE))
			continue;

		fd = obj->fileobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider pagecache_fd_provider = {
	.name = "pagecache",
	.objtype = OBJ_FD_PAGECACHE,
	.enabled = true,
	.init = &init_pagecache_fds,
	.get = &get_rand_pagecache_fd,
};

REG_FD_PROV(pagecache_fd_provider);
