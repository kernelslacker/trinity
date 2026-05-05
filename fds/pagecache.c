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
 * A parallel small index array of "interesting" objects (currently:
 * setuid binaries) is maintained alongside the per-objhead pool so
 * get_rand_pagecache_fd() can bias picks towards them without scanning
 * the full pool on every call.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>

#include "fd.h"
#include "files.h"
#include "objects.h"
#include "pathnames.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC	0x794c7630
#endif
#ifndef ZFS_SUPER_MAGIC
#define ZFS_SUPER_MAGIC		0x2fc12fc1
#endif

#define NR_PAGECACHE_FDS	64
#define NR_PAGECACHE_SETUID	16
#define SETUID_BIAS_PCT		25

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

static void pagecache_destructor(struct object *obj)
{
	close(obj->fileobj.fd);
}

static void pagecache_dump(struct object *obj, enum obj_scope scope)
{
	struct fileobj *fo = &obj->fileobj;

	output(2, "pagecache fd:%d filename:%s flags:%x setuid:%d scope:%d\n",
		fo->fd, fo->filename, fo->flags, fo->is_setuid, scope);
}

static int init_pagecache_fds(void)
{
	struct objhead *head;
	unsigned int attempts;
	unsigned int opened = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PAGECACHE);
	head->destroy = &pagecache_destructor;
	head->dump = &pagecache_dump;
	head->shared_alloc = true;

	generate_filelist();

	if (fileindex == NULL || files_in_index == 0) {
		outputerr("init_pagecache_fds: empty fileindex (generate_filelist produced no files)\n");
		return false;
	}

	nr_setuid = 0;

	/* Bounded sample to keep init time predictable on huge fileindexes. */
	for (attempts = 0;
	     attempts < files_in_index * 4 && opened < NR_PAGECACHE_FDS;
	     attempts++) {
		const char *filename = fileindex[rand() % files_in_index];
		struct stat sb;
		struct object *obj;
		int fd;
		bool setuid;

		if (lstat(filename, &sb) != 0)
			continue;
		if (!S_ISREG(sb.st_mode))
			continue;

		fd = open(filename, O_RDONLY | O_NONBLOCK);
		if (fd < 0)
			continue;

		if (!fs_is_pagecache_backed(fd)) {
			close(fd);
			continue;
		}

		obj = alloc_shared_obj(sizeof(struct object));
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

	if (opened == 0)
		outputerr("init_pagecache_fds: opened 0 files after %u attempts (no pagecache-backed regular files in fileindex)\n",
			attempts);

	return opened > 0;
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
	 * indexes head->array directly, so it doesn't pick up the
	 * slot-version validation below.  Same UAF class applies (the
	 * setuid slot can be destroyed/recycled out from under the read of
	 * head->array[slot]->fileobj.fd), but reworking the bias path to
	 * round-trip through the versioned API would require teaching it
	 * about specific slots rather than picks, which is out of scope
	 * for the mechanical fd-getter wireup.  Tracked separately. */
	if (nr_setuid > 0 && (int)(rand() % 100) < SETUID_BIAS_PCT) {
		unsigned int slot = setuid_indices[rand() % nr_setuid];

		head = get_objhead(OBJ_GLOBAL, OBJ_FD_PAGECACHE);
		if (head != NULL && slot < head->num_entries &&
		    head->array[slot] != NULL)
			return head->array[slot]->fileobj.fd;
	}

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->fileobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of the
	 * pagecache fd routed into mmap/read/write, the parent can destroy
	 * the obj, free_shared_obj() returns the chunk to the shared-heap
	 * freelist, and a concurrent alloc_shared_obj() recycles it
	 * underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_PAGECACHE, OBJ_GLOBAL,
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
			outputerr("get_rand_pagecache_fd: bogus obj %p in "
				  "OBJ_FD_PAGECACHE pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_PAGECACHE, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
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
