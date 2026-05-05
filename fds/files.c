#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "exit.h"
#include "fd.h"
#include "files.h"
#include "objects.h"
#include "pathnames.h"
#include "random.h"
#include "syscalls/syscalls.h"
#include "utils.h"

int open_with_fopen(const char *filename, int flags)
{
	FILE *file;
	int fd = -1;
	char mode[3]="   ";

	switch (flags) {
	case O_RDONLY:  mode[0] = 'r';
			mode[1] = 0;
			break;
	case O_WRONLY:  mode[0] = 'w';
			mode[1] = 0;
			break;
	case O_RDWR:    mode[0] = 'w';
			mode[1] = '+';
			mode[2] = 0;
			break;
	}

	file = fopen(filename, mode);
	if (file) {
		fd = dup(fileno(file));
		fclose(file);
	}

	return fd;
}

static int open_file(struct object *obj, const char *filename, int flags)
{
	int fd;
	int tries = 0;
	int randflags = 0;

	obj->fileobj.filename = filename;
	obj->fileobj.pagecache_backed = false;
	obj->fileobj.is_setuid = false;
	obj->fileobj.fopened = false;
	obj->fileobj.fcntl_flags = 0;

	/* OR in some random flags. */
retry_flags:

	randflags = get_o_flags();
	obj->fileobj.flags = flags | randflags;
	fd = open(filename, flags | randflags | O_NONBLOCK, 0666);

	if (fd < 0) {
		/*
		 * if we failed to open the file, retry with different flags.
		 * we should eventually succeed, but set an arbitary upper limit of
		 * 50 tries before just giving up.
		 */
		tries++;
		if (tries == 50) {
			output(2, "Couldn't open %s : %s\n", filename, strerror(errno));
			return fd;
		}
		goto retry_flags;
	}

	return fd;
}

static void filefd_destructor(struct object *obj)
{
	close(obj->fileobj.fd);
}

static void filefd_dump(struct object *obj, enum obj_scope scope)
{
	struct fileobj *fo = &obj->fileobj;

	output(2, "file fd:%d filename:%s flags:%x fopened:%d fcntl_flags:%x scope:%d\n",
		fo->fd, fo->filename, fo->flags, fo->fopened, fo->fcntl_flags, scope);
}

/*
 * Per-pool provider: open files from a specific pathname pool.
 */
int open_pool_files(unsigned int pool_id, enum objecttype objtype)
{
	struct objhead *head;
	unsigned int i, nr_to_open, pool_count;

	head = get_objhead(OBJ_GLOBAL, objtype);
	head->destroy = &filefd_destructor;
	head->dump = &filefd_dump;
	head->shared_alloc = true;

	generate_filelist();

	pool_count = get_pool_file_count(pool_id);
	if (pool_count == 0)
		return false;

	nr_to_open = min(pool_count, NR_FILE_FDS / 3);

	if (fileindex == NULL)	/* this can happen if we ctrl-c'd */
		return false;

	for (i = 0; i < nr_to_open; i++) {
		struct stat sb;
		const char *filename;
		struct object *obj;
		int fd = -1;
		int flags;

		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL)
			break;

		do {
			int ret;

			filename = get_filename_for_pool(pool_id);
			if (filename == NULL)
				break;

			ret = lstat(filename, &sb);
			if (ret == -1)
				continue;

			flags = check_stat_file(&sb);
			if (flags == -1)
				continue;

			fd = open_file(obj, filename, flags);
		} while (fd == -1);

		if (fd == -1) {
			free_shared_obj(obj, sizeof(struct object));
			break;
		}

		obj->fileobj.fd = fd;
		add_object(obj, OBJ_GLOBAL, objtype);

		/* convert O_ open flags to mmap prot flags */
		switch (flags) {
		case O_RDONLY:
			flags = PROT_READ;
			break;
		case O_WRONLY:
			flags = PROT_WRITE;
			break;
		case O_RDWR:
			flags = PROT_READ|PROT_WRITE;
			break;
		default:
			break;
		}

		mmap_fd(fd, filename, sb.st_size, flags, OBJ_GLOBAL, OBJ_MMAP_FILE);
	}
	return true;
}

int get_rand_pool_fd(enum objecttype objtype)
{
	if (objects_empty(objtype) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->fileobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of the
	 * returned fd, the parent can destroy the obj, free_shared_obj()
	 * returns the chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 *
	 * Shared helper for procfs/sysfs/devfs (and any other file-pool
	 * fd_provider whose .get points at this function); covers all
	 * three providers with a single wireup.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(objtype, OBJ_GLOBAL,
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
			outputerr("get_rand_pool_fd: bogus obj %p in "
				  "objtype=%d pool\n", obj, objtype);
			continue;
		}

		if (!validate_object_handle(objtype, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->fileobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

int open_pool_fd(unsigned int pool_id, enum objecttype objtype)
{
	struct object *obj;
	const char *filename;
	struct stat sb;
	int fd, flags, tries;

	if (fileindex == NULL)
		return false;

	for (tries = 0; tries < 10; tries++) {
		filename = get_filename_for_pool(pool_id);
		if (filename == NULL)
			return false;
		if (lstat(filename, &sb) == -1)
			continue;
		flags = check_stat_file(&sb);
		if (flags == -1)
			continue;

		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL)
			return false;
		fd = open_file(obj, filename, flags);
		if (fd == -1) {
			free_shared_obj(obj, sizeof(struct object));
			continue;
		}

		obj->fileobj.fd = fd;
		add_object(obj, OBJ_GLOBAL, objtype);
		return true;
	}
	return false;
}

