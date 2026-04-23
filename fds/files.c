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
	int fcntl_flags = 0;
	int randflags = 0;

	obj->fileobj.filename = filename;

	/* OR in some random flags. */
retry_flags:

	if (RAND_BOOL()) {
		randflags = get_o_flags();
		obj->fileobj.flags = flags | randflags;
		fd = open(filename, flags | randflags | O_NONBLOCK, 0666);
		obj->fileobj.fopened = false;
		obj->fileobj.fcntl_flags = 0;
	} else {
		fd = open_with_fopen(filename, flags);
		obj->fileobj.fopened = true;
		obj->fileobj.flags = flags;

		fcntl_flags = random_fcntl_setfl_flags();
		if (fd != -1) {
			fcntl(fd, F_SETFL, fcntl_flags);
			obj->fileobj.fcntl_flags = fcntl_flags;
		}
	}

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
	struct object *obj;

	if (objects_empty(objtype) == true)
		return -1;

	obj = get_random_object(objtype, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->fileobj.fd;
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

