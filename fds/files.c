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
	if (file)
		fd = fileno(file);

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
		obj->fileobj.fopened = FALSE;
		obj->fileobj.fcntl_flags = 0;
	} else {
		fd = open_with_fopen(filename, flags);
		obj->fileobj.fopened = TRUE;
		obj->fileobj.flags = flags;

		fcntl_flags = random_fcntl_setfl_flags();
		fcntl(fd, F_SETFL, fcntl_flags);
		obj->fileobj.fcntl_flags = fcntl_flags;
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

static void filefd_dump(struct object *obj, bool global)
{
	struct fileobj *fo = &obj->fileobj;

	output(2, "file fd:%d filename:%s flags:%x fopened:%d fcntl_flags:%x global:%d\n",
		fo->fd, fo->filename, fo->flags, fo->fopened, fo->fcntl_flags, global);
}

static int open_files(void)
{
	struct objhead *head;
	unsigned int i, nr_to_open;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_FILE);
	head->destroy = &filefd_destructor;
	head->dump = &filefd_dump;

	generate_filelist();

	if (files_in_index == 0) {
		/* Something bad happened. Crappy -V maybe? */
		panic(EXIT_NO_FILES);
		return FALSE;
	}

	nr_to_open = min(files_in_index, NR_FILE_FDS);

	if (fileindex == NULL)	/* this can happen if we ctrl-c'd */
		return FALSE;

	for (i = 0; i < nr_to_open; i++) {
		struct stat sb;
		const char *filename;
		struct object *obj = alloc_object();
		int fd = -1;
		int flags;

		do {
			int ret;

			filename = get_filename();

			ret = lstat(filename, &sb);
			if (ret == -1)
				continue;

			flags = check_stat_file(&sb);
			if (flags == -1)
				continue;

			fd = open_file(obj, filename, flags);
		} while (fd == -1);

		obj->fileobj.fd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_FILE);

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
	return TRUE;
}

static int get_rand_file_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_FILE) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_FILE, OBJ_GLOBAL);
	return obj->fileobj.fd;
}

static const struct fd_provider file_fd_provider = {
	.name = "pseudo",	// FIXME: Use separate providers for dev/sysfs/procfs
	.enabled = TRUE,
	.open = &open_files,
	.get = &get_rand_file_fd,
};

REG_FD_PROV(file_fd_provider);
