#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fd.h"
#include "files.h"
#include "log.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscalls/syscalls.h"
#include "testfile.h"
#include "utils.h"

#define MAX_TESTFILES 4
#define MAX_TESTFILE_FDS 20

static void testfile_destructor(struct object *obj)
{
	close(obj->testfilefd);
}

static int open_testfile(char *filename)
{
	struct objhead *head;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TESTFILE);
	head->destroy = &testfile_destructor;

	/* file might be around from an earlier run, nuke it. */
	(void) unlink(filename);

	if (RAND_BOOL()) {
		fd = open_with_fopen(filename, O_RDWR);
		if (fd != -1) {
			output(2, "fd[%d] = fopen(\"%s\", O_RDWR)\n", fd, filename);
			(void) fcntl(fd, F_SETFL, random_fcntl_setfl_flags());
		}
	} else {
		const unsigned long open_flags[] = { O_DIRECT, O_DSYNC, O_SYNC, };
		int flags = 0;

		flags = set_rand_bitmask(ARRAY_SIZE(open_flags), open_flags);;

		fd = open(filename, O_CREAT | flags, 0666);
		if (fd != -1)
			output(2, "fd[%d] = open(\"%s\", flags:%x)\n", fd, filename, flags);	//TODO: decode flags
	}

	return fd;
}

static int open_testfile_fds(void)
{
	char *filename;
	unsigned int i = 1, nr = 0;
	unsigned int fails = 0;

	filename = zmalloc(64);

	while (nr < MAX_TESTFILE_FDS) {
		int fd;

		sprintf(filename, "trinity-testfile%u", i);

		fd = open_testfile(filename);
		if (fd != -1) {
			struct object *obj;

			obj = alloc_object();
			obj->testfilefd = fd;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_TESTFILE);

			i++;
			if (i > MAX_TESTFILES)
				i = 1;
			nr++;

			fails = 0;

			mmap_fd(fd, filename, page_size, PROT_READ|PROT_WRITE, OBJ_GLOBAL, OBJ_MMAP_TESTFILE);

		} else {
			fails++;
			if (fails == 100) {
				output(2, "testfile creation is failing a lot. last error:%s\n", strerror(errno));
			}
		}
	}

	dump_objects(OBJ_GLOBAL, OBJ_MMAP_TESTFILE);

	free(filename);
	return TRUE;
}

int get_rand_testfile_fd(void)
{
	struct object *obj;

	/* check if testfilefd's unavailable/disabled. */
	if (objects_empty(OBJ_FD_TESTFILE) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_TESTFILE, OBJ_GLOBAL);
	return obj->testfilefd;
}

static const struct fd_provider testfile_fd_provider = {
	.name = "testfile",
	.enabled = TRUE,
	.open = &open_testfile_fds,
	.get = &get_rand_testfile_fd,
};

REG_FD_PROV(testfile_fd_provider);
