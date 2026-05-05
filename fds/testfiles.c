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
	close(obj->testfileobj.fd);
	if (obj->testfileobj.filename != NULL) {
		free_shared_str((void *) obj->testfileobj.filename, 64);
		obj->testfileobj.filename = NULL;
	}
}

static void testfile_dump(struct object *obj, enum obj_scope scope)
{
	struct fileobj *fo = &obj->testfileobj;

	output(2, "testfile fd:%d filename:%s flags:%x fopened:%d fcntl_flags:%x scope:%d\n",
		fo->fd, fo->filename, fo->flags, fo->fopened, fo->fcntl_flags, scope);
}

static int open_testfile(struct object *obj, char *filename)
{
	int fd;

	obj->testfileobj.filename = filename;

	/* file might be around from an earlier run, nuke it. */
	(void) unlink(filename);

	if (RAND_BOOL()) {
		const unsigned long open_flags[] = { O_DIRECT, O_DSYNC, O_SYNC, };
		int flags = 0;

		flags = set_rand_bitmask(ARRAY_SIZE(open_flags), open_flags);
		obj->testfileobj.flags = O_CREAT | flags;
		fd = open(filename, O_CREAT | flags, 0666);
		obj->testfileobj.fopened = false;
		obj->testfileobj.fcntl_flags = 0;
	} else {
		obj->testfileobj.fopened = true;
		obj->testfileobj.flags = O_RDWR;

		fd = open_with_fopen(filename, O_RDWR);
		if (fd != -1) {
			int fcntl_flags;

			fcntl_flags = random_fcntl_setfl_flags();
			(void) fcntl(fd, F_SETFL, fcntl_flags);
			obj->testfileobj.fcntl_flags = fcntl_flags;
		}
	}

	return fd;
}

static int open_testfile_fds(void)
{
	struct objhead *head;
	struct object *obj = NULL;
	unsigned int i = 1, nr = 0;
	unsigned int fails = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TESTFILE);
	head->destroy = &testfile_destructor;
	head->dump = &testfile_dump;
	head->shared_alloc = true;

	while (nr < MAX_TESTFILE_FDS) {
		char *filename;
		int fd;

		filename = alloc_shared_str(64);
		if (filename == NULL) {
			/* shared str heap exhausted — bail out of init.  Caller
			 * has whatever testfiles got created so far; that's
			 * still useful, no need to crash. */
			output(2, "testfile init aborted: shared str heap exhausted at i=%u\n", i);
			break;
		}
		snprintf(filename, 64, "trinity-testfile%u", i);

		if (obj == NULL) {
			obj = alloc_shared_obj(sizeof(struct object));
			if (obj == NULL) {
				free_shared_str(filename, 64);
				fails++;
				if (fails == 100) {
					output(2, "testfile creation is failing a lot. last error:%s\n", strerror(errno));
					break;
				}
				continue;
			}
		}

		fd = open_testfile(obj, filename);
		if (fd != -1) {

			obj->testfileobj.fd = fd;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_TESTFILE);

			i++;
			if (i > MAX_TESTFILES)
				i = 1;
			nr++;

			fails = 0;

			obj = NULL;	// Make it alloc a new one.

			mmap_fd(fd, filename, page_size, PROT_READ|PROT_WRITE, OBJ_GLOBAL, OBJ_MMAP_TESTFILE);

		} else {
			free_shared_str(filename, 64);
			fails++;
			if (fails == 100) {
				output(2, "testfile creation is failing a lot. last error:%s\n", strerror(errno));
				break;
			}
		}
	}

	if (obj != NULL)
		free_shared_obj(obj, sizeof(struct object));

	return true;
}

static int open_testfile_fd(void)
{
	struct object *obj;
	char *filename;
	int fd;

	filename = alloc_shared_str(64);
	if (filename == NULL)
		return false;	/* shared str heap exhausted; skip regen */
	snprintf(filename, 64, "trinity-testfile%d", 1 + (rand() % MAX_TESTFILES));

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		free_shared_str(filename, 64);
		return false;
	}
	fd = open_testfile(obj, filename);
	if (fd == -1) {
		free_shared_str(filename, 64);
		free_shared_obj(obj, sizeof(struct object));
		return false;
	}

	obj->testfileobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_TESTFILE);
	return true;
}

int get_rand_testfile_fd(void)
{
	struct object *obj;

	/* check if testfilefd's unavailable/disabled. */
	if (objects_empty(OBJ_FD_TESTFILE) == true)
		return -1;

	obj = get_random_object(OBJ_FD_TESTFILE, OBJ_GLOBAL);
	if (!obj)
		return -1;
	return obj->testfileobj.fd;
}

static const struct fd_provider testfile_fd_provider = {
	.name = "testfile",
	.objtype = OBJ_FD_TESTFILE,
	.enabled = true,
	.init = &open_testfile_fds,
	.get = &get_rand_testfile_fd,
	.open = &open_testfile_fd,
};

REG_FD_PROV(testfile_fd_provider);
