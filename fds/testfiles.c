#include <errno.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "deferred-free.h"
#include "fd.h"
#include "files.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
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
		obj->testfileobj.flags = O_CREAT | O_RDWR | flags;
		fd = open(filename, O_CREAT | O_RDWR | flags, 0666);
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
			obj = alloc_object();
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
			obj->testfileobj.filename = NULL;
			fails++;
			if (fails == 100) {
				output(2, "testfile creation is failing a lot. last error:%s\n", strerror(errno));
				break;
			}
		}
	}

	if (obj != NULL)
		tracked_free_now(obj);

	return true;
}

int get_rand_testfile_fd(void)
{
	if (objects_empty(OBJ_FD_TESTFILE) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->testfileobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the testfile fd handed to filesystem syscalls via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_TESTFILE, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_TESTFILE))
			continue;

		fd = obj->testfileobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

void invalidate_testfile_mmaps_for_index(unsigned int index)
{
	char target[32];
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	/*
	 * The pathname-pinning sanitiser passes a 1-based index in the
	 * range it chose its target from -- silently ignore anything
	 * outside that range so callers can hand us the snap field
	 * unconditionally without bracketing the call.
	 */
	if (index == 0 || index > MAX_TESTFILES)
		return;

	/*
	 * Rebuild the basename the sanitiser pinned the pathname to.
	 * fds/testfiles.c records each fd's basename (not the absolute
	 * path) on obj->testfileobj.filename, so we match against the
	 * basename form here.  open_testfile_fds() rotates MAX_TESTFILE_FDS
	 * fds across MAX_TESTFILES distinct inodes, so multiple OBJ_FD_TESTFILE
	 * entries may match a single basename; walk every match and
	 * dispatch a per-fd invalidate.
	 */
	snprintf(target, sizeof(target), "trinity-testfile%u", index);

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TESTFILE);
	if (head == NULL || head->array == NULL)
		return;

	for_each_obj(head, obj, idx) {
		if (!objpool_check(obj, OBJ_FD_TESTFILE))
			continue;
		if (obj->testfileobj.filename == NULL)
			continue;
		if (strcmp(obj->testfileobj.filename, target) != 0)
			continue;
		if (obj->testfileobj.fd < 0)
			continue;
		invalidate_obj_mmap_by_fd(obj->testfileobj.fd);
	}
}

static const struct fd_provider testfile_fd_provider = {
	.name = "testfile",
	.objtype = OBJ_FD_TESTFILE,
	.enabled = true,
	.init = &open_testfile_fds,
	.get = &get_rand_testfile_fd,
};

REG_FD_PROV(testfile_fd_provider);
