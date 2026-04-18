#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "debug.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Use this allocator if you have an object a child writes to that you want
 * all other processes to see.
 *
 * Every allocation is tracked so that VM syscalls (munmap, madvise, mremap,
 * mprotect) can avoid clobbering trinity's own shared state.
 */

#define MAX_SHARED_ALLOCS 512

static struct {
	unsigned long addr;
	unsigned long size;
	bool is_global_obj;
} shared_regions[MAX_SHARED_ALLOCS];
static unsigned int nr_shared_regions;

static void * __alloc_shared(unsigned int size, bool is_global_obj)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED) {
		outputerr("mmap %u failure\n", size);
		exit(EXIT_FAILURE);
	}
	/* poison, to force users to set it to something sensible. */
	memset(ret, rand(), size);

	if (nr_shared_regions < MAX_SHARED_ALLOCS) {
		shared_regions[nr_shared_regions].addr = (unsigned long) ret;
		shared_regions[nr_shared_regions].size = size;
		shared_regions[nr_shared_regions].is_global_obj = is_global_obj;
		nr_shared_regions++;
	} else {
		outputerr("alloc_shared: MAX_SHARED_ALLOCS (%d) reached, "
			"region %p won't be tracked by range_overlaps_shared()\n",
			MAX_SHARED_ALLOCS, ret);
	}

	return ret;
}

void * alloc_shared(unsigned int size)
{
	return __alloc_shared(size, false);
}

/*
 * Allocate shared memory for global object data (list heads, parallel
 * arrays, etc.).  Tagged so freeze_global_objects() can mprotect just
 * these regions PROT_READ once init is done — children that stray-write
 * into the global object pool then SIGSEGV at the source instead of
 * silently corrupting list pointers.
 */
void * alloc_shared_global(unsigned int size)
{
	return __alloc_shared(size, true);
}

static void mprotect_global_obj_regions(int prot)
{
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		if (!shared_regions[i].is_global_obj)
			continue;
		if (mprotect((void *) shared_regions[i].addr,
			     shared_regions[i].size, prot) != 0) {
			outputerr("mprotect_global_obj_regions: failed for %p (%lu bytes, prot=%d): %s\n",
				  (void *) shared_regions[i].addr,
				  shared_regions[i].size, prot,
				  strerror(errno));
		}
	}
}

void freeze_global_objects(void)
{
	mprotect_global_obj_regions(PROT_READ);
}

void thaw_global_objects(void)
{
	mprotect_global_obj_regions(PROT_READ | PROT_WRITE);
}

bool range_overlaps_shared(unsigned long addr, unsigned long len)
{
	unsigned long end = addr + len;
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		unsigned long r_start = shared_regions[i].addr;
		unsigned long r_end = r_start + shared_regions[i].size;

		if (addr < r_end && end > r_start)
			return true;
	}
	return false;
}

void * __zmalloc(size_t size, const char *func)
{
	void *p;

	p = malloc(size);
	if (p == NULL) {
		/* Maybe we mlockall'd everything. Try and undo that, and retry. */
		munlockall();
		p = malloc(size);
		if (p != NULL)
			goto done;

		outputerr("%s: malloc(%zu) failure.\n", func, size);
		exit(EXIT_FAILURE);
	}

done:
	memset(p, 0, size);
	return p;
}

void sizeunit(unsigned long size, char *buf, size_t buflen)
{
	/* non kilobyte aligned size? */
	if (size < 1024) {
		snprintf(buf, buflen, "%lu bytes", size);
		return;
	}

	/* < 1MB ? */
	if (size < (1024 * 1024)) {
		snprintf(buf, buflen, "%luKB", size / 1024);
		return;
	}

	/* < 1GB ? */
	if (size < (1024 * 1024 * 1024)) {
		snprintf(buf, buflen, "%luMB", (size / 1024) / 1024);
		return;
	}

	snprintf(buf, buflen, "%luGB", ((size / 1024) / 1024) / 1024);
}

void kill_pid(pid_t pid)
{
	int ret;
	int childno;

	if (pid == -1) {
		show_backtrace();
		syslogf("kill_pid tried to kill -1!\n");
		return;
	}
	if (pid == 0) {
		show_backtrace();
		syslogf("tried to kill_pid 0!\n");
		return;
	}

	childno = find_childno(pid);
	if (childno != CHILD_NOT_FOUND) {
		if (children[childno]->dontkillme == true)
			return;
	}

	ret = kill(pid, SIGKILL);
	if (ret != 0)
		debugf("couldn't kill pid %d [%s]\n", pid, strerror(errno));
}

void freeptr(unsigned long *p)
{
	void *ptr = (void *) *p;

	if (ptr != NULL)
		free(ptr);
	*p = 0L;
}

int get_num_fds(void)
{
	struct linux_dirent64 {
		uint64_t       d_ino;
		int64_t        d_off;
		unsigned short d_reclen;
		unsigned char  d_type;
		char           d_name[];
	};
	char path[64];
	char buf[4096];
	int fd, fd_count = 0;
	long nread, pos;

	snprintf(path, sizeof(path), "/proc/%i/fd", mainpid);

	fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd == -1)
		return 0;

	while ((nread = syscall(SYS_getdents64, fd, buf, sizeof(buf))) > 0) {
		for (pos = 0; pos < nread; ) {
			struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + pos);
			const char *name = de->d_name;

			/* Skip "." and ".." */
			if (!(name[0] == '.' &&
			      (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0'))))
				fd_count++;

			pos += de->d_reclen;
		}
	}

	close(fd);
	return fd_count;
}
