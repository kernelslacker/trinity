#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
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
#include "utils.h"

/*
 * Use this allocator if you have an object a child writes to that you want
 * all other processes to see.
 *
 * Every allocation is tracked so that VM syscalls (munmap, madvise, mremap,
 * mprotect) can avoid clobbering trinity's own shared state.
 */

#define MAX_SHARED_ALLOCS 128

static struct {
	unsigned long addr;
	unsigned long size;
} shared_regions[MAX_SHARED_ALLOCS];
static unsigned int nr_shared_regions;

void * alloc_shared(unsigned int size)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED) {
		printf("mmap %u failure\n", size);
		exit(EXIT_FAILURE);
	}
	/* poison, to force users to set it to something sensible. */
	memset(ret, rand(), size);

	if (nr_shared_regions < MAX_SHARED_ALLOCS) {
		shared_regions[nr_shared_regions].addr = (unsigned long) ret;
		shared_regions[nr_shared_regions].size = size;
		nr_shared_regions++;
	}

	return ret;
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

		printf("%s: malloc(%zu) failure.\n", func, size);
		exit(EXIT_FAILURE);
	}

done:
	memset(p, 0, size);
	return p;
}

void sizeunit(unsigned long size, char *buf)
{
	/* non kilobyte aligned size? */
	if (size < 1024) {
		sprintf(buf, "%lu bytes", size);
		return;
	}

	/* < 1MB ? */
	if (size < (1024 * 1024)) {
		sprintf(buf, "%luKB", size / 1024);
		return;
	}

	/* < 1GB ? */
	if (size < (1024 * 1024 * 1024)) {
		sprintf(buf, "%luMB", (size / 1024) / 1024);
		return;
	}

	sprintf(buf, "%luGB", ((size / 1024) / 1024) / 1024);
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
		if (shm->children[childno]->dontkillme == true)
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
     int fd_count;
     char buf[64];
     struct dirent *dp;

     snprintf(buf, 64, "/proc/%i/fd/", mainpid);

     fd_count = 0;
     DIR *dir = opendir(buf);
     if (dir == NULL)
          return 0;
     while ((dp = readdir(dir)) != NULL) {
          fd_count++;
     }
     closedir(dir);
     return fd_count;
}
