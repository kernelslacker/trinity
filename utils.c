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
	/* poison with independently-random bytes to expose uninitialized reads. */
	{
		unsigned char *p = ret;
		size_t i;

		for (i = 0; i + sizeof(unsigned int) <= size; i += sizeof(unsigned int)) {
			unsigned int r = rand32();
			memcpy(p + i, &r, sizeof(r));
		}
		for (; i < size; i++)
			p[i] = (unsigned char)rand();
	}

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

/*
 * Shared obj heap — backing store for individual obj structs that need
 * to be readable from any process.
 *
 * Why a pre-allocated pool instead of one mmap per object?  An
 * mmap(MAP_SHARED|MAP_ANON) issued post-fork by the parent creates a
 * fresh tmpfs-backed mapping that already-forked children have no
 * page-table entry for; following the pointer SIGSEGVs in the child.
 * The only way a single allocator can serve both pre-fork init AND
 * post-fork regen with cross-process visibility is to map the backing
 * region once before any child forks, then carve allocations out of
 * that region.  Children inherit the mapping at fork time and see
 * subsequent parent writes via ordinary shared-memory semantics.
 *
 * The backing region is allocated with alloc_shared() (not
 * alloc_shared_global) — alloc_shared_global tags the region for
 * mprotect(PROT_READ) at freeze time, which would block the regen
 * path's writes.  We accept losing the freeze-time defence on the
 * obj heap; the existing shm->global_objects array (still
 * alloc_shared_global) is what catches stray child writes that
 * scribble into the parallel pointer array.
 *
 * Size: 4 MiB at ~150 B per struct object gives ~28k slots — far
 * larger than GLOBAL_OBJ_MAX_CAPACITY (1024) per type even if every
 * type were converted, with headroom for the bump-and-leak free
 * strategy below.  Real recycling can come later if exhaustion
 * becomes observable in long fuzz runs.
 *
 * free_shared_obj() does NOT recycle.  A freelist or slab recycler is
 * a deliberate non-goal here: fd lifecycle is rare relative to syscall
 * arg generation, throughput pressure is on the latter, and the
 * simplest free that preserves the "zeroed on alloc" invariant is to
 * just zero the slot and leak it.
 */
#define SHARED_OBJ_HEAP_SIZE (4U * 1024U * 1024U)

static char *shared_obj_heap;
static size_t shared_obj_heap_capacity;

static void shared_obj_heap_init(void)
{
	/*
	 * First call must come from the parent before any child forks,
	 * otherwise the mapping won't be in the child's address space.
	 * In practice the first caller is an init_*_fds() function
	 * driven by open_fds(), which runs before fork_children().
	 * We keep the lazy-init form (instead of an explicit hook in
	 * init_shm) because it keeps the contract local to this file.
	 */
	shared_obj_heap_capacity = SHARED_OBJ_HEAP_SIZE;
	shared_obj_heap = alloc_shared(shared_obj_heap_capacity);
}

void * alloc_shared_obj(size_t size)
{
	size_t old_used, new_used;
	void *p;

	if (size == 0)
		return NULL;

	if (shared_obj_heap == NULL)
		shared_obj_heap_init();

	/* Round up so each allocation starts pointer-aligned. */
	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	/*
	 * Lock-free bump via CAS.  shm->shared_obj_heap_used lives in
	 * the SHM region, so concurrent allocators in any process see a
	 * single source of truth.  RELAXED ordering is enough: the
	 * returned pointer's contents are published downstream by the
	 * caller's add_object() RELEASE-store on num_entries, and that
	 * is what synchronises with consumers in get_random_object().
	 */
	old_used = __atomic_load_n(&shm->shared_obj_heap_used,
				   __ATOMIC_RELAXED);
	do {
		new_used = old_used + size;
		if (new_used > shared_obj_heap_capacity) {
			outputerr("alloc_shared_obj: heap exhausted "
				  "(cap %zu, used %zu, req %zu)\n",
				  shared_obj_heap_capacity, old_used,
				  size);
			return NULL;
		}
	} while (!__atomic_compare_exchange_n(&shm->shared_obj_heap_used,
					      &old_used, new_used,
					      false,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));

	p = shared_obj_heap + old_used;
	memset(p, 0, size);
	return p;
}

void free_shared_obj(void *p, size_t size)
{
	if (p == NULL || size == 0)
		return;

	/* Poison-on-free: zero the slot so a use-after-free reads as
	 * obvious garbage (NULL pointers, zero counts) instead of a
	 * stale obj that looks live.  No recycling — the slot is just
	 * leaked.  See the design note above SHARED_OBJ_HEAP_SIZE. */
	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
	memset(p, 0, size);
}

static bool global_objects_protected;

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
	global_objects_protected = true;
}

void thaw_global_objects(void)
{
	mprotect_global_obj_regions(PROT_READ | PROT_WRITE);
	global_objects_protected = false;
}

bool globals_are_protected(void)
{
	return global_objects_protected;
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
