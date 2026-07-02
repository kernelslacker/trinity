#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "breadcrumb_ring.h"
#include "child.h"
#include "debug.h"
#include "deferred-free.h"
#include "locks.h"
#include "objects.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "signals.h"	// asb_copy_recover / asb_copy_active snapshot-copy guard
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"



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

	/*
	 * Refuse to SIGKILL ourselves.  A wrapper run was observed dying
	 * with mainpid SIGKILL'ing mainpid; bpftrace on signal_generate
	 * confirmed the kill syscall came from main itself.  The path is
	 * shm corruption scribbling mainpid into a pids[] slot, then a
	 * reap/kill loop walking pids[] and feeding that value back in
	 * here.  pid_is_valid() accepts mainpid as in-range, so without
	 * this guard main commits suicide.
	 *
	 * Scan pids[] first so the diagnostic line names the scribbled
	 * slot, then dump childnos + the pids page state so we can tell
	 * whether this was a single wild write or a page-level event.
	 */
	if (pid == mainpid) {
		unsigned int i;
		int corrupt_slot = -1;

		for_each_child(i) {
			pid_t slot = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
			if (slot == mainpid) {
				corrupt_slot = i;
				break;
			}
		}

		if (corrupt_slot == -1)
			syslogf("kill_pid refused: pid=%d == mainpid=%d, pids[] slot=none\n",
				pid, mainpid);
		else
			syslogf("kill_pid refused: pid=%d == mainpid=%d, pids[] slot=%d\n",
				pid, mainpid, corrupt_slot);

		show_backtrace();
		dump_childnos();
		dump_pids_page_state();
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


bool range_readable_user(const void *addr, size_t len)
{
	unsigned long a = (unsigned long) addr;

	if (len == 0)
		return false;
	if (addr == NULL)
		return false;
	if (a > ULONG_MAX - len)
		return false;

	/*
	 * Fast path 1: range is fully inside a tracked shared region.
	 * Trinity owns those mappings outright -- alloc_shared() creates
	 * them PROT_READ|PROT_WRITE and they live for the run, so VMA
	 * presence implies the source bytes are readable.
	 */
	if (range_in_tracked_shared(a, len))
		return true;

	/*
	 * Fast path 2: range is fully inside the cached libc heap (brk
	 * arena) or any captured non-brk allocator region.  Allocator
	 * mappings are PROT_READ|PROT_WRITE by construction; the
	 * heap_bounds_init() snapshot only records writable private VMAs.
	 */
	if (range_inside_libc_heap(a, len))
		return true;

	/*
	 * Unknown layout: a fuzz-introduced VMA outside every cached
	 * snapshot.  Treat as unproven and let the caller route to
	 * asb_relocate()'s no-copy fallback -- chasing the source via a
	 * /proc/self/maps walk on every hot-path call is what this code
	 * was retired to avoid.
	 */
	return false;
}

bool post_snapshot_str(char *dst, size_t dstsz, const char *src)
{
	size_t i;

	if (dst == NULL || dstsz == 0)
		return false;
	if (src == NULL)
		return false;

	/*
	 * Single-probe readability gate.  range_readable_user proves the
	 * full dstsz-byte window of src is mapped (tracked-shared region
	 * or cached libc heap); the copy loop below then never reads past
	 * what we proved.  False here means src is not provably readable
	 * and the caller skips the .post sample rather than feeding a
	 * stale heap-shaped pointer into a downstream strncpy that would
	 * walk off an unrelated allocation.  ASAN catches that walk-off in
	 * test; in production it silently surfaces as an oracle anomaly
	 * against a foreign byte pattern.
	 */
	if (!range_readable_user(src, dstsz))
		return false;

	/*
	 * Same TOCTOU window as post_snapshot_or_skip: a sibling
	 * mprotect/munmap between the readability proof and the read can
	 * fault the src[i] load.  Guard the copy loop with the
	 * asb_copy_active sigsetjmp slot so the fault degrades to a
	 * skipped sample rather than a child crash.
	 */
	if (sigsetjmp(asb_copy_recover, 1) != 0) {
		asb_copy_active = 0;
		return false;
	}
	asb_copy_active = 1;
	for (i = 0; i + 1 < dstsz; i++) {
		char c = src[i];

		dst[i] = c;
		if (c == '\0') {
			asb_copy_active = 0;
			return true;
		}
	}
	dst[i] = '\0';
	asb_copy_active = 0;
	return true;
}

bool post_snapshot_or_skip(void *dst, const void *src, size_t len)
{
	if (src == NULL)
		return false;

	/*
	 * Single-probe readability gate, identical in shape to the one
	 * in post_snapshot_str().  The post oracle's NULL + shape-only
	 * looks_like_corrupted_ptr guard waves through a heap-shaped but
	 * stale/unmapped snap->field; range_readable_user proves the
	 * full len-byte window is mapped (tracked-shared region or
	 * cached libc heap), so the memcpy below cannot fault on the
	 * sibling free / unmap / fuzz-redirect window between the
	 * syscall return and the post sample.  False here means the
	 * caller skips the .post sample rather than feeding the
	 * downstream oracle a foreign byte pattern.
	 */
	if (!range_readable_user(src, len))
		return false;

	/*
	 * range_readable_user() proves src is mapped per trinity's
	 * shared/heap bookkeeping, but a sibling syscall can mprotect or
	 * munmap the tracked region in the window between that check and
	 * this copy.  Guard the memcpy with the asb_copy_active sigsetjmp
	 * slot (the same recovery the get_writable_struct relocate-copy
	 * uses) so a TOCTOU fault skips the .post sample instead of
	 * killing the child.
	 */
	if (sigsetjmp(asb_copy_recover, 1) != 0) {
		asb_copy_active = 0;
		return false;
	}
	asb_copy_active = 1;
	memcpy(dst, src, len);
	asb_copy_active = 0;
	return true;
}

void sanitize_inherited_fds(void)
{
	DIR *dir;
	struct dirent *de;
	int dir_fd;

	dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		outputerr("sanitize_inherited_fds: opendir(/proc/self/fd) failed: %s\n",
			  strerror(errno));
		return;
	}
	dir_fd = dirfd(dir);

	while ((de = readdir(dir)) != NULL) {
		char linkpath[64];
		char target[PATH_MAX];
		char *endp;
		ssize_t n;
		long fdl;
		int fd;

		if (de->d_name[0] == '.')
			continue;

		errno = 0;
		fdl = strtol(de->d_name, &endp, 10);
		if (errno != 0 || *endp != '\0' || fdl < 0 || fdl > INT_MAX)
			continue;
		fd = (int) fdl;

		/* Always keep stdin/stdout/stderr. */
		if (fd <= 2)
			continue;

		/* Skip the readdir() handle itself; closedir() will release
		 * it once the walk completes. */
		if (fd == dir_fd)
			continue;

		n = -1;
		if ((size_t) snprintf(linkpath, sizeof(linkpath),
				      "/proc/self/fd/%d", fd) < sizeof(linkpath))
			n = readlink(linkpath, target, sizeof(target) - 1);
		if (n < 0)
			n = 0;
		target[n] = '\0';

		outputerr("sanitize_inherited_fds: closing unexpected inherited fd %d (%s)\n",
			  fd, n > 0 ? target : "?");

		close(fd);
		if (shm != NULL)
			__atomic_add_fetch(&shm->stats.parent_inherited_fds_closed,
					   1, __ATOMIC_RELAXED);
	}
	closedir(dir);
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

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Shared by every
 * persistence format trinity emits (minicorpus / cmp_hints /
 * kcov-bitmap) so the headers checksum payloads with one definition
 * instead of byte-identical copies that drift apart silently.  Lazy
 * 256-entry table; first call pays one build, every subsequent call
 * (in any caller) reuses the cached table. */
uint32_t crc32(const void *buf, size_t len)
{
	static uint32_t table[256];
	static bool table_built;
	const uint8_t *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;

	if (!table_built) {
		uint32_t c;
		unsigned int n, k;

		for (n = 0; n < 256; n++) {
			c = n;
			for (k = 0; k < 8; k++)
				c = (c & 1) ? (0xedb88320U ^ (c >> 1)) : (c >> 1);
			table[n] = c;
		}
		table_built = true;
	}

	for (i = 0; i < len; i++)
		crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);

	return crc ^ 0xffffffffU;
}

/*
 * Online-CPU count snapshotted on first use.  The kernel rejects
 * sched_setaffinity masks with no bits in cpu_online_mask, so a
 * random CPU_SETSIZE-wide draw misses every legality test path
 * unless we constrain it to the real online range.
 */
unsigned int cached_online_cpus(void)
{
	static unsigned int n;
	long v;

	if (n != 0)
		return n;

	v = sysconf(_SC_NPROCESSORS_ONLN);
	if (v <= 0)
		v = 1;
	if (v > CPU_SETSIZE)
		v = CPU_SETSIZE;
	n = (unsigned int) v;
	return n;
}
