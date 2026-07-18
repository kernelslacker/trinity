/*
 * map_shared_stress - exercise MAP_SHARED writeback + coherence paths.
 *
 * The anonymous-mapping pool the syscall path draws from is almost
 * entirely MAP_PRIVATE, so the file-backed shared-writeback,
 * MADV_DONTFORK vs fork COW, and O_APPEND-vs-mmap pagecache-coherence
 * paths stay cold.  This op owns a small backing file for the duration
 * of one invocation and drives three sub-ops against it:
 *
 *   1. Concurrent shared writeback.  mmap a file-backed MAP_SHARED
 *      region; fork a small pair of workers that dirty their assigned
 *      sub-range and msync it back; the parent interleaves its own
 *      writes and an msync sweep across the whole region.  Races
 *      shared-page writeback vs sibling readers/writers on the same
 *      pagecache pages.
 *
 *   2. MAP_SHARED + MADV_DONTFORK vs fork.  mmap two adjacent
 *      MAP_SHARED regions from the same file; MADV_DONTFORK the
 *      first, leave the second inheritable, then fork.  The child
 *      writes only to the inheritable half and _exits; the parent
 *      observes the child's writes through its own mapping after
 *      reap + msync.  Exercises the VM_DONTCOPY vs VM_SHARED fork
 *      inheritance split.
 *
 *   3. MAP_SHARED vs O_APPEND ordering.  Open a second fd against
 *      the backing file with O_APPEND | O_RDWR, write a short payload
 *      through it, then msync + read the mapping to force the shared
 *      pagecache pages the append landed on through the sync path.
 *      Exercises the ordering between write() append-past-i_size and
 *      the shared-writeback walker on the same inode.
 *
 * Self-bounding:
 *   - Backing file is fixed at MAP_SHARED_STRESS_FILE_BYTES (128 KiB),
 *     capped well below anything that could pressure the host page
 *     cache even at fleet scale.
 *   - Outer iter count runs through BUDGETED() with a small base so
 *     adapt_budget can only ever scale within [MIN, MAX] * base.
 *   - Sibling worker count is fixed at MAP_SHARED_STRESS_WORKERS (2)
 *     and every fork is drained with waitpid_eintr before this op
 *     returns.
 *   - Backing file lives under $TMPDIR (falling back to /tmp) with a
 *     unique per-invocation name; unlinked immediately after open so
 *     an abort cannot leak files.
 *   - If the initial file create/mmap probe fails, latch
 *     unsupported=true and no-op on every subsequent call, mirroring
 *     the sibling childops' unsupported-latch pattern.
 *
 * No libc rand(): the sub-op pick, worker payload byte, and stride
 * jitter all route through rnd_u32 / rnd_modulo_u32 from include/rnd.h.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define MAP_SHARED_STRESS_FILE_BYTES	(128UL << 10)	/* 128 KiB */
#define MAP_SHARED_STRESS_ITERS_BASE	16U
#define MAP_SHARED_STRESS_WORKERS	2U
#define MAP_SHARED_STRESS_APPEND_BYTES	32U

/*
 * One-shot unsupported latch.  Set true when the first probe cannot
 * create or extend the scratch file; every subsequent invocation
 * returns immediately without repeating the syscall attempts.  Mirrors
 * the ns_unsupported / *_probed pattern in childops/misc/sysv-shm-
 * orphan-race.c.
 */
static bool map_shared_stress_unsupported;
static bool map_shared_stress_probed;

/*
 * Open a fresh backing file under $TMPDIR (or /tmp), ftruncate it to
 * MAP_SHARED_STRESS_FILE_BYTES, and unlink the path immediately so an
 * unexpected exit cannot leak the file.  Returns the fd on success,
 * -1 on failure with the unsupported latch armed for future calls.
 */
static int open_backing_file(void)
{
	const char *tmp = getenv("TMPDIR");
	char path[64];
	int fd;
	int n;

	if (tmp == NULL || *tmp == '\0')
		tmp = "/tmp";

	n = snprintf(path, sizeof(path), "%s/trinity-mss-XXXXXX", tmp);
	if (n <= 0 || (size_t)n >= sizeof(path))
		return -1;

	fd = mkstemp(path);
	if (fd < 0)
		return -1;

	if (ftruncate(fd, (off_t)MAP_SHARED_STRESS_FILE_BYTES) < 0) {
		(void)unlink(path);
		(void)close(fd);
		return -1;
	}

	/* Unlink immediately: the fd keeps the inode alive for the
	 * lifetime of this invocation; a crash before close cannot
	 * leave a stray file on disk. */
	(void)unlink(path);
	return fd;
}

/*
 * Sub-op 1.  Fork MAP_SHARED_STRESS_WORKERS workers, each of which
 * dirties its slice of a MAP_SHARED region and msync's it back.  The
 * parent interleaves its own writes plus a full-region msync sweep so
 * writeback races sibling dirtying on the same pagecache pages.
 */
static void run_concurrent_writeback(int fd, unsigned char *map,
				     unsigned long region_bytes)
{
	unsigned long slice = region_bytes / MAP_SHARED_STRESS_WORKERS;
	pid_t workers[MAP_SHARED_STRESS_WORKERS];
	unsigned int i;

	for (i = 0; i < MAP_SHARED_STRESS_WORKERS; i++)
		workers[i] = -1;

	for (i = 0; i < MAP_SHARED_STRESS_WORKERS; i++) {
		pid_t pid = fork();

		if (pid < 0)
			break;
		if (pid == 0) {
			unsigned long off = i * slice;
			unsigned long end = off + slice;
			unsigned long p;
			unsigned char byte = (unsigned char)(rnd_u32() & 0xff);

			for (p = off; p < end; p += page_size)
				map[p] = byte;

			(void)msync(map + off, slice, MS_ASYNC);
			_exit(0);
		}
		workers[i] = pid;
	}

	{
		unsigned long p;
		unsigned char byte = (unsigned char)(rnd_u32() & 0xff);

		for (p = 0; p < region_bytes; p += page_size)
			map[p] ^= byte;
	}
	(void)msync(map, region_bytes, MS_ASYNC);

	for (i = 0; i < MAP_SHARED_STRESS_WORKERS; i++) {
		int status;

		if (workers[i] < 0)
			continue;
		(void)waitpid_eintr(workers[i], &status, 0);
	}

	(void)fd;
}

/*
 * Sub-op 2.  MAP_SHARED + MADV_DONTFORK on the first half of the file,
 * inheritable MAP_SHARED on the second half.  Fork a child that touches
 * only the inheritable half then _exits; parent reaps and msync's.
 * Both regions unmap on return regardless of fork outcome.
 */
static void run_dontfork_split(int fd, unsigned long region_bytes)
{
	unsigned long half = region_bytes / 2;
	unsigned char *dontfork_map;
	unsigned char *inherit_map;
	pid_t pid;
	int status;

	if (half < page_size)
		return;

	dontfork_map = mmap(NULL, half, PROT_READ | PROT_WRITE,
			    MAP_SHARED, fd, 0);
	if (dontfork_map == MAP_FAILED)
		return;

	inherit_map = mmap(NULL, half, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, (off_t)half);
	if (inherit_map == MAP_FAILED) {
		(void)munmap(dontfork_map, half);
		return;
	}

	/* MADV_DONTFORK marks the first VMA VM_DONTCOPY: the fork
	 * child's mm will lack it entirely, so its address is unsafe
	 * to touch from the child.  The inheritable region is left
	 * unmarked so the child sees a MAP_SHARED copy of the same
	 * inode pages the parent sees. */
	if (madvise(dontfork_map, half, MADV_DONTFORK) < 0) {
		(void)munmap(dontfork_map, half);
		(void)munmap(inherit_map, half);
		return;
	}

	pid = fork();
	if (pid < 0) {
		(void)munmap(dontfork_map, half);
		(void)munmap(inherit_map, half);
		return;
	}
	if (pid == 0) {
		unsigned long p;
		unsigned char byte = (unsigned char)(rnd_u32() & 0xff);

		/* Only the inheritable half is legally reachable from
		 * here; the dontfork half is not mapped in this mm. */
		for (p = 0; p < half; p += page_size)
			inherit_map[p] = byte;

		_exit(0);
	}

	(void)waitpid_eintr(pid, &status, 0);
	(void)msync(inherit_map, half, MS_ASYNC);

	(void)munmap(dontfork_map, half);
	(void)munmap(inherit_map, half);
}

/*
 * Sub-op 3.  Open a second fd against the same inode with O_APPEND,
 * write a short payload past current i_size, then msync + read the
 * mapping to force the shared pagecache pages the append landed on
 * through the sync path.  Exercises the ordering between the write()
 * append-past-i_size and the shared-writeback walker.
 */
static void run_append_vs_mmap(int fd, unsigned char *map,
			       unsigned long region_bytes)
{
	char proc_link[64];
	unsigned char payload[MAP_SHARED_STRESS_APPEND_BYTES];
	unsigned int i;
	int append_fd;
	int n;

	n = snprintf(proc_link, sizeof(proc_link),
		     "/proc/self/fd/%d", fd);
	if (n <= 0 || (size_t)n >= sizeof(proc_link))
		return;

	append_fd = open(proc_link, O_APPEND | O_RDWR);
	if (append_fd < 0)
		return;

	for (i = 0; i < MAP_SHARED_STRESS_APPEND_BYTES; i++)
		payload[i] = (unsigned char)(rnd_u32() & 0xff);

	{
		ssize_t w = write(append_fd, payload, sizeof(payload));
		(void)w;
	}
	(void)close(append_fd);

	(void)msync(map, region_bytes, MS_ASYNC);

	/* Volatile touch of the last page so a subsequent read faults
	 * a fresh pagecache page in if the append grew i_size onto a
	 * page we hadn't previously touched. */
	{
		volatile unsigned char *last =
			(volatile unsigned char *)map +
			(region_bytes - page_size);
		volatile unsigned char sink = last[0];
		(void)sink;
	}
}

bool map_shared_stress(struct childdata *child)
{
	unsigned long region_bytes = MAP_SHARED_STRESS_FILE_BYTES;
	unsigned char *map;
	unsigned int iters, i;
	int fd;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (map_shared_stress_unsupported)
		return true;

	__atomic_add_fetch(&shm->stats.map_shared_stress.runs, 1,
			   __ATOMIC_RELAXED);

	fd = open_backing_file();
	if (fd < 0) {
		if (!map_shared_stress_probed) {
			map_shared_stress_probed = true;
			map_shared_stress_unsupported = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.map_shared_stress.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	map_shared_stress_probed = true;

	map = mmap(NULL, region_bytes, PROT_READ | PROT_WRITE,
		   MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.map_shared_stress.setup_failed,
				   1, __ATOMIC_RELAXED);
		(void)close(fd);
		return true;
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	iters = BUDGETED(CHILD_OP_MAP_SHARED_STRESS,
			 MAP_SHARED_STRESS_ITERS_BASE);

	for (i = 0; i < iters; i++) {
		uint32_t pick = rnd_modulo_u32(3);

		switch (pick) {
		case 0:
			run_concurrent_writeback(fd, map, region_bytes);
			__atomic_add_fetch(
				&shm->stats.map_shared_stress.writeback_ok,
				1, __ATOMIC_RELAXED);
			break;
		case 1:
			run_dontfork_split(fd, region_bytes);
			__atomic_add_fetch(
				&shm->stats.map_shared_stress.dontfork_ok,
				1, __ATOMIC_RELAXED);
			break;
		default:
			run_append_vs_mmap(fd, map, region_bytes);
			__atomic_add_fetch(
				&shm->stats.map_shared_stress.append_ok,
				1, __ATOMIC_RELAXED);
			break;
		}
	}

	(void)munmap(map, region_bytes);
	(void)close(fd);
	return true;
}
