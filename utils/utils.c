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
#include "child-api.h"
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
			__atomic_add_fetch(&shm->stats.fd.parent_inherited_fds_closed,
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
 * instead of byte-identical copies that drift apart silently.  Table
 * is built once at load time by the constructor below so crc32() is a
 * pure reader — safe from a signal handler on the same thread and
 * from any post-fork child. */
static uint32_t crc32_table[256];

static void crc32_build_table(void)
{
	uint32_t c;
	unsigned int n, k;

	for (n = 0; n < 256; n++) {
		c = n;
		for (k = 0; k < 8; k++)
			c = (c & 1) ? (0xedb88320U ^ (c >> 1)) : (c >> 1);
		crc32_table[n] = c;
	}
}

static void __attribute__((constructor)) crc32_init(void)
{
	crc32_build_table();
}

uint32_t crc32(const void *buf, size_t len)
{
	const uint8_t *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;

	for (i = 0; i < len; i++)
		crc = crc32_table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);

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
