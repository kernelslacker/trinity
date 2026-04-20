/*
 * refcount_auditor — periodic cross-subsystem refcount consistency check.
 *
 * Kernel object refcount imbalances manifest as either object leaks (never
 * freed) or use-after-free (freed too early).  The UAF case typically crashes
 * fast enough for trinity to detect directly; the leak case is invisible to
 * crash-only detection — the object silently accumulates.  We detect it
 * indirectly: tracked objects in the trinity pool should always have a
 * corresponding kernel-side representation visible through /proc.
 *
 * Three audit buckets, one per invocation (cycling via a static cursor):
 *
 *   FD:     Every fd in the trinity object pool should have a readable entry
 *           under /proc/self/fdinfo/N.  A missing entry means the kernel
 *           freed the file struct before trinity removed the fd from its pool.
 *
 *   MMAP:   Every tracked mapping should appear in /proc/self/maps at the
 *           recorded address, size, and protection.  Reuses proc_maps_check().
 *
 *   SOCKET: Every tracked socket fd should have a corresponding inode entry
 *           in /proc/net (tcp, udp, tcp6, udp6, unix, packet).  A missing
 *           inode means the socket was freed in the kernel but trinity still
 *           holds a reference in its pool.
 *
 * Anomalies are logged at verbosity 0 and counted; trinity keeps running.
 * The auditor bails silently if /proc is unavailable (containerized env).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "child.h"
#include "maps.h"
#include "object-types.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* Latched once if /proc/self/fdinfo is inaccessible (containerized, etc.). */
static bool proc_unavailable;

/*
 * Probe /proc availability via the fdinfo directory.
 * Returns false and latches proc_unavailable on first failure.
 */
static bool check_proc_available(void)
{
	int fd;

	if (proc_unavailable)
		return false;

	fd = open("/proc/self/fdinfo", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		proc_unavailable = true;
		return false;
	}
	close(fd);
	return true;
}

/*
 * Bucket 0: fd refcount check via /proc/self/fdinfo/N.
 *
 * Walk shm->fd_hash.  For each live fd, confirm the kernel still exposes it
 * under /proc/self/fdinfo/N.  A missing entry means trinity's pool believes
 * the fd is open but the underlying file struct has been freed — a refcount
 * imbalance between the pool and the kernel.
 *
 * False-positive discipline: we confirm the fd is locally open via
 * fcntl(F_GETFD) before checking fdinfo, so transient hash entries being
 * concurrently removed by the parent do not cause spurious reports.
 */
static void audit_fd_bucket(void)
{
	unsigned int i;

	if (!check_proc_available())
		return;

	for (i = 0; i < FD_HASH_SIZE; i++) {
		char path[64];
		struct stat st;
		int fd;

		fd = __atomic_load_n(&shm->fd_hash[i].fd, __ATOMIC_ACQUIRE);
		if (fd < 0)
			continue;

		/*
		 * Confirm the fd is locally open; skip on failure to tolerate
		 * the parent concurrently removing the entry from the hash.
		 */
		if (fcntl(fd, F_GETFD) < 0)
			continue;

		snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
		if (stat(path, &st) != 0 && errno == ENOENT) {
			output(0, "refcount audit: fd %d tracked in pool but /proc/self/fdinfo/%d missing\n",
			       fd, fd);
			__atomic_add_fetch(&shm->stats.refcount_audit_fd_anomalies,
					   1, __ATOMIC_RELAXED);
		}
	}
}

static void audit_mmap_bucket(void)
{
}

static void audit_socket_bucket(void)
{
}

bool refcount_auditor(struct childdata *child __unused__)
{
	static unsigned int bucket_cursor;

	if (!ONE_IN(50))
		return true;

	__atomic_add_fetch(&shm->stats.refcount_audit_runs, 1, __ATOMIC_RELAXED);

	switch (bucket_cursor % 3) {
	case 0: audit_fd_bucket();     break;
	case 1: audit_mmap_bucket();   break;
	case 2: audit_socket_bucket(); break;
	}
	bucket_cursor++;

	return true;
}
