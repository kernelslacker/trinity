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

/* Latched once if /proc/net is inaccessible. */
static bool proc_net_unavailable;

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

/*
 * Bucket 1: mmap refcount check via /proc/self/maps.
 *
 * Walk the global pool for all three mmap object types and verify each
 * recorded mapping is still visible in /proc/self/maps at the expected
 * address, size, and protection.  Reuses proc_maps_check(), which handles
 * /proc open failures gracefully (returns true on I/O error, so we only
 * report genuine mismatches).
 *
 * The global object array lives in MAP_SHARED memory so we can read it from
 * child context without a lock.  We null-check each slot to tolerate the
 * parent concurrently pruning entries under objlock.
 */
static void audit_mmap_bucket(void)
{
	static const enum objecttype mmap_types[] = {
		OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
	};
	unsigned int t;

	for (t = 0; t < ARRAY_SIZE(mmap_types); t++) {
		struct objhead *head;
		unsigned int i;

		head = get_objhead(OBJ_GLOBAL, mmap_types[t]);
		if (head == NULL || head->num_entries == 0 || head->array == NULL)
			continue;

		for (i = 0; i < head->num_entries; i++) {
			struct object *obj;
			struct map *m;
			unsigned long addr;

			if (i >= head->array_capacity)
				break;

			obj = head->array[i];
			if (obj == NULL)
				continue;

			m = &obj->map;
			addr = (unsigned long) m->ptr;
			if (addr == 0 || m->size == 0)
				continue;

			if (!proc_maps_check(addr, m->size, m->prot, true)) {
				output(0, "refcount audit: mapping %p size=%lu prot=0x%x missing from /proc/self/maps\n",
				       m->ptr, m->size, m->prot);
				__atomic_add_fetch(&shm->stats.refcount_audit_mmap_anomalies,
						   1, __ATOMIC_RELAXED);
			}
		}
	}
}

/*
 * Parse one /proc/net file and collect the inode numbers found at the given
 * 1-indexed field position in each data line (the header line is skipped).
 * Returns the count written to out[].  Stops when max is reached.
 */
#define MAX_PROC_NET_INODES 4096

static unsigned int collect_proc_net_inodes(const char *path,
					    unsigned int inode_field,
					    ino_t *out, unsigned int max)
{
	FILE *f;
	char line[256];
	unsigned int count = 0;
	bool skip_header = true;

	f = fopen(path, "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f) && count < max) {
		char *tok, *saveptr, *p;
		unsigned int field;
		unsigned long inode;

		if (skip_header) {
			skip_header = false;
			continue;
		}

		p = line;
		for (field = 1; field <= inode_field; field++) {
			tok = strtok_r(p, " \t\n", &saveptr);
			p = NULL;
			if (tok == NULL)
				break;
			if (field == inode_field) {
				if (sscanf(tok, "%lu", &inode) == 1 && inode != 0)
					out[count++] = (ino_t)inode;
			}
		}
	}

	fclose(f);
	return count;
}

/*
 * Bucket 2: socket refcount check via /proc/net/{tcp,udp,tcp6,udp6,unix,packet}.
 *
 * For each tracked socket in the global OBJ_FD_SOCKET pool, fstat the fd to
 * obtain its kernel inode number.  Then verify the inode appears in at least
 * one of the /proc/net files.  A missing inode means the kernel freed the
 * socket struct while trinity's pool still holds the fd — a refcount imbalance
 * that will produce a UAF once the fd is eventually used.
 *
 * We collect inodes from all six /proc/net files up front to avoid re-parsing
 * them once per socket.  If /proc/net/tcp is unavailable we latch a flag and
 * skip all future invocations rather than accumulating spurious anomalies.
 */
static void audit_socket_bucket(void)
{
	static const struct {
		const char *path;
		unsigned int inode_field;
	} net_files[] = {
		{ "/proc/net/tcp",    10 },
		{ "/proc/net/udp",    10 },
		{ "/proc/net/tcp6",   10 },
		{ "/proc/net/udp6",   10 },
		{ "/proc/net/unix",    7 },
		{ "/proc/net/packet",  9 },
	};
	struct objhead *head;
	ino_t *net_inodes;
	unsigned int net_count = 0;
	unsigned int t, i;

	if (proc_net_unavailable)
		return;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SOCKET);
	if (head == NULL || head->num_entries == 0 || head->array == NULL)
		return;

	net_inodes = malloc(MAX_PROC_NET_INODES * sizeof(*net_inodes));
	if (!net_inodes)
		return;

	for (t = 0; t < ARRAY_SIZE(net_files) && net_count < MAX_PROC_NET_INODES; t++) {
		unsigned int n;

		n = collect_proc_net_inodes(net_files[t].path,
					    net_files[t].inode_field,
					    net_inodes + net_count,
					    MAX_PROC_NET_INODES - net_count);
		net_count += n;
	}

	if (net_count == 0) {
		proc_net_unavailable = true;
		free(net_inodes);
		return;
	}

	for (i = 0; i < head->num_entries; i++) {
		struct object *obj;
		struct socketinfo *si;
		struct stat st;
		unsigned int j;
		bool found;

		if (i >= head->array_capacity)
			break;

		obj = head->array[i];
		if (obj == NULL)
			continue;

		si = &obj->sockinfo;
		if (si->fd < 0)
			continue;

		if (fstat(si->fd, &st) != 0)
			continue;

		if (st.st_ino == 0)
			continue;

		found = false;
		for (j = 0; j < net_count; j++) {
			if (net_inodes[j] == st.st_ino) {
				found = true;
				break;
			}
		}

		if (!found) {
			output(0, "refcount audit: socket fd %d inode %lu missing from /proc/net\n",
			       si->fd, (unsigned long)st.st_ino);
			__atomic_add_fetch(&shm->stats.refcount_audit_sock_anomalies,
					   1, __ATOMIC_RELAXED);
		}
	}

	free(net_inodes);
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
