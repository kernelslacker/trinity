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
 *           holds a reference in its pool.  The check runs in two phases —
 *           pool-side (OBJ_FD_SOCKET pool, fstat for inode) and fdinfo-side
 *           (/proc/self/fd readlinks for "socket:[<inode>]") — sharing the
 *           net-inode set so we catch drift from either side of the pool.
 *
 * Anomalies are logged at verbosity 0 and counted; trinity keeps running.
 * The auditor bails silently if /proc is unavailable (containerized env).
 */

#include <dirent.h>
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
 * Walk shm->fd_live[], the parallel compact list of live fds maintained
 * by fd_hash_insert / fd_hash_remove.  fd_hash[] is a sparse open-addressing
 * table sized for hash-collision headroom (FD_HASH_SIZE slots, typically
 * <10% occupied), so iterating it directly burns >90% of the work on
 * empty-slot NULL checks.  fd_live[] is dense — every entry is a live fd —
 * so the auditor only visits real work.
 *
 * For each live fd, confirm the kernel still exposes it under
 * /proc/self/fdinfo/N.  A missing entry means trinity's pool believes
 * the fd is open but the underlying file struct has been freed — a
 * refcount imbalance between the pool and the kernel.
 *
 * False-positive discipline: we dup() the fd to obtain a stable handle
 * to the underlying file struct, then stat /proc/self/fdinfo/<newfd>.
 * The dup pins the file struct against concurrent close by a sibling
 * (close-racer, fd-stress) — without it, the F_GETFD→stat window allowed
 * a sibling close between the two syscalls to produce spurious
 * "fd missing from /proc" reports.
 *
 * Lockless read of fd_live[]: ACQUIRE-load fd_live_count first to
 * synchronise with the publishing RELEASE store on the writer side, then
 * RELAXED-load each fd_live[] entry.  A concurrent swap-remove can race
 * us — we may re-read an fd that was just removed, which the dup() check
 * naturally tolerates (it returns EBADF and we skip the entry).
 */
static void audit_fd_bucket(void)
{
	struct childdata *child = this_child();
	const int *fd_live;
	unsigned int i;
	unsigned int count;

	if (!check_proc_available())
		return;

	/*
	 * Read the live-fd list from this child's fork-time snapshot.
	 * The snapshot does not pick up post-fork inserts in the parent's
	 * table, which is acceptable for a sampling auditor.  Skip if the
	 * snapshot has not yet been allocated (early-init window).
	 */
	if (child == NULL || child->fd_live == NULL)
		return;

	fd_live = child->fd_live;
	count = child->fd_live_count;

	for (i = 0; i < count; i++) {
		char path[64];
		struct stat st;
		int fd, newfd;

		fd = fd_live[i];
		if (fd < 0)
			continue;

		/*
		 * dup() atomically: succeeds with a new descriptor pointing at
		 * the same file struct, or fails with EBADF if a sibling has
		 * already closed fd.  Either outcome is race-free; the failure
		 * case means the entry is genuinely gone, not a TOCTOU artifact.
		 */
		newfd = dup(fd);
		if (newfd < 0)
			continue;

		snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", newfd);
		if (stat(path, &st) != 0 && errno == ENOENT) {
			output(0, "refcount audit: fd %d tracked in pool but /proc/self/fdinfo/%d missing\n",
			       fd, newfd);
			__atomic_add_fetch(&shm->stats.refcount_audit_fd_anomalies,
					   1, __ATOMIC_RELAXED);
		}
		close(newfd);
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
		struct object *obj;
		unsigned int i;

		head = get_objhead(OBJ_GLOBAL, mmap_types[t]);
		if (head == NULL)
			continue;

		for_each_obj(head, obj, i) {
			struct map *m;
			unsigned long addr;

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
 * Writes the count gathered to *count_out (capped by max).
 *
 * Returns true if the file was reachable (open() succeeded); false on a real
 * open failure.  The two outputs are kept separate because "file readable but
 * currently empty" (e.g. a quiet namespace with no sockets of that family) is
 * a valid sample and must not be conflated with "/proc/net is unavailable" —
 * the caller latches its unavailable flag only when every probed file fails
 * to open, never on a zero count from a file that opened cleanly.
 */
#define MAX_PROC_NET_INODES 4096

static bool collect_proc_net_inodes(const char *path,
				    unsigned int inode_field,
				    ino_t *out, unsigned int max,
				    unsigned int *count_out)
{
	/* Chunked stack-buffer read, no stdio.  Each call to the auditor
	 * sweeps six /proc/net files, and the auditor itself runs in the
	 * fuzz loop (sampled at 1-in-50, with one of three buckets selected
	 * per call), so under load the stdio path here was driving a steady
	 * stream of FILE-struct + IO-buffer malloc/free cycles per file.
	 * That heap traffic is wasted work and, under ASAN, becomes
	 * candidate abort sites; the freed IO buffer is also a known recycle
	 * source for a heap-use-after-free shape where the buffer is later
	 * reissued by trinity's __zmalloc into an obj pool slot.
	 *
	 * /proc/net/{tcp,udp,...} can run to many KB on a busy host, so a
	 * single read into a stack buffer would truncate the file and
	 * spuriously report "inode missing".  Chunked read with line
	 * stitching: read into a stack buffer, process complete lines up
	 * to the last newline, memmove any partial trailing line to the
	 * front of the buffer, refill, repeat.  Skips the one-line header
	 * exactly like the previous fgets-based loop.
	 */
	char buf[8192];
	size_t held = 0;
	unsigned int count = 0;
	bool skip_header = true;
	int fd;

	*count_out = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	for (;;) {
		ssize_t n;
		char *start, *eol;

		n = read(fd, buf + held, sizeof(buf) - 1 - held);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0 && held == 0)
			break;
		held += (size_t)n;
		buf[held] = '\0';

		start = buf;
		while (count < max &&
		       (eol = memchr(start, '\n', buf + held - start)) != NULL) {
			char *tok, *saveptr, *p;
			unsigned int field;
			unsigned long inode;

			*eol = '\0';

			if (skip_header) {
				skip_header = false;
				start = eol + 1;
				continue;
			}

			p = start;
			for (field = 1; field <= inode_field; field++) {
				tok = strtok_r(p, " \t", &saveptr);
				p = NULL;
				if (tok == NULL)
					break;
				if (field == inode_field) {
					if (sscanf(tok, "%lu", &inode) == 1 && inode != 0)
						out[count++] = (ino_t)inode;
				}
			}
			start = eol + 1;
		}

		if (count >= max)
			break;

		/* Stitch the partial trailing line (no newline yet) to the
		 * front of the buffer and refill from the kernel.  If the
		 * remainder fills the entire buffer, the line is pathologically
		 * long — drop it to avoid an infinite loop. */
		held -= (size_t)(start - buf);
		if (held == sizeof(buf) - 1)
			held = 0;
		else if (held > 0)
			memmove(buf, start, held);

		if (n == 0)
			break;
	}

	close(fd);
	*count_out = count;
	return true;
}

/*
 * Walk /proc/self/fd readlinks and collect inode numbers from any entry
 * whose target matches "socket:[<inode>]".  Returns the count written to out[].
 *
 * This is the kernel-direct view of socket fds the child actually holds, used
 * as the authoritative side of the fdinfo-vs-/proc/net cross-check below.
 * /proc/self/fd/N is a symlink with target "socket:[<inode>]" for socket fds,
 * so a single readlink yields the inode without parsing fdinfo key-value
 * lines (which expose the same information but require more work).
 *
 * On opendir failure (containerised env with /proc hidden) we return 0; the
 * caller treats zero held inodes as "idle child" and skips the cross-check.
 */
static unsigned int collect_held_socket_inodes(ino_t *out, unsigned int max)
{
	DIR *dir;
	struct dirent *de;
	unsigned int count = 0;

	dir = opendir("/proc/self/fd");
	if (dir == NULL)
		return 0;

	while (count < max && (de = readdir(dir)) != NULL) {
		/* /proc/self/fd/ (14) + NAME_MAX (255) + NUL.  d_name is in
		 * practice a small integer string, but gcc's format-truncation
		 * check sees the full 255-byte upper bound. */
		char linkpath[14 + 256];
		char target[64];
		ssize_t n;
		unsigned long inode;

		if (de->d_name[0] == '.')
			continue;

		snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%s", de->d_name);
		n = readlink(linkpath, target, sizeof(target) - 1);
		if (n <= 0)
			continue;
		target[n] = '\0';

		if (sscanf(target, "socket:[%lu]", &inode) == 1 && inode != 0)
			out[count++] = (ino_t)inode;
	}

	closedir(dir);
	return count;
}

/*
 * Bucket 2: socket refcount check via /proc/net/{tcp,udp,tcp6,udp6,unix,packet}.
 *
 * Two complementary cross-checks share a single collected net-inode set:
 *
 *   Phase 1 (pool-side): for each tracked socket in the global OBJ_FD_SOCKET
 *     pool, fstat the fd to obtain its kernel inode number and verify the
 *     inode appears in at least one of the /proc/net files.  A missing inode
 *     means the kernel freed the socket struct while trinity's pool still
 *     holds the fd — a refcount imbalance that will produce a UAF once the
 *     fd is eventually used.
 *
 *   Phase 2 (fdinfo-side): walk /proc/self/fd readlinks for
 *     "socket:[<inode>]" entries to obtain the kernel-direct list of socket
 *     fds this child actually holds, and verify each inode is present in the
 *     net-inode set.  This catches imbalances the pool view would miss, e.g.
 *     when the pool tracker drifts from the kernel's real fd table because
 *     a sibling closed the fd out from under trinity's bookkeeping.
 *
 * We collect inodes from all six /proc/net files up front to avoid re-parsing
 * them once per socket.  If /proc/net/tcp is unavailable we latch a flag and
 * skip all future invocations rather than accumulating spurious anomalies.
 *
 * Idle-child discipline: phase 2 silently skips when readlink finds zero
 * "socket:[...]" entries.  A child that holds no socket fds cannot mismatch
 * the net tables, and we must not bump the anomaly counter in that window.
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
	struct object *obj;
	ino_t *net_inodes;
	unsigned int net_count = 0;
	unsigned int t, i;
	bool any_open = false;

	if (proc_net_unavailable)
		return;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SOCKET);
	if (head == NULL)
		return;

	net_inodes = malloc(MAX_PROC_NET_INODES * sizeof(*net_inodes));
	if (!net_inodes)
		return;

	for (t = 0; t < ARRAY_SIZE(net_files) && net_count < MAX_PROC_NET_INODES; t++) {
		unsigned int n = 0;

		if (collect_proc_net_inodes(net_files[t].path,
					    net_files[t].inode_field,
					    net_inodes + net_count,
					    MAX_PROC_NET_INODES - net_count,
					    &n))
			any_open = true;
		net_count += n;
	}

	/*
	 * Latch unavailable only when every probed file failed to open — a
	 * containerised env with /proc/net hidden.  A zero count from files
	 * that opened cleanly just means no sockets of those families exist
	 * right now; skip this round and try again next cycle.
	 */
	if (!any_open) {
		proc_net_unavailable = true;
		free(net_inodes);
		return;
	}

	if (net_count == 0) {
		free(net_inodes);
		return;
	}

	for_each_obj(head, obj, i) {
		struct socketinfo *si;
		struct stat st;
		unsigned int j;
		bool found;

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

	/*
	 * Phase 2: fdinfo-side cross-check.  Pull the kernel's own list of
	 * socket inodes this child holds (via /proc/self/fd readlinks) and
	 * verify every one of them appears in the net-inode set.
	 *
	 * Stack-bounded held[] cap (256) is far above any realistic per-child
	 * socket-fd count under sane fuzz loads but small enough to keep the
	 * frame tight.  Overflow truncates silently — the next cycle samples
	 * the same set, so a real leak is not hidden.
	 *
	 * held_count == 0 silently skips the loop: no false positives on an
	 * idle child whose fd table holds no sockets at all.
	 */
	{
		ino_t held[256];
		unsigned int held_count;
		unsigned int j;

		held_count = collect_held_socket_inodes(held, ARRAY_SIZE(held));
		for (j = 0; j < held_count; j++) {
			unsigned int k;
			bool found = false;

			for (k = 0; k < net_count; k++) {
				if (net_inodes[k] == held[j]) {
					found = true;
					break;
				}
			}
			if (!found) {
				output(0, "refcount audit: held socket inode %lu (via /proc/self/fd) missing from all /proc/net tables\n",
				       (unsigned long)held[j]);
				__atomic_add_fetch(&shm->stats.refcount_audit_sock_anomalies,
						   1, __ATOMIC_RELAXED);
			}
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
