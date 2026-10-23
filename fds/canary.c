/*
 * Canary file pool: an fd_provider exposing NR_CANARY_FILES trinity-owned
 * files, created at init in the run's working directory (tmp/ when it
 * exists) and published read-only, whose bytes are deterministic at every
 * (file_idx, offset).  The verifier childop pagecache_canary_check
 * (childops/mm/pagecache-canary-check.c) consumes it; the O_RDONLY /
 * OBJ_FLAG_NO_WRITE rationale is in include/canary.h.
 */

#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "canary.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define CANARY_DIR		"canary"
/*
 * The longest path open() accepts; a directory too deep to hold a pool
 * path fails init rather than have the path truncated.
 */
#define CANARY_PATH_CAP		PATH_MAX
#define CANARY_FILL_BUF_SIZE	4096

/*
 * Per-slot file size.  Chosen to mix small (single-page), medium
 * (multi-page within a typical readahead window), large (forces
 * multi-fault mmap walks), and one odd-sized entry that exercises
 * the non-page-aligned partial-tail paths in copy_file_range,
 * splice, and the read-side oracle.
 */
static const size_t canary_sizes[NR_CANARY_FILES] = {
	4096, 4096,
	65536, 65536, 65536,
	1024 * 1024, 1024 * 1024,
	5000,
};

/*
 * Per-slot metadata, populated at init time and read by both the
 * fd_provider .get callback and the verifier childop.  Lives in
 * shared memory so children see the parent's init result without
 * a fork-time copy.
 */
struct canary_pool {
	struct canary_file_info entries[NR_CANARY_FILES];
	unsigned int count;
};

static struct canary_pool *canary_pool;

static void canary_destructor(struct object *obj)
{
	/*
	 * Do NOT free obj->fileobj.filename here.  The string is owned
	 * by the canary pool: canary_create_one() stashes the same
	 * alloc_shared_strdup() pointer in canary_pool->entries[idx].path
	 * once at init, and the pool retains it for the process lifetime
	 * (the pool is bounded and allocate-once — no per-op free path
	 * touches entries[].path anywhere).  Freeing it on object teardown
	 * leaves a dangling pool entry that pagecache_canary_check()
	 * subsequently reopens, which is a cross-process use-after-free.
	 */
	close(obj->fileobj.fd);
}

static void canary_dump(struct object *obj, enum obj_scope scope)
{
	struct fileobj *fo = &obj->fileobj;

	output(2, "canary fd:%d filename:%s flags:%x obj_flags:%x scope:%d\n",
		fo->fd, fo->filename, fo->flags, fo->obj_flags, scope);
}

/*
 * Write the deterministic canary pattern into a freshly-created
 * file.  Buffered in CANARY_FILL_BUF_SIZE chunks to keep init time
 * predictable: the largest file is 1 MiB so the loop runs at most
 * 256 times per file.  Returns true on success, false on any
 * short-write or errno from the write loop.
 */
static bool canary_fill_file(int fd, unsigned int file_idx, size_t size)
{
	unsigned char buf[CANARY_FILL_BUF_SIZE];
	uint64_t file_key = (uint64_t)file_idx << 40;
	size_t written = 0;

	while (written < size) {
		size_t chunk = size - written;
		size_t i;
		ssize_t n;

		if (chunk > sizeof(buf))
			chunk = sizeof(buf);
		for (i = 0; i < chunk; i++)
			buf[i] = canary_finalize_byte(file_key ^
						      (uint64_t)(written + i));
		n = write(fd, buf, chunk);
		if (n <= 0)
			return false;
		written += (size_t)n;
	}
	return true;
}

/*
 * Build the on-disk file at @dir/<idx>, fill it with the
 * deterministic pattern, then reopen O_RDONLY and publish as an
 * OBJ_FD_CANARY object.  Returns true on success.
 *
 * The intermediate creation fd is opened O_WRONLY and closed before
 * the read-side reopen so the pool never holds a writable handle to
 * its own contents — a wild-write through a fuzzed dup3()/sendfd()
 * cannot turn a stray write-end into a content-mutation primitive.
 */
static bool canary_create_one(const char *dir, unsigned int idx)
{
	char path[CANARY_PATH_CAP];
	struct object *obj;
	char *shared_path;
	int wfd, rfd;

	if ((size_t)snprintf(path, sizeof(path), "%s/%u", dir, idx) >=
	    sizeof(path)) {
		outputerr("canary: %s/%u is longer than %zu bytes\n",
			  dir, idx, sizeof(path) - 1);
		return false;
	}

	(void)unlink(path);
	wfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (wfd < 0) {
		outputerr("canary: open(W) %s failed: %s\n",
			  path, strerror(errno));
		return false;
	}
	if (!canary_fill_file(wfd, idx, canary_sizes[idx])) {
		outputerr("canary: fill %s (size=%zu) failed: %s\n",
			  path, canary_sizes[idx], strerror(errno));
		close(wfd);
		return false;
	}
	if (fsync(wfd) < 0) {
		/* Best-effort — keep going.  The verifier reopens with
		 * a fresh fd anyway and the write-back path just
		 * happens slightly later on a kernel that defers it. */
	}
	close(wfd);

	rfd = open(path, O_RDONLY);
	if (rfd < 0) {
		outputerr("canary: open(R) %s failed: %s\n",
			  path, strerror(errno));
		return false;
	}

	shared_path = alloc_shared_strdup(path);
	if (shared_path == NULL) {
		close(rfd);
		return false;
	}

	obj = alloc_object();
	if (obj == NULL) {
		free_shared_str(shared_path);
		close(rfd);
		return false;
	}

	obj->fileobj.filename = shared_path;
	obj->fileobj.flags = O_RDONLY;
	obj->fileobj.fd = rfd;
	obj->fileobj.fopened = false;
	obj->fileobj.pagecache_backed = true;
	obj->fileobj.is_setuid = false;
	obj->fileobj.fcntl_flags = 0;
	obj->fileobj.obj_flags = OBJ_FLAG_NO_WRITE;

	add_object(obj, OBJ_GLOBAL, OBJ_FD_CANARY);

	canary_pool->entries[idx].path = shared_path;
	canary_pool->entries[idx].size = canary_sizes[idx];
	canary_pool->entries[idx].idx = idx;
	canary_pool->count++;
	return true;
}

static int init_canary_fds(void)
{
	char cwd[CANARY_PATH_CAP];
	char dir[CANARY_PATH_CAP];
	struct objhead *head;
	unsigned int i;

	/*
	 * Every pool path is absolute, built from the directory init runs in:
	 * the tmp dir main() has moved into when there is one, the launch
	 * directory when not.  The verifier reopens them in children whose
	 * cwd a fuzzed chdir() has moved, where a path relative to the cwd at
	 * init names nothing, or an unrelated file.  trinity_tmpdir_abs() is
	 * no anchor: without a tmp dir it is the fixed /tmp, the same pool
	 * paths for every run.  With no cwd to anchor at, build no pool.
	 */
	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		outputerr("canary: getcwd failed: %s\n", strerror(errno));
		return false;
	}
	if ((size_t)snprintf(dir, sizeof(dir), "%s/%s", cwd, CANARY_DIR) >=
	    sizeof(dir)) {
		outputerr("canary: %s/%s is longer than %zu bytes\n",
			  cwd, CANARY_DIR, sizeof(dir) - 1);
		return false;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_CANARY);
	head->destroy = &canary_destructor;
	head->dump = &canary_dump;

	/*
	 * Route through alloc_shared_pool so the default --guard-shared
	 * scope (pools) wraps this long-lived metadata region in
	 * PROT_NONE guard pages.  A stray writer that over- or under-
	 * runs the region then faults at the write PC instead of
	 * silently corrupting entries[].path -- the shared-string
	 * strdup pointer that pagecache_canary_check() dereferences on
	 * every verify pass to reopen the file.  A scribble that swaps
	 * .path for another plausible address reopens the wrong file
	 * (the verifier then compares its read against the wrong
	 * canary_sizes[] expectation); a scribble that lands NULL fails
	 * the open and silently drops the slot from verify coverage.
	 * Pool-routing closes both modes under the default scope
	 * without forcing operators up to =all.
	 */
	canary_pool = alloc_shared_pool(sizeof(*canary_pool));
	if (canary_pool == NULL) {
		outputerr("canary: alloc_shared_pool(canary_pool) failed\n");
		return false;
	}
	memset(canary_pool, 0, sizeof(*canary_pool));

	if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
		outputerr("canary: mkdir %s failed: %s\n",
			  dir, strerror(errno));
		return false;
	}

	for (i = 0; i < NR_CANARY_FILES; i++) {
		if (!canary_create_one(dir, i)) {
			/* Partial pool is still useful — keep what we
			 * built and continue.  The verifier checks
			 * canary_pool_size() before picking a slot. */
			outputerr("canary: stopped at %u/%u files\n",
				  i, NR_CANARY_FILES);
			break;
		}
	}

	if (canary_pool->count == 0) {
		outputerr("canary: pool init produced 0 files\n");
		return false;
	}

	output(1, "canary: initialised %u/%u files in %s\n",
		canary_pool->count, NR_CANARY_FILES, dir);
	return true;
}

const struct canary_file_info *canary_file_get(unsigned int idx)
{
	/*
	 * count lives in shared memory: a stomped value > NR_CANARY_FILES
	 * would let an in-range-of-count idx still index past entries[].
	 * Bound at the array cap too so the deref is provably in-array.
	 */
	if (canary_pool == NULL || idx >= NR_CANARY_FILES ||
	    idx >= canary_pool->count)
		return NULL;
	return &canary_pool->entries[idx];
}

unsigned int canary_pool_size(void)
{
	unsigned int count;

	/*
	 * count lives in shared memory; clamp to the array cap so a caller
	 * that picks an index from this size (pagecache_canary_check) can't
	 * be driven past entries[] by a stomped count -- matches the cap in
	 * canary_file_get() above.
	 */
	if (canary_pool == NULL)
		return 0;
	count = canary_pool->count;
	return count < NR_CANARY_FILES ? count : NR_CANARY_FILES;
}

static int get_rand_canary_fd(void)
{
	if (objects_empty(OBJ_FD_CANARY) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->fileobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_CANARY, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_CANARY))
			continue;

		fd = obj->fileobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider canary_fd_provider = {
	.name = "canary",
	.objtype = OBJ_FD_CANARY,
	.enabled = true,
	.init = &init_canary_fds,
	.get = &get_rand_canary_fd,
};

REG_FD_PROV(canary_fd_provider);
