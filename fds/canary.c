/*
 * Canary file pool — fd_provider that exposes a small set of
 * trinity-owned files whose byte content is deterministic across
 * the (file_idx, offset) product.
 *
 * Init steps (run inside the .init callback during open_fds()):
 *   1. mkdir tmp/canary/ inside trinity's working tmp dir.
 *   2. Create NR_CANARY_FILES files with varied sizes:
 *        2 small  (4 KiB)
 *        3 medium (64 KiB)
 *        2 large  (1 MiB)
 *        1 odd    (5000 bytes — non-page-aligned, drives the
 *                  partial-tail code paths)
 *   3. Fill each file with the deterministic
 *      canary_expected_byte() pattern via a clean buffered loop.
 *   4. Reopen each O_RDONLY and publish as an OBJ_FD_CANARY object,
 *      tagged with OBJ_FLAG_NO_WRITE so future write-side fd
 *      filtering can skip these.  The O_RDONLY open is the actual
 *      backstop today — every kernel write/splice-out/sendfile-out/
 *      copy_file_range-out/ftruncate/fallocate against an O_RDONLY
 *      fd returns EBADF before reaching any data path.
 *
 * The verifier childop pagecache_canary_check (childops/pagecache-
 * canary-check.c) consumes this pool; see its top comment for the
 * read-side coverage matrix.
 *
 * This is the Phase 1 baseline.  Phase 2 (directed splice/copy-fail/
 * crypto setup childops aimed at the canary pool) lands separately.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "canary.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Path is relative to trinity's run-time CWD.  change_tmp_dir()
 * (called from main() before open_fds()) chdirs us into the tmp/
 * subdir of the launch directory, so a "canary" basename here
 * resolves to <launch>/tmp/canary on disk.  No leading "tmp/"
 * prefix — that would land at <launch>/tmp/tmp/canary.
 */
#define CANARY_DIR		"canary"
#define CANARY_PATH_CAP		96
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
	size_t written = 0;

	while (written < size) {
		size_t chunk = size - written;
		size_t i;
		ssize_t n;

		if (chunk > sizeof(buf))
			chunk = sizeof(buf);
		for (i = 0; i < chunk; i++)
			buf[i] = canary_expected_byte(file_idx,
						      (off_t)(written + i));
		n = write(fd, buf, chunk);
		if (n <= 0)
			return false;
		written += (size_t)n;
	}
	return true;
}

/*
 * Build the on-disk file at tmp/canary/<idx>, fill it with the
 * deterministic pattern, then reopen O_RDONLY and publish as an
 * OBJ_FD_CANARY object.  Returns true on success.
 *
 * The intermediate creation fd is opened O_WRONLY and closed before
 * the read-side reopen so the pool never holds a writable handle to
 * its own contents — a wild-write through a fuzzed dup3()/sendfd()
 * cannot turn a stray write-end into a content-mutation primitive.
 */
static bool canary_create_one(unsigned int idx)
{
	char path[CANARY_PATH_CAP];
	struct object *obj;
	char *shared_path;
	int wfd, rfd;

	snprintf(path, sizeof(path), "%s/%u", CANARY_DIR, idx);

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

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		free_shared_str(shared_path, strlen(shared_path) + 1);
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
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_CANARY);
	head->destroy = &canary_destructor;
	head->dump = &canary_dump;
	head->shared_alloc = true;

	canary_pool = alloc_shared(sizeof(*canary_pool));
	if (canary_pool == NULL) {
		outputerr("canary: alloc_shared(canary_pool) failed\n");
		return false;
	}
	memset(canary_pool, 0, sizeof(*canary_pool));

	if (mkdir(CANARY_DIR, 0755) != 0 && errno != EEXIST) {
		outputerr("canary: mkdir %s failed: %s\n",
			  CANARY_DIR, strerror(errno));
		return false;
	}

	for (i = 0; i < NR_CANARY_FILES; i++) {
		if (!canary_create_one(i)) {
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
		canary_pool->count, NR_CANARY_FILES, CANARY_DIR);
	return true;
}

const struct canary_file_info *canary_file_get(unsigned int idx)
{
	if (canary_pool == NULL || idx >= canary_pool->count)
		return NULL;
	return &canary_pool->entries[idx];
}

unsigned int canary_pool_size(void)
{
	return canary_pool ? canary_pool->count : 0;
}

static int get_rand_canary_fd(void)
{
	if (objects_empty(OBJ_FD_CANARY) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->fileobj.fd deref, mirroring the wireup in
	 * fds/pagecache.c::get_rand_pagecache_fd() at b7e... — same
	 * OBJ_GLOBAL lockless-reader UAF window the framework commit
	 * a7fdbb97830c spelled out.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version, slot_array_gen;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_CANARY, OBJ_GLOBAL,
						  &slot_idx, &slot_version, &slot_array_gen);
		if (obj == NULL)
			continue;

		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_canary_fd: bogus obj %p in "
				  "OBJ_FD_CANARY pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_CANARY, OBJ_GLOBAL, obj,
					    slot_idx, slot_version, slot_array_gen))
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
