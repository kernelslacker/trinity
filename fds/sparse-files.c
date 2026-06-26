/*
 * Sparse file fd provider.
 *
 * Builds a small pool of files extended with ftruncate() to several
 * pages, with a single page of real data written at a deterministic
 * offset.  The result is a file whose inode has at least one data
 * extent surrounded by holes -- the input shape SEEK_DATA / SEEK_HOLE
 * need to actually exercise the per-fs sparse-walk code paths
 * (iomap_seek_data / iomap_seek_hole, ext4 / btrfs / xfs / f2fs custom
 * implementations).  Dense files built by testfiles.c are rejected
 * with -ENXIO before reaching that code.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "arch.h"
#include "deferred-free.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "sparse-files.h"
#include "utils.h"

#define MAX_SPARSE_FILES	8
#define SPARSE_FILE_PAGES	16

static void sparse_file_destructor(struct object *obj)
{
	close(obj->sparsefileobj.fd);
	if (obj->sparsefileobj.filename != NULL) {
		unlink(obj->sparsefileobj.filename);
		free_shared_str((void *) obj->sparsefileobj.filename, 64);
		obj->sparsefileobj.filename = NULL;
	}
}

static void sparse_file_dump(struct object *obj, enum obj_scope scope)
{
	struct sparsefileobj *so = &obj->sparsefileobj;

	output(2, "sparsefile fd:%d filename:%s size:%lld data_offset:%lld scope:%d\n",
		so->fd, so->filename, (long long) so->size,
		(long long) so->data_offset, scope);
}

static int open_one_sparse_file(unsigned int idx)
{
	struct object *obj;
	char *filename;
	off_t size, data_offset;
	char buf[1];
	int fd;

	filename = alloc_shared_str(64);
	if (filename == NULL)
		return false;
	snprintf(filename, 64, "trinity-sparsefile%u", idx);

	(void) unlink(filename);

	fd = open(filename, O_CREAT | O_RDWR, 0666);
	if (fd < 0) {
		free_shared_str(filename, 64);
		return false;
	}

	size = (off_t) page_size * SPARSE_FILE_PAGES;
	/*
	 * Spread the data extent across pages [1, PAGES-2] so every file
	 * has at least one leading hole and one trailing hole.  Picking
	 * deterministically off idx keeps the layout reproducible across
	 * runs and across the parent / child observers of the pool.
	 */
	data_offset = (off_t) page_size *
		(1 + (idx * 3) % (SPARSE_FILE_PAGES - 2));

	if (ftruncate(fd, size) < 0)
		goto err;

	buf[0] = 'x';
	if (pwrite(fd, buf, 1, data_offset) != 1)
		goto err;

	obj = alloc_object();
	if (obj == NULL)
		goto err;

	obj->sparsefileobj.fd = fd;
	obj->sparsefileobj.filename = filename;
	obj->sparsefileobj.size = size;
	obj->sparsefileobj.data_offset = data_offset;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_SPARSE_FILE);
	return true;

err:
	unlink(filename);
	close(fd);
	free_shared_str(filename, 64);
	return false;
}

static int open_sparse_file_fds(void)
{
	struct objhead *head;
	unsigned int i;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SPARSE_FILE);
	head->destroy = &sparse_file_destructor;
	head->dump = &sparse_file_dump;

	for (i = 0; i < MAX_SPARSE_FILES; i++) {
		if (open_one_sparse_file(i))
			ret = true;
	}

	return ret;
}

struct object *get_rand_sparse_file_obj(void)
{
	if (objects_empty(OBJ_FD_SPARSE_FILE) == true)
		return NULL;

	/*
	 * Versioned slot pick + objpool_check() before the caller
	 * dereferences obj->sparsefileobj.  A version-validated
	 * object-slot read guards the lockless reader against a recycled
	 * object (cf. get_rand_socketinfo in fds/sockets.c).  Same
	 * OBJ_GLOBAL lockless-reader UAF window: between the lockless
	 * slot pick and
	 * the consumer's read of the sparse fd / size handed to
	 * lseek(SEEK_DATA|SEEK_HOLE), the parent can destroy the obj;
	 * release_obj() zeroes the chunk and routes it through
	 * deferred-free, so the stale slot pointer can read a zeroed or
	 * recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;

		obj = get_random_object(OBJ_FD_SPARSE_FILE, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_SPARSE_FILE))
			continue;
		if (obj->sparsefileobj.fd < 0)
			continue;
		return obj;
	}

	return NULL;
}

int get_rand_sparse_file_fd(void)
{
	struct object *obj = get_rand_sparse_file_obj();

	if (obj == NULL)
		return -1;
	return obj->sparsefileobj.fd;
}

static const struct fd_provider sparse_file_fd_provider = {
	.name = "sparse-file",
	.objtype = OBJ_FD_SPARSE_FILE,
	.enabled = true,
	.init = &open_sparse_file_fds,
	.get = &get_rand_sparse_file_fd,
};

REG_FD_PROV(sparse_file_fd_provider);
