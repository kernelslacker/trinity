/*
 * inode_spewer - rapidly create and destroy inodes to stress inode
 * allocation, slab caches, and dentry/inode lifecycle management.
 *
 * Creates temporary files, optionally extends them with ftruncate()
 * or fallocate(), then closes and unlinks them.  Files are created
 * under trinity-inodes-<pid>/ inside trinity's own work directory
 * (the "tmp/" subdir trinity chdirs into at startup), never in the
 * system /tmp tmpfs — the latter would blow up host memory and
 * persist across runs.
 *
 * This exercises: inode alloc/free, dentry cache pressure, directory
 * hash table growth, extent allocation (fallocate), and the unlink
 * path including orphan inode handling when fds are still open.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifdef __linux__
#include <linux/falloc.h>
#endif

#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01
#endif

#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02
#endif

static unsigned long file_counter;

static void ensure_spew_dir(char *dir, size_t len)
{
	snprintf(dir, len, "trinity-inodes-%d", getpid());
	(void)mkdir(dir, 0700);
}

static unsigned long pick_file_size(void)
{
	switch (rand() % 6) {
	case 0:	return 0;
	case 1:	return 1;
	case 2:	return page_size;
	case 3:	return page_size * (1 + (rand() % 64));
	case 4:	return MB(1);
	default: return rand() % MB(4);
	}
}

/*
 * Create a file, optionally extend it, close it.
 * Sometimes leave unlink for later to create orphan inodes.
 */
static bool do_create_and_destroy(void)
{
	char spew_dir[128];
	char path[256];
	int fd;
	unsigned long size;

	ensure_spew_dir(spew_dir, sizeof(spew_dir));

	snprintf(path, sizeof(path), "%s/%lu", spew_dir, file_counter++);

	fd = open(path, O_CREAT | O_RDWR | O_EXCL, 0600);
	if (fd < 0)
		return true;	/* non-fatal */

	/* Optionally extend the file. */
	if (RAND_BOOL()) {
		size = pick_file_size();
		if (size > 0) {
			int ret __unused__;
			if (RAND_BOOL())
				ret = ftruncate(fd, size);
			else
				ret = fallocate(fd, 0, 0, size);
		}
	}

	/* Optionally punch a hole if we have content. */
	if (ONE_IN(4)) {
		int ret __unused__;
		size = pick_file_size();
		if (size > 0)
			ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					0, size);
	}

	/* Optionally write some data. */
	if (ONE_IN(3)) {
		char buf[256];
		ssize_t ret __unused__;
		generate_rand_bytes((unsigned char *)buf, sizeof(buf));
		ret = write(fd, buf, sizeof(buf));
	}

	/*
	 * 10% of the time, unlink while the fd is still open.
	 * This creates an orphan inode that exercises the orphan
	 * list cleanup path when the fd is finally closed.
	 */
	if (ONE_IN(10))
		(void)unlink(path);

	close(fd);

	/* Unlink if we didn't already. */
	(void)unlink(path);

	return true;
}

/*
 * Batch-create several files then batch-unlink, to build up
 * directory hash table entries before tearing them all down.
 */
static bool do_batch_spew(void)
{
	char spew_dir[128];
	char paths[32][256];
	unsigned int i, count;

	ensure_spew_dir(spew_dir, sizeof(spew_dir));

	count = 4 + (rand() % 28);

	for (i = 0; i < count; i++) {
		int fd;

		snprintf(paths[i], sizeof(paths[i]), "%s/%lu",
			 spew_dir, file_counter++);

		fd = open(paths[i], O_CREAT | O_RDWR | O_EXCL, 0600);
		if (fd >= 0)
			close(fd);
	}

	/* Unlink in random order for extra churn. */
	for (i = 0; i < count; i++) {
		unsigned int j = rand() % count;
		char tmp[256];
		memcpy(tmp, paths[i], sizeof(tmp));
		memcpy(paths[i], paths[j], sizeof(paths[i]));
		memcpy(paths[j], tmp, sizeof(tmp));
	}

	for (i = 0; i < count; i++)
		(void)unlink(paths[i]);

	return true;
}

/*
 * Create and immediately remove directories to exercise
 * the directory inode allocation paths.
 */
static bool do_mkdir_rmdir(void)
{
	char spew_dir[128];
	char path[256];

	ensure_spew_dir(spew_dir, sizeof(spew_dir));

	snprintf(path, sizeof(path), "%s/d%lu", spew_dir, file_counter++);

	if (mkdir(path, 0700) == 0)
		(void)rmdir(path);

	return true;
}

/*
 * Create hard links and symlinks for dentry cache variety.
 */
static bool do_link_dance(void)
{
	char spew_dir[128];
	char src[256], dst[256];
	int fd, ret __unused__;

	ensure_spew_dir(spew_dir, sizeof(spew_dir));

	snprintf(src, sizeof(src), "%s/%lu", spew_dir, file_counter++);

	fd = open(src, O_CREAT | O_RDWR | O_EXCL, 0600);
	if (fd < 0)
		return true;
	close(fd);

	snprintf(dst, sizeof(dst), "%s/%lu", spew_dir, file_counter++);

	if (RAND_BOOL())
		ret = link(src, dst);
	else
		ret = symlink(src, dst);

	(void)unlink(dst);
	(void)unlink(src);

	return true;
}

bool inode_spewer(struct childdata *child)
{
	(void)child;

	switch (rand() % 10) {
	case 0 ... 5:	do_create_and_destroy();	break;
	case 6 ... 7:	do_batch_spew();		break;
	case 8:		do_mkdir_rmdir();		break;
	case 9:		do_link_dance();		break;
	}

	return true;
}
