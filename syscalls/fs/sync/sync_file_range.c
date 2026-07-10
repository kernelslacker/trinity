/*
 * SYSCALL_DEFINE(sync_file_range)(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
 * SYSCALL_DEFINE(sync_file_range2)(int fd, unsigned int flags, loff_t offset, loff_t nbytes)
 */
#include <linux/fs.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "arch.h"
#include "files.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"

#define VALID_SFR_FLAGS (SYNC_FILE_RANGE_WAIT_BEFORE | \
			 SYNC_FILE_RANGE_WRITE | \
			 SYNC_FILE_RANGE_WAIT_AFTER)

/*
 * Bucket (offset, nbytes) against the fd's real extent.  Random
 * 0..2^60 ranges mostly fail offset/endbyte validation in the
 * kernel before the writeback path is touched, so the fsync-like
 * arm rarely runs.  Whole-file, page-sized random window, and the
 * "until EOF" (nbytes==0) sentinel cover the success path; keep a
 * random-shape bucket for invalid-range coverage.
 */
static void pick_range(int fd, loff_t *offp, loff_t *nbytesp)
{
	struct stat st;
	unsigned long long size;
	unsigned long long pg = (unsigned long long) page_size;
	unsigned long long max_pages;
	unsigned long long off_pages;
	long endbyte;
	loff_t off;
	loff_t nbytes;

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0)
		goto random;

	size = (unsigned long long) st.st_size;

	/* ~25% random-shape baseline for invalid-range coverage. */
	if (rnd_modulo_u32(4) == 0)
		goto random;

	switch (rnd_modulo_u32(3)) {
	case 0:
		/* whole-file flush */
		*offp = 0;
		*nbytesp = (loff_t) size;
		return;
	case 1:
		/* page-sized random window aligned within file */
		max_pages = size / pg;
		if (max_pages == 0)
			break;
		off_pages = rnd_modulo_u32((uint32_t) max_pages);
		*offp = (loff_t) (off_pages * pg);
		*nbytesp = (loff_t) pg;
		return;
	case 2:
		/* nbytes==0 means "to EOF" */
		max_pages = size / pg + 1;
		off_pages = rnd_modulo_u32((uint32_t) max_pages);
		*offp = (loff_t) (off_pages * pg);
		*nbytesp = 0;
		return;
	}

random:
retry:
	off = (loff_t) (rand64() & 0x0fffffffffffffffUL);
	nbytes = (loff_t) (rand64() & 0x0fffffffffffffffUL);
	endbyte = off + nbytes;
	if (endbyte < off)
		goto retry;

	if (off >= (0x100000000LL << PAGE_SHIFT))
		goto retry;

	*offp = off;
	*nbytesp = nbytes;
}

static unsigned int pick_flags(void)
{
	/* ~10% invalid-high-bit bucket for the EINVAL arm. */
	if (rnd_modulo_u32(10) == 0)
		return 0x80000000U | (rnd_u32() & ~VALID_SFR_FLAGS);

	switch (rnd_modulo_u32(5)) {
	case 0:
		return 0;
	case 1:
		return SYNC_FILE_RANGE_WRITE;
	case 2:
		return SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE;
	case 3:
		return SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
	default:
		return SYNC_FILE_RANGE_WAIT_BEFORE |
		       SYNC_FILE_RANGE_WRITE |
		       SYNC_FILE_RANGE_WAIT_AFTER;
	}
}

static void sanitise_sync_file_range(struct syscallrecord *rec)
{
	loff_t off, nbytes;
	unsigned int flags;

	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_pagecache_fd();
		if (fd >= 0)
			rec->a1 = fd;
	}

	pick_range((int) rec->a1, &off, &nbytes);
	flags = pick_flags();

	if (!current_entry_is_sync_file_range2()) {
		rec->a2 = (unsigned long) off;
		rec->a3 = (unsigned long) nbytes;
		rec->a4 = (unsigned long) flags;
	} else {
		rec->a2 = (unsigned long) flags;
		rec->a3 = (unsigned long) off;
		rec->a4 = (unsigned long) nbytes;
	}
}

struct syscallentry syscall_sync_file_range = {
	.name = "sync_file_range",
	.num_args = 4,
	.sanitise = sanitise_sync_file_range,
	.argtype = { [0] = ARG_FD, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "offset", [2] = "nbytes", [3] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * ARM & PowerPC have different argument order.
 * See edd5cd4a9424f22b0fa08bef5e299d41befd5622 in kernel tree.
 */
struct syscallentry syscall_sync_file_range2 = {
	.name = "sync_file_range2",
	.num_args = 4,
	.sanitise = sanitise_sync_file_range,
	.argtype = { [0] = ARG_FD, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "flags", [2] = "offset", [3] = "nbytes" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
