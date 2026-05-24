/*
 * SYSCALL_DEFINE(readahead)(int fd, loff_t offset, size_t count)
 */
#include <sys/stat.h>
#include "arch.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * Bucket (offset, count) against the fd's real extent.  A random
 * 0..2^63 offset overwhelmingly hits the EINVAL reject path before
 * the kernel ever walks the page cache, so cover the in-extent arm
 * explicitly: whole-file, first page, last page, a page-aligned
 * middle slice, at-EOF, past-EOF, and a one-byte unaligned variant
 * to exercise the round-up to page granularity inside the readahead
 * code path.  Keep a small random-shape bucket for reject coverage.
 */
static void sanitise_readahead(struct syscallrecord *rec)
{
	struct stat st;
	unsigned long long size;
	unsigned long long pg = (unsigned long long) page_size;
	unsigned long long max_pages;
	unsigned long long off_pages;
	loff_t off;
	unsigned long long count;

	if (fstat((int) rec->a1, &st) < 0 || !S_ISREG(st.st_mode) ||
	    st.st_size <= 0)
		goto random;

	size = (unsigned long long) st.st_size;

	/* ~15% random-shape baseline for the reject path. */
	if (rnd_modulo_u32(7) == 0)
		goto random;

	switch (rnd_modulo_u32(7)) {
	case 0:
		off = 0;
		count = size;
		goto out;
	case 1:
		off = 0;
		count = pg;
		goto out;
	case 2:
		if (size < pg)
			break;
		off = (loff_t) ((size - pg) & ~(pg - 1));
		count = pg;
		goto out;
	case 3:
		max_pages = size / pg;
		if (max_pages == 0)
			break;
		off_pages = rnd_modulo_u32((uint32_t) max_pages);
		off = (loff_t) (off_pages * pg);
		count = pg * (rnd_modulo_u32(16) + 1);
		goto out;
	case 4:
		off = (loff_t) size;
		count = pg;
		goto out;
	case 5:
		off = (loff_t) (size + pg);
		count = pg;
		goto out;
	case 6:
		/* off-by-one unaligned: forces the page-rounding path */
		max_pages = size / pg;
		if (max_pages == 0)
			break;
		off_pages = rnd_modulo_u32((uint32_t) max_pages);
		off = (loff_t) (off_pages * pg + 1);
		count = pg;
		goto out;
	}

random:
	/* Negative offsets produce EINVAL; mask to non-negative loff_t. */
	off = (loff_t) (rand64() & 0x7fffffffffffffffULL);
	count = (unsigned long long) rand64();

out:
	rec->a2 = (unsigned long) off;
	rec->a3 = (unsigned long) count;
}

struct syscallentry syscall_readahead = {
	.name = "readahead",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "offset", [2] = "count" },
	.sanitise = sanitise_readahead,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
