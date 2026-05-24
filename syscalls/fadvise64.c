/*
 * SYSCALL_DEFINE(fadvise64)(int fd, loff_t offset, size_t len, int advice)
 *
 * On success, zero is returned.
 * On error, an error number is returned.
 */
#include <fcntl.h>
#include <sys/stat.h>
#include "arch.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * Bucket (offset, len) against the fd's real extent.  Otherwise the
 * random 0..2^31 offset overwhelmingly trips the offset > i_size
 * reject path in the kernel, and the in-extent code never runs.  Keep
 * a small random-shape bucket so the reject path stays covered too.
 */
static void pick_range(int fd, loff_t *off, unsigned long long *len)
{
	struct stat st;
	unsigned long long size;
	unsigned long long pg = (unsigned long long) page_size;
	unsigned long long max_pages;
	unsigned long long off_pages;

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0)
		goto random;

	size = (unsigned long long) st.st_size;

	/* ~15% random-shape baseline for the reject path. */
	if (rnd_modulo_u32(7) == 0)
		goto random;

	switch (rnd_modulo_u32(6)) {
	case 0:
		/* whole file */
		*off = 0;
		*len = size;
		return;
	case 1:
		/* first page */
		*off = 0;
		*len = pg;
		return;
	case 2:
		/* last page, page-aligned -- only if file is at least a page */
		if (size < pg)
			break;
		*off = (loff_t) ((size - pg) & ~(pg - 1));
		*len = pg;
		return;
	case 3:
		/* middle: page-aligned offset under i_size, 1..16 pages */
		max_pages = size / pg;
		if (max_pages == 0)
			break;
		off_pages = rnd_modulo_u32((uint32_t) max_pages);
		*off = (loff_t) (off_pages * pg);
		*len = pg * (rnd_modulo_u32(16) + 1);
		return;
	case 4:
		/* at-EOF (truncation arm for DONTNEED) */
		*off = (loff_t) size;
		*len = pg;
		return;
	case 5:
		/* past EOF (DONTNEED is legal, others EINVAL) */
		*off = (loff_t) (size + pg);
		*len = pg;
		return;
	}

random:
	/* Negative offsets produce EINVAL. */
	*off = (loff_t) (rand64() & 0x7fffffff);
	*len = (unsigned long long) rand64();
}

static void sanitise_fadvise64(struct syscallrecord *rec)
{
	loff_t off;
	unsigned long long len;

	pick_range((int) rec->a1, &off, &len);
	rec->a2 = (unsigned long) off;
	rec->a3 = (unsigned long) len;
}

static unsigned long fadvise_flags[] = {
	POSIX_FADV_NORMAL,
	POSIX_FADV_SEQUENTIAL,
	POSIX_FADV_RANDOM,
	POSIX_FADV_NOREUSE,
	POSIX_FADV_WILLNEED,
	POSIX_FADV_DONTNEED,
};

struct syscallentry syscall_fadvise64 = {
	.name = "fadvise64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [2] = ARG_LEN, [3] = ARG_OP },
	.argname = { [0] = "fd", [1] = "offset", [2] = "len", [3] = "advice" },
	.arg_params[3].list = ARGLIST(fadvise_flags),
	.sanitise = sanitise_fadvise64,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

#ifndef __arm__
/*
 * SYSCALL_DEFINE(fadvise64_64)(int fd, loff_t offset, loff_t len, int advice)
 *
 * On success, zero is returned.
 * On error, an error number is returned.
 */

struct syscallentry syscall_fadvise64_64 = {
	.name = "fadvise64_64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [2] = ARG_LEN, [3] = ARG_OP },
	.argname = { [0] = "fd", [1] = "offset", [2] = "len", [3] = "advice" },
	.arg_params[3].list = ARGLIST(fadvise_flags),
	.sanitise = sanitise_fadvise64,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

#else

/*
 * asmlinkage long sys_arm_fadvise64_64(int fd, int advice, loff_t offset, loff_t len)
 * ARM has same as fadvise64 but with other argument order.
 */
static void sanitise_arm_fadvise64_64(struct syscallrecord *rec)
{
	loff_t off;
	unsigned long long len;

	pick_range((int) rec->a1, &off, &len);
	rec->a3 = (unsigned long) off;
	rec->a4 = (unsigned long) len;
}

struct syscallentry syscall_arm_fadvise64_64 = {
	.name = "fadvise64_64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_OP, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "advice", [2] = "offset", [3] = "len" },
	.arg_params[1].list = ARGLIST(fadvise_flags),
	.sanitise = sanitise_arm_fadvise64_64,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
#endif
