/*
 * SYSCALL_DEFINE4(cachestat, unsigned int, fd,
 *		struct cachestat_range __user *, cstat_range,
 *		struct cachestat __user *, cstat, unsigned int, flags)
 */
#include <sys/stat.h>
#include <linux/mman.h>
#include "arch.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * Pick a cachestat_range based on the fd's actual file size.  The
 * kernel rejects unaligned / past-EOF / EFBIG ranges before touching
 * the page-cache lookup, so a fully random off/len mostly stays on
 * the input-validation path.  Bias toward shapes that land inside
 * the file, with a smaller bucket of intentionally-bogus ranges so
 * the reject path stays covered.
 */
static void pick_range(int fd, struct cachestat_range *range)
{
	struct stat st;
	unsigned long long size;
	unsigned long long pg = (unsigned long long) page_size;

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		/*
		 * No usable size (pipe, socket, empty file, fstat failure).
		 * Whole-file is a legal value for any fd type cachestat
		 * accepts -- the kernel walks the address_space up to EOF.
		 */
		range->off = 0;
		range->len = 0;
		return;
	}

	size = (unsigned long long) st.st_size;

	/* 70% real-range shapes, 30% intentionally-invalid. */
	switch (rnd_modulo_u32(10)) {
	case 0:
		/* whole file */
		range->off = 0;
		range->len = size;
		return;
	case 1:
		/* first page */
		range->off = 0;
		range->len = pg;
		return;
	case 2:
		/* last page, page-aligned */
		if (size >= pg)
			range->off = (size - pg) & ~(pg - 1);
		else
			range->off = 0;
		range->len = pg;
		return;
	case 3:
		/* around EOF: starts inside file, runs well past EOF */
		if (size >= pg)
			range->off = (size - pg) & ~(pg - 1);
		else
			range->off = 0;
		range->len = pg * 4;
		return;
	case 4:
	case 5: {
		/* middle slice, both off and len page-aligned, within file */
		unsigned long long max_pages;
		unsigned long long off_pages, len_pages;

		max_pages = size / pg;
		if (max_pages == 0) {
			range->off = 0;
			range->len = pg;
			return;
		}
		off_pages = rnd_modulo_u32(max_pages);
		len_pages = 1 + rnd_modulo_u32(max_pages - off_pages + 1);
		range->off = off_pages * pg;
		range->len = len_pages * pg;
		return;
	}
	case 6:
		/* zero-length is legal and returns an all-zero cachestat */
		range->off = (rnd_modulo_u32((unsigned int) (size / pg + 1))) * pg;
		range->len = 0;
		return;
	case 7:
		/* off past EOF */
		range->off = size + pg + rnd_u64();
		range->len = pg;
		return;
	case 8:
		/* negative-shaped len (high bit set as unsigned) */
		range->off = 0;
		range->len = ~0ULL ^ rnd_modulo_u32(pg);
		return;
	default:
		/* unaligned offset and length, mid-file */
		range->off = rnd_modulo_u64(size + 1);
		range->len = 1 + rnd_modulo_u32((unsigned int) (pg * 64));
		return;
	}
}

static void sanitise_cachestat(struct syscallrecord *rec)
{
	struct cachestat_range *range;
	struct cachestat *cs;

	range = (struct cachestat_range *) get_writable_struct(sizeof(*range));
	if (!range)
		return;

	pick_range((int) rec->a1, range);

	cs = (struct cachestat *) get_writable_struct(sizeof(*cs));
	if (!cs)
		return;

	rec->a2 = (unsigned long) range;
	rec->a3 = (unsigned long) cs;

	/*
	 * Flags are currently a "must be zero" slot in the kernel.  Pass
	 * 0 the vast majority of the time and a small random bucket for
	 * future-proofing against new flag bits.
	 */
	if (ONE_IN(64))
		rec->a4 = rnd_u32();
	else
		rec->a4 = 0;

	avoid_shared_buffer_out(&rec->a3, sizeof(struct cachestat));
}

struct syscallentry syscall_cachestat = {
	.name = "cachestat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "fd", [1] = "cstat_range", [2] = "cstat", [3] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_cachestat,
};
