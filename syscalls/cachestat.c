/*
 * SYSCALL_DEFINE4(cachestat, unsigned int, fd,
 *		struct cachestat_range __user *, cstat_range,
 *		struct cachestat __user *, cstat, unsigned int, flags)
 */
#include <linux/mman.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"

static void sanitise_cachestat(struct syscallrecord *rec)
{
	struct cachestat_range *range;
	struct cachestat *cs;

	range = (struct cachestat_range *) get_writable_address(sizeof(*range));

	switch (rand() % 4) {
	case 0: /* entire file */
		range->off = 0;
		range->len = 0;	/* 0 means "to end of file" */
		break;
	case 1: /* first page */
		range->off = 0;
		range->len = page_size;
		break;
	case 2: /* random offset, one page */
		range->off = (unsigned long long) page_size * (rand() % 256);
		range->len = page_size;
		break;
	default: /* random range */
		range->off = rand32();
		range->len = 1 + (rand() % (page_size * 64));
		break;
	}

	cs = (struct cachestat *) get_writable_address(sizeof(*cs));

	rec->a2 = (unsigned long) range;
	rec->a3 = (unsigned long) cs;
}

struct syscallentry syscall_cachestat = {
	.name = "cachestat",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cstat_range",
	.arg3name = "cstat",
	.arg4name = "flags",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_cachestat,
};
