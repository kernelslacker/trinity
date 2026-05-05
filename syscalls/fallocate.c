/*
 * SYSCALL_DEFINE(fallocate)(int fd, int mode, loff_t offset, loff_t len)
 *
 * fallocate() returns zero on success, and -1 on failure.
 */
#include <stdint.h>
#include "random.h"
#include "sanitise.h"

#define FALLOC_FL_KEEP_SIZE	0x01
#define FALLOC_FL_PUNCH_HOLE	0x02
#define FALLOC_FL_NO_HIDE_STALE 0x04
#define FALLOC_FL_COLLAPSE_RANGE 0x08
#define FALLOC_FL_ZERO_RANGE 0x10
#define FALLOC_FL_INSERT_RANGE 0x20
#define FALLOC_FL_UNSHARE_RANGE 0x40

static unsigned long fallocate_modes[] = {
	FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE,
	FALLOC_FL_NO_HIDE_STALE, FALLOC_FL_COLLAPSE_RANGE,
	FALLOC_FL_ZERO_RANGE, FALLOC_FL_INSERT_RANGE,
	FALLOC_FL_UNSHARE_RANGE,
};

static void sanitise_fallocate(struct syscallrecord *rec)
{
	int64_t offset = RAND_RANGE(0, 1ULL << 30);	/* [0, 1 GB] */
	int64_t len = RAND_RANGE(1, 64ULL << 20);	/* [1, 64 MB] */

	/* Prevent offset+len from overflowing loff_t */
	if (len > INT64_MAX - offset)
		len = INT64_MAX - offset;

	rec->a3 = (unsigned long) offset;
	rec->a4 = (unsigned long) len;
}

struct syscallentry syscall_fallocate = {
	.name = "fallocate",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_LIST, [2] = ARG_LEN, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "mode", [2] = "offset", [3] = "len" },
	.arg_params[1].list = ARGLIST(fallocate_modes),
	.sanitise = sanitise_fallocate,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
