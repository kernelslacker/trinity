/*
 * SYSCALL_DEFINE(fallocate)(int fd, int mode, loff_t offset, loff_t len)
 *
 * fallocate() returns zero on success, and -1 on failure.
 */
#include <stdint.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#define FALLOC_FL_KEEP_SIZE	0x01
#define FALLOC_FL_PUNCH_HOLE	0x02
#define FALLOC_FL_NO_HIDE_STALE 0x04
#define FALLOC_FL_COLLAPSE_RANGE 0x08
#define FALLOC_FL_ZERO_RANGE 0x10
#define FALLOC_FL_INSERT_RANGE 0x20
#define FALLOC_FL_UNSHARE_RANGE 0x40

#define FALLOCATE_BLOCK_ALIGN	4096ULL

static unsigned long fallocate_modes[] = {
	FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE,
	FALLOC_FL_NO_HIDE_STALE, FALLOC_FL_COLLAPSE_RANGE,
	FALLOC_FL_ZERO_RANGE, FALLOC_FL_INSERT_RANGE,
	FALLOC_FL_UNSHARE_RANGE,
};

/*
 * fallocate(2) mode is not a freely combinable bitmask: the kernel
 * enforces a small set of legal mode combinations and rejects the
 * rest with EOPNOTSUPP before reaching the per-filesystem
 * fallocate_op.  The combos below are the ones the manpage and
 * fs/open.c's vfs_fallocate() validator actually accept:
 *
 *   - 0                                       default allocate
 *   - FALLOC_FL_KEEP_SIZE                     allocate without size bump
 *   - FALLOC_FL_PUNCH_HOLE | KEEP_SIZE        PUNCH_HOLE requires KEEP_SIZE
 *   - FALLOC_FL_ZERO_RANGE [| KEEP_SIZE]
 *   - FALLOC_FL_COLLAPSE_RANGE                exclusive with KEEP_SIZE
 *   - FALLOC_FL_INSERT_RANGE                  exclusive with KEEP_SIZE
 *   - FALLOC_FL_UNSHARE_RANGE [| KEEP_SIZE]
 *
 * Random bitmask draws over fallocate_modes[] generate the
 * COLLAPSE|KEEP_SIZE / INSERT|KEEP_SIZE / PUNCH_HOLE-without-KEEP_SIZE
 * shapes that the validator reject, so the actual filesystem path
 * almost never runs.  The combo table makes those legal mode shapes
 * the common case.
 */
static const unsigned long fallocate_valid_combos[] = {
	0,
	FALLOC_FL_KEEP_SIZE,
	FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
	FALLOC_FL_ZERO_RANGE,
	FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
	FALLOC_FL_COLLAPSE_RANGE,
	FALLOC_FL_INSERT_RANGE,
	FALLOC_FL_UNSHARE_RANGE,
	FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_KEEP_SIZE,
};

/*
 * Unrelated bits to OR onto a valid combo for the "+1 garbage bit"
 * bucket.  Covers FALLOC_FL_NO_HIDE_STALE (legacy, accepted only on
 * very specific paths) plus a sprinkling of the next bits past the
 * defined set so the kernel's reserved-bit validator gets exercised.
 */
static const unsigned long fallocate_extra_bits[] = {
	FALLOC_FL_NO_HIDE_STALE,
	0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
};

static void sanitise_fallocate(struct syscallrecord *rec)
{
	uint32_t pick = rnd_modulo_u32(100);
	unsigned long mode;
	int64_t offset, len;

	if (pick < 75) {
		mode = RAND_ARRAY(fallocate_valid_combos);
	} else if (pick < 90) {
		mode = RAND_ARRAY(fallocate_valid_combos) |
		       RAND_ARRAY(fallocate_extra_bits);
	} else {
		mode = set_rand_bitmask(ARRAY_SIZE(fallocate_modes),
					fallocate_modes);
	}
	rec->a2 = mode;

	offset = RAND_RANGE(0ULL, 1ULL << 30);	/* [0, 1 GB] */
	len = RAND_RANGE(1ULL, 64ULL << 20);	/* [1, 64 MB] */

	/*
	 * COLLAPSE_RANGE and INSERT_RANGE require fs-block-aligned
	 * offset and length: the kernel returns EINVAL before reaching
	 * the per-filesystem op otherwise.  Most modern filesystems use
	 * a 4 KiB block, so floor-align to that and bump len up off
	 * zero if the mask wiped it.
	 */
	if (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE)) {
		offset &= ~(int64_t)(FALLOCATE_BLOCK_ALIGN - 1);
		len &= ~(int64_t)(FALLOCATE_BLOCK_ALIGN - 1);
		if (len == 0)
			len = FALLOCATE_BLOCK_ALIGN;
	}

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
