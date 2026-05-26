/*
 * SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
	int, fd_out, loff_t __user *, off_out,
	size_t, len, unsigned int, flags)
 */
#include <fcntl.h>
#include "files.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

static unsigned long splice_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

/*
 * splice_flags[] is still wired up to ARG_LIST so the argument
 * generator has a default to publish; sanitise_splice overrides
 * rec->a6 below with an explicit bucket draw.  ARG_LIST's single-bit
 * pick never reaches the zero-flags arm, the 11 multi-bit subsets
 * of {MOVE,NONBLOCK,MORE,GIFT}, or the invalid-high-bit reject path.
 * splice_check_flags() in fs/splice.c rejects any bit >= 0x10 with
 * -EINVAL; all 16 subsets of the valid bits are legal.
 */
static unsigned long sanitise_splice_flags(void)
{
	unsigned int pick = rnd_modulo_u32(20);

	switch (pick) {
	case 0 ... 3:
		/* (a) 20%: zero-flag arm. */
		return 0;
	case 4 ... 6:
		/* (b) 15%: NONBLOCK alone. */
		return SPLICE_F_NONBLOCK;
	case 7 ... 8:
		/* (c) 10%: MORE alone. */
		return SPLICE_F_MORE;
	case 9 ... 11:
		/* (d) 15%: NONBLOCK | MORE canonical pair. */
		return SPLICE_F_NONBLOCK | SPLICE_F_MORE;
	case 12:
		/* (e) 5%: MOVE alone. */
		return SPLICE_F_MOVE;
	case 13:
		/* (f) 5%: GIFT alone. */
		return SPLICE_F_GIFT;
	case 14 ... 15:
		/* (g) 10%: random subset of the four valid bits. */
		return set_rand_bitmask(ARRAY_SIZE(splice_flags), splice_flags);
	case 16:
		/* (h) 5%: all four bits set. */
		return SPLICE_F_MOVE | SPLICE_F_NONBLOCK |
		       SPLICE_F_MORE | SPLICE_F_GIFT;
	case 17 ... 18:
		/* (i) 10%: preserve ARG_LIST-style single bit pick. */
		return splice_flags[rnd_modulo_u32(ARRAY_SIZE(splice_flags))];
	default: {
		/* (j) 5%: invalid high bit -- kernel reject path. */
		static const unsigned long invalid[] = {
			0x10UL, 0x100UL, 0x80000000UL,
		};
		return invalid[rnd_modulo_u32(ARRAY_SIZE(invalid))];
	}
	}
}

static void sanitise_splice(struct syscallrecord *rec)
{
	loff_t *off_in = (loff_t *) get_writable_address(sizeof(loff_t));
	loff_t *off_out = (loff_t *) get_writable_address(sizeof(loff_t));

	if (off_in == NULL || off_out == NULL)
		return;

	*off_in = RAND_RANGE(0ULL, 1ULL << 30);
	*off_out = RAND_RANGE(0ULL, 1ULL << 30);
	rec->a2 = (unsigned long) off_in;
	rec->a4 = (unsigned long) off_out;

	/*
	 * ~25% of the time, replace fd_in with a page-cache-backed fd so
	 * we exercise splice_read_to_pipe() against real backing pages
	 * instead of the default pipe-to-pipe shuffle.  argtype stays
	 * ARG_FD_PIPE so the natural pipe→pipe coverage is preserved on
	 * the other 75%.  A -1 from get_rand_pagecache_fd() (provider
	 * disabled or pool empty) leaves rec->a1 untouched.
	 */
	if ((rnd_modulo_u32(100)) < 25) {
		int fd = get_rand_pagecache_fd();

		if (fd >= 0)
			rec->a1 = fd;
	}

	/* ~20%: regular-file fd_out routes through iter_file_splice_write. */
	if ((rnd_modulo_u32(100)) < 20) {
		int fd = get_rand_pagecache_fd();

		if (fd >= 0)
			rec->a3 = fd;
	}

	/* ~5%: same-fd terminal override -- kernel rejects overlap EINVAL. */
	if ((rnd_modulo_u32(100)) < 5)
		rec->a3 = rec->a1;

	rec->a6 = sanitise_splice_flags();
}

struct syscallentry syscall_splice = {
	.name = "splice",
	.num_args = 6,
	.argtype = { [0] = ARG_FD_PIPE, [1] = ARG_ADDRESS, [2] = ARG_FD_PIPE, [3] = ARG_ADDRESS, [4] = ARG_LEN, [5] = ARG_LIST },
	.argname = { [0] = "fd_in", [1] = "off_in", [2] = "fd_out", [3] = "off_out", [4] = "len", [5] = "flags" },
	.arg_params[5].list = ARGLIST(splice_flags),
	.sanitise = sanitise_splice,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.rettype = RET_NUM_BYTES,
	.bound_arg = 5,
};
