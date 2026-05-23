/*
 * SYSCALL_DEFINE3(getrandom, char __user *, buf, size_t, count, unsigned int, flags)
 */
#include <errno.h>
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK  0x0001
#endif
#ifndef GRND_RANDOM
#define GRND_RANDOM    0x0002
#endif
#ifndef GRND_INSECURE
#define GRND_INSECURE  0x0004
#endif

/*
 * Explicit flag combos.  The ARG_LIST draw OR's a random subset of
 * { GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE } via set_rand_bitmask,
 * which forces at least one bit -- so the zero-flags case (the default
 * urandom path through urandom_read_iter) is unreachable.  The list
 * also picks the meaningful pairwise combos only by accident.  Drive
 * rec->a3 from a hand-built pool so each named combination including
 * the zero entry gets even weight; a random-bits bucket keeps the
 * EINVAL validation path that rejects undefined bits warm.
 */
static const unsigned long getrandom_valid_combos[] = {
	0,
	GRND_RANDOM,
	GRND_NONBLOCK,
	GRND_INSECURE,
	GRND_RANDOM | GRND_NONBLOCK,
	GRND_INSECURE | GRND_NONBLOCK,
};

/*
 * Size boundary pool.  Hits each side of the page boundary and the
 * GETRANDOM_MAX_CHUNK (256 KiB) chunking split point inside the
 * urandom read iterator.  Zero-size must succeed with no bytes
 * written; the page-edge values exercise the partial-chunk logic;
 * 256 KiB checks the loop that breaks after each chunk to let
 * signals interrupt long copies.  A random-bytes-up-to-a-few-MB
 * bucket covers everything above the chunk boundary.
 */
static const unsigned long getrandom_sizes[] = {
	0, 1, 16, 256, 4095, 4096, 4097, 256 * 1024,
};

static void sanitise_getrandom(struct syscallrecord *rec)
{
	struct map *map;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL)
		return;

	/*
	 * Override the buffer length first so the avoid_shared_buffer_out
	 * call below sees the chosen size when deciding whether to relocate.
	 * ~90% from the boundary pool, ~10% a random multi-page size capped
	 * at a few MB so it still fits in the largest pool mappings.
	 */
	if (ONE_IN(10))
		rec->a2 = rnd_modulo_u32(MB(4)) + 1;
	else
		rec->a2 = RAND_ARRAY(getrandom_sizes);

	/*
	 * Override flags.  ~85% explicit named combos so each one gets
	 * even attention, ~15% random low-byte bits to keep the
	 * undefined-flags rejection path warm.
	 */
	if (rnd_modulo_u32(20) < 17)
		rec->a3 = RAND_ARRAY(getrandom_valid_combos);
	else
		rec->a3 = rnd_u32() & 0xff;

	avoid_shared_buffer_out(&rec->a1, rec->a2);
}

static unsigned long getrandom_flags[] = {
	GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE,
};

static void post_getrandom(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || (size_t) ret > (size_t) rec->a2)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_getrandom = {
	.name = "getrandom",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "buf", [1] = "count", [2] = "flags" },
	.arg_params[2].list = ARGLIST(getrandom_flags),
	.sanitise = sanitise_getrandom,
	.post = post_getrandom,
	.group = GROUP_PROCESS,
	.bound_arg = 2,
	.rettype = RET_NUM_BYTES,
};
