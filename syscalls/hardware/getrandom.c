/*
 * SYSCALL_DEFINE3(getrandom, char __user *, buf, size_t, count, unsigned int, flags)
 */
#include <errno.h>
#include <stdint.h>
#include "maps.h"
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "utils-alloc.h"
#include "utils-mem.h"

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

/*
 * Snapshot of the buf user pointer plus the fixed poison pattern
 * stamped across it, captured at sanitise time and consumed by
 * post_getrandom.  Lives in rec->post_state, a slot the syscall ABI
 * does not expose, so a sibling scribbling rec->a1 between the
 * syscall returning and the post handler running cannot redirect
 * the poison check against an unrelated heap page whose residual
 * bytes happen to still match the fixed pattern.  A poison_seed of
 * 0 means the sanitise-time writability check refused to stamp for
 * this call (writable-pool draw no longer provably mapped after
 * avoid_shared_buffer_out) and the post handler must no-op the
 * untouched-buffer arm.  addr == 0 signals buf was NULL and the
 * post handler no-ops that case too since there is nothing to
 * check.
 */
#define GETRANDOM_POST_STATE_MAGIC	0x47524e44UL	/* "GRND" */
#define GETRANDOM_POISON_PATTERN	0xE9F1E9F1E9F1E9F1ULL

struct getrandom_post_state {
	unsigned long magic;
	unsigned long addr;
	uint64_t poison_seed;
};

static void sanitise_getrandom(struct syscallrecord *rec)
{
	struct getrandom_post_state *snap;
	struct map *map;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a
	 * stale pointer carried over from an earlier syscall on this
	 * record.
	 */
	rec->post_state = 0;

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

	/*
	 * Stamp a fixed poison pattern across the count bytes the kernel
	 * writes on success.  The post handler compares the first
	 * min(retval, CHECK_OUTPUT_STRUCT_SNAP_MAX) bytes byte-for-byte
	 * against the same pattern; a match after a rec->retval > 0
	 * return means the kernel reported success without writing any
	 * random bytes into the buffer -- a use-uninitialised-memory
	 * hazard the caller would then feed straight into a key or a
	 * nonce.  Random getrandom output essentially never reproduces
	 * a fixed 8-byte pattern, so false positives are near zero.
	 * Pattern is a fixed non-zero magic (not rnd_u64()) so the
	 * sanitise pass draws no RNG bytes on this leg: --dry-run output
	 * with a fixed seed stays byte-identical to a build without this
	 * oracle, keeping cross-tree replays and fixed-seed corpus
	 * regeneration unaffected.  Snapshot rec->a1 into snap so a
	 * sibling scribble of the ABI slot between syscall return and
	 * post entry cannot redirect the check.  Gate on
	 * range_readable_user() so a writable-pool draw that
	 * avoid_shared_buffer_out moved to an address no longer provably
	 * mapped does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk; on skip poison_seed stays 0
	 * and the post handler no-ops the arm.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = GETRANDOM_POST_STATE_MAGIC;
	snap->addr        = rec->a1;
	snap->poison_seed = 0;

	if (rec->a1 != 0 && rec->a2 != 0) {
		buf = (void *)(unsigned long) rec->a1;
		if (range_readable_user(buf, rec->a2))
			snap->poison_seed =
				poison_output_struct(buf, rec->a2,
						     GETRANDOM_POISON_PATTERN);
	}

	post_state_install(rec, snap);
}

/*
 * Oracle: getrandom on success returns the number of random bytes
 * written (>= 0) into the caller's buf.  A byte-identical match
 * against the fixed poison pattern after a success return with
 * retval > 0 means the kernel reported success but skipped
 * copy_to_user for the checked region -- the caller would then feed
 * the untouched poison bytes into whatever key or nonce prompted
 * the getrandom() call.  Only retval bytes are checked, not the
 * full requested count: partial returns write only what they
 * report.  Error returns (retval < 0), zero-byte returns (retval
 * == 0, nothing was written and nothing to check), calls where
 * sanitise refused to stamp (poison_seed == 0), and NULL-buf calls
 * (snap->addr == 0) stay silent.  The
 * check_output_struct_user_or_skip SNAP_MAX cap silently drops
 * checks larger than that ceiling, so multi-KB requests trade
 * coverage for a bounded post-handler cost.  Measure-only: no
 * re-issue, no argument mutation, no oracle output beyond the
 * counter bump.
 */
static void post_getrandom(struct syscallrecord *rec)
{
	struct getrandom_post_state *snap;

	snap = post_state_claim_owned(rec, GETRANDOM_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval <= 0)
		goto out_release;

	if (snap->addr != 0 && snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->addr,
					     (size_t) rec->retval,
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

static unsigned long getrandom_flags[] = {
	GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE,
};

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
	.flags = REEXEC_SANITISE_OK,
};
