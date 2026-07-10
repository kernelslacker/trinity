/*
 * SYSCALL_DEFINE4(cachestat, unsigned int, fd,
 *		struct cachestat_range __user *, cstat_range,
 *		struct cachestat __user *, cstat, unsigned int, flags)
 */
#include <sys/stat.h>
#include <linux/mman.h>
#include "arch.h"
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the cachestat output-buffer pointer + poison seed the
 * post oracle needs, captured at sanitise time.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot retarget the untouched-buffer
 * check at a foreign user allocation.  The poison seed travels with
 * the pointer so a stomp cannot smear the seed against a heap page
 * that happens to still carry a residual pattern from an earlier
 * call.
 */
#define CACHESTAT_POST_STATE_MAGIC	0x43535441UL	/* "CSTA" */
struct cachestat_post_state {
	unsigned long magic;
	unsigned long cstat;
	uint64_t poison_seed;
};

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
	struct cachestat_post_state *snap;
	void *buf;

	rec->post_state = 0;

	range = (struct cachestat_range *) get_writable_struct(sizeof(*range));
	if (!range)
		return;

	pick_range((int) rec->a1, range);

	cs = (struct cachestat *) get_writable_struct(sizeof(*cs));
	if (!cs)
		return;

	rec->a2 = (unsigned long) range;
	avoid_shared_buffer_inout(&rec->a2, sizeof(*range));
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

	/*
	 * See sanitise_fstat64 for the full rationale: writing a poison
	 * pattern into an unmapped or non-writable user address would
	 * SIGSEGV the sanitiser and mask the syscall path we are trying
	 * to fuzz.  range_readable_user() proves the range from cached
	 * VMA state before we touch it; the writable-pool page backing
	 * cs is track_shared_region()'d so this check nearly always
	 * passes, but the gate closes the sibling-munmap window where a
	 * fuzzed munmap has torn down the tracked region between the
	 * pool allocation and the poison stamp.  On skip, rec->post_state
	 * stays 0 and the post handler no-ops via post_state_claim_owned()
	 * returning NULL.
	 */
	buf = (void *)(unsigned long) rec->a3;
	if (!range_readable_user(buf, sizeof(struct cachestat)))
		return;

	/*
	 * Snapshot the output-buffer pointer + poison seed for the post
	 * oracle.  Without this the post handler reads rec->a3 at
	 * post-time, when a sibling syscall may have scribbled the slot:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original user cstat pointer, so the poison
	 * check would touch a foreign allocation and mistake stale bytes
	 * elsewhere for a real "untouched" signal.  Stamp the poison
	 * after avoid_shared_buffer_out() so it lands on the final buffer
	 * the kernel will see; the returned seed is fed back into
	 * check_output_struct() in the post handler.  post_state is
	 * private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = CACHESTAT_POST_STATE_MAGIC;
	snap->cstat       = rec->a3;
	snap->poison_seed = poison_output_struct(buf, sizeof(struct cachestat), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: cachestat(fd, cstat_range, cstat, flags) writes a struct
 * cachestat describing the page-cache residency of the requested
 * range into the user cstat buffer.  This post handler catches the
 * "returned success but wrote zero bytes" bug shape by stamping a
 * per-call poison pattern into the output buffer at sanitise time
 * and asking check_output_struct() whether the pattern survived
 * intact on a success return.  A byte-identical poison after a
 * 0-retval means the kernel never called copy_to_user() at all, or
 * copied fewer bytes than sizeof(struct cachestat) implies and left
 * an uninitialised-field tail readable in user memory (a
 * kernel->user infoleak).  Snapshot the buffer via
 * post_snapshot_or_skip so a sibling munmap of the writable-pool
 * page between syscall return and the poison compare degrades to a
 * skipped sample instead of a SIGSEGV in check_output_struct's
 * byte-walk; false from the snapshot means the buffer is not
 * provably readable now and the sample is skipped.  Counts against
 * the shared post_handler_untouched_out_buf slot -- no per-syscall
 * counter here, so this file stays a one-file change.
 */
static void post_cachestat(struct syscallrecord *rec)
{
	struct cachestat_post_state *snap;
	struct cachestat snapshot;

	snap = post_state_claim_owned(rec, CACHESTAT_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (!post_snapshot_or_skip(&snapshot,
				   (void *)(unsigned long) snap->cstat,
				   sizeof(snapshot)))
		goto out_release;

	if (check_output_struct(&snapshot, sizeof(snapshot), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_cachestat = {
	.name = "cachestat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "fd", [1] = "cstat_range", [2] = "cstat", [3] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_cachestat,
	.post = post_cachestat,
	.flags = REEXEC_SANITISE_OK,
};
