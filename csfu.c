/*
 * copy_struct_from_user() bucket-aware userspace struct builder.
 *
 * See include/csfu.h for the five-bucket model and the rationale for
 * centralising it.  This file owns the bucket-pick distribution and
 * the tail-byte mutation; callers retain ownership of the kernel-
 * known field fill (since field semantics are syscall-specific) and
 * of the eventual deferred_free_enqueue().
 */

#include <stdint.h>

#include "csfu.h"
#include "rnd.h"
#include "utils.h"

/*
 * Extra bytes allocated past @desc->ksize so the OVERSIZE_* and
 * TAIL_MISMATCH buckets have a real, in-bounds tail to mutate.  32
 * is the same slack the open-coded openat2 sanitiser used before
 * migrating; large enough that pick_tail_extension() has room to
 * vary the declared usize, small enough that the allocation cost
 * stays under one cache line for the typical (small) CSFU struct.
 */
#define CSFU_TAIL_SLACK	32

/*
 * Bucket distribution.  EXACT dominates at 60% so the syscall reaches
 * the post-validator code paths -- where the interesting bugs live --
 * the majority of the time.  The four mutation buckets split the
 * remaining 40% evenly at 10% each.  Mirrors the canonical-dominant
 * weighting the openat2 sanitiser was already using (70% exact, 30%
 * split across mutation), shifted slightly to make room for the two
 * extra buckets (OVERSIZE_NONZERO, TAIL_MISMATCH) the open-coded
 * version did not cover.
 */
static enum csfu_bucket csfu_pick_bucket(void)
{
	uint32_t pick = rnd_modulo_u32(100);

	if (pick < 60)
		return CSFU_BUCKET_EXACT;
	if (pick < 70)
		return CSFU_BUCKET_UNDERSIZE;
	if (pick < 80)
		return CSFU_BUCKET_OVERSIZE_ZERO;
	if (pick < 90)
		return CSFU_BUCKET_OVERSIZE_NONZERO;
	return CSFU_BUCKET_TAIL_MISMATCH;
}

/*
 * Choose how far past ksize the declared usize stretches.  Returns
 * a value in [1, slack]: at least one tail byte is always declared
 * so the OVERSIZE_* buckets actually exercise the tail-zero check.
 */
static size_t csfu_pick_tail_extension(size_t slack)
{
	if (slack == 0)
		return 0;
	return 1 + rnd_modulo_u32((uint32_t) slack);
}

struct csfu_buf build_csfu_struct(const struct csfu_desc *desc)
{
	struct csfu_buf out;
	uint8_t *bytes;
	size_t tail_off;
	size_t tail_len;
	size_t i;

	out.buflen = desc->ksize + CSFU_TAIL_SLACK;
	bytes = zmalloc_tracked(out.buflen);
	out.ptr = bytes;
	out.bucket = csfu_pick_bucket();

	switch (out.bucket) {
	case CSFU_BUCKET_UNDERSIZE:
		/*
		 * If the consumer supplied a curated pool of meaningful
		 * pre-ksize sizes (e.g. ABI-floor sizes like
		 * CLONE_ARGS_SIZE_VER0), draw uniformly from it.
		 * Otherwise pick a uniformly-random size in [0, ksize) --
		 * includes the usize == 0 corner, which most CSFU
		 * consumers reject with -EINVAL but is worth exercising
		 * for the validator coverage.
		 */
		if (desc->known_sizes != NULL && desc->n_known_sizes > 0)
			out.usize = desc->known_sizes[rnd_modulo_u32((uint32_t) desc->n_known_sizes)];
		else
			out.usize = rnd_modulo_u32((uint32_t) desc->ksize);
		/* known_sizes[] entries are caller-curated and may exceed buflen;
		 * relocate-by-size copies usize bytes, so an unclamped pick would
		 * read past the end of the buffer. */
		out.usize = min(out.usize, out.buflen);
		break;

	case CSFU_BUCKET_EXACT:
		out.usize = desc->ksize;
		break;

	case CSFU_BUCKET_OVERSIZE_ZERO:
		/* zmalloc already zeroed the tail; just declare the usize. */
		out.usize = desc->ksize + csfu_pick_tail_extension(CSFU_TAIL_SLACK);
		break;

	case CSFU_BUCKET_OVERSIZE_NONZERO:
		tail_len = csfu_pick_tail_extension(CSFU_TAIL_SLACK);
		out.usize = desc->ksize + tail_len;
		/* OR-in 1 guarantees every byte is nonzero -- -E2BIG every time. */
		for (i = 0; i < tail_len; i++)
			bytes[desc->ksize + i] = (uint8_t) (rnd_u32() | 1);
		break;

	case CSFU_BUCKET_TAIL_MISMATCH:
		/*
		 * Single stray nonzero byte at a uniformly-chosen offset
		 * inside the declared tail.  Exercises the boundary cases
		 * (first byte past ksize, last byte before usize, and the
		 * interior); the kernel's check_zeroed_user word-vs-byte
		 * loop has had off-by-one bugs at exactly these offsets
		 * before.
		 */
		tail_len = csfu_pick_tail_extension(CSFU_TAIL_SLACK);
		out.usize = desc->ksize + tail_len;
		tail_off = rnd_modulo_u32((uint32_t) tail_len);
		bytes[desc->ksize + tail_off] = (uint8_t) (rnd_u32() | 1);
		break;

	case CSFU_NR_BUCKETS:
		/* unreachable; csfu_pick_bucket never returns the sentinel */
		out.usize = desc->ksize;
		break;
	}

	/*
	 * In-band size-field fix-up.  CSFU-shaped syscalls whose usize
	 * lives inside the struct (statmount/listmount/listns/...) need
	 * that slot to match the bucket-chosen usize or the kernel rejects
	 * the call before the validator path we want to exercise.  Width
	 * is per-desc so we can target __u32-typed slots (mnt_id_req.size)
	 * without smearing into the adjacent member.
	 */
	if (desc->size_field_width > 0) {
		uint64_t v = (uint64_t) out.usize;

		switch (desc->size_field_width) {
		case 4:
			*(uint32_t *)(bytes + desc->size_field_off) =
				(uint32_t) v;
			break;
		case 8:
			*(uint64_t *)(bytes + desc->size_field_off) = v;
			break;
		}
	}

	return out;
}
