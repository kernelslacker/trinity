/*
 * Poison / check helpers for ARG_STRUCT_PTR_OUT buffers.
 *
 * Sanitise-side: stamp a deterministic byte pattern into the buffer the
 * kernel is about to write into.  Post-side: re-read the buffer and
 * report whether every byte still equals the original pattern.  An
 * unchanged buffer after a "success" return means the kernel claimed
 * the call succeeded without copying any output -- a class of bug the
 * downstream oracles can also catch through field-level divergence,
 * but only after paying for a re-issue of the syscall.  This check is
 * O(struct size) and surfaces the same bug class without re-entering
 * the kernel.
 *
 * Pattern is the 8 bytes of `seed` repeated across the buffer (byte i
 * is seed >> ((i & 7) * 8)).  Generated once in poison_output_struct
 * (rnd_u64() when the caller passes seed == 0), returned to the caller
 * so it can stash the value next to the other post-handler state, and
 * fed back in to check_output_struct from the post handler.  The
 * helpers do not log, exit, or otherwise change control flow -- the
 * caller decides what to do with the result.
 */
#include "output-poison.h"
#include "rnd.h"
#include "signals.h"
#include "utils-mem.h"

/* seed is volatile: it is written before and read after the sigsetjmp below,
 * so -Werror=clobbered requires it survive a siglongjmp unclobbered. */
uint64_t poison_output_struct(void *buf, size_t sz, volatile uint64_t seed)
{
	volatile unsigned char *p = buf;
	volatile size_t i;

	if (buf == NULL || sz == 0)
		return 0;

	/*
	 * Prove the buffer is a tracked RW region before writing into it.
	 * range_readable_user only approves alloc_shared() and libc-heap
	 * mappings, both PROT_READ|PROT_WRITE by construction, so a pass here
	 * means the poison write lands in writable memory; a fuzz-introduced
	 * read-only or unmapped OUT pointer is rejected (return 0) rather than
	 * faulting the raw write.  Returning 0 routes through the caller's
	 * `poison_seed == 0` gate, which skips the .post check.  This raw
	 * write, gated only on the caller's readability probe, was the
	 * SEGV_ACCERR storm the writeback-oracle wave caused (2026-07-14).
	 */
	if (!range_readable_user(buf, sz))
		return 0;

	if (seed == 0)
		seed = rnd_u64();
	/*
	 * splitmix64 cannot return 0 from a non-zero state, but be defensive
	 * -- a degenerate seed of 0 would make every byte a legitimate
	 * "untouched" value AND a legitimate "kernel wrote 0" value, so the
	 * check would never trigger or would always trigger.
	 */
	if (seed == 0)
		seed = 0xAAAAAAAAAAAAAAAAULL;

	/*
	 * TOCTOU: a sibling mprotect/munmap between the check above and the
	 * write can still fault.  Guard the write with the asb_copy sigsetjmp
	 * slot (the same recovery post_snapshot_or_skip uses) so a fault
	 * degrades to "not poisoned" (return 0 -> caller skips) rather than a
	 * child crash.
	 */
	if (sigsetjmp(asb_copy_recover, 1) != 0) {
		asb_copy_active = 0;
		return 0;
	}
	asb_copy_active = 1;
	for (i = 0; i < sz; i++)
		p[i] = (unsigned char) (seed >> ((i & 7) * 8));
	asb_copy_active = 0;

	return seed;
}

bool check_output_struct(const void *buf, size_t sz, uint64_t seed)
{
	const unsigned char *p = buf;
	size_t i;

	for (i = 0; i < sz; i++) {
		if (p[i] != (unsigned char) (seed >> ((i & 7) * 8)))
			return false;
	}
	return true;
}

bool check_output_struct_user_or_skip(const void *user, size_t sz,
				      uint64_t seed)
{
	unsigned char snap[CHECK_OUTPUT_STRUCT_SNAP_MAX];

	if (sz == 0 || sz > sizeof(snap))
		return false;

	if (!post_snapshot_or_skip(snap, user, sz))
		return false;

	return check_output_struct(snap, sz, seed);
}
