#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "child.h"
#include "debug.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"

#include "kernel/fcntl.h"
/*
 * Render a PROT_* mask as "READ|WRITE|EXEC" into the caller-provided
 * buffer.  Empties to "NONE" for prot==PROT_NONE so the diagnostic line
 * is never silently truncated to nothing between the brackets.  Unknown
 * upper bits (PROT_GROWSDOWN, pkey bits, ...) are left to the raw
 * 0x%x rendering at the call site.
 */
static void prot_to_string(int prot, char *buf, size_t buflen)
{
	int n = 0;
	int written;

	if (buf == NULL || buflen == 0)
		return;

	buf[0] = '\0';

	/* snprintf returns the would-have-written length even when truncated.
	 * Naive `n += snprintf(buf+n, buflen-n, ...)` advances n past buflen
	 * once the buffer fills, so the next call writes outside buf.  Currently
	 * safe at buflen=32 with the three short strings but identical cliff
	 * to the stats.c stack-depth histogram cumulator.  Bound n each step. */
	if ((prot & PROT_READ) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n, "READ");
		if (written > 0)
			n += written;
	}
	if ((prot & PROT_WRITE) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n,
				   "%sWRITE", n ? "|" : "");
		if (written > 0)
			n += written;
	}
	if ((prot & PROT_EXEC) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n,
				   "%sEXEC", n ? "|" : "");
		if (written > 0)
			n += written;
	}

	if (n == 0)
		snprintf(buf, buflen, "NONE");
}

static const char *mprotect_errstr(int err)
{
	switch (err) {
	case ENOMEM:	return "ENOMEM";
	case EACCES:	return "EACCES";
	case EINVAL:	return "EINVAL";
	case EAGAIN:	return "EAGAIN";
	case EFAULT:	return "EFAULT";
	default:	return "unknown error";
	}
}

void log_mprotect_failure(void *addr, size_t len, int prot,
			  void *caller, int err)
{
	char protbuf[32];
	char pcbuf[128];

	prot_to_string(prot, protbuf, sizeof(protbuf));
	outputerr("mprotect(addr=%p, len=%zu, prot=0x%x [%s]) failed at %s: %s\n",
		  addr, len, prot, protbuf,
		  pc_to_string(caller, pcbuf, sizeof(pcbuf)),
		  mprotect_errstr(err));
}


/* Tunable: how often range_overlaps_shared() emits a -v summary line.
 * Lower = noisier, higher = blunter. */
#define RANGE_OVERLAPS_SHARED_REJECT_REPORT_INTERVAL 10000

/* Sibling tunable for the size-bucket bitmap short-circuit path.
 * Same cadence as the rejects line above so the two -v summaries
 * stay in lockstep when both fire on the same child. */
#define RANGE_OVERLAPS_SHARED_BM_SKIP_REPORT_INTERVAL 10000

/*
 * Exact byte-range overlap confirmation after a bitmap hit.  The
 * bitmap rounds tracked regions up to 2 MiB chunks, so a hit means
 * "some tracked region lives in a chunk that touches the query" --
 * not that the query and the region share a byte.  Walking the two
 * region arrays here resolves the false positives in which a valid,
 * disjoint mm-syscall range shares a 2 MiB chunk with a tracked
 * allocation; the bitmap previously rejected those unconditionally,
 * losing real munmap / mremap / madvise / mprotect / mseal / mbind
 * coverage on hosts where allocations cluster.
 *
 * Semantics match the pre-bitmap byte-precise test:
 *   - a non-empty range [addr, end) overlaps [rstart, rend) iff
 *     addr < rend && rstart < end (standard interval overlap);
 *   - an empty (len == 0) range matches iff @addr is strictly inside
 *     a region (rstart <= addr < rend), which is the only empty-range
 *     case the original test accepted.
 *
 * Zero-size tracked regions never overlap anything, matching the
 * alloc_shared() / track_shared_region() callers that treat size==0
 * as "no region" (and matching shared_bitmap_mark()'s no-op on size 0).
 *
 * Returning false here only removes false-positive rejects; it never
 * accepts a query that truly overlaps a tracked region, so the safety
 * invariant the callers rely on (no fuzzed mm-syscall clobbers a
 * trinity-owned shared mapping) is preserved.
 */
static bool shared_regions_exact_overlap(unsigned long addr,
					 unsigned long len,
					 unsigned long end)
{
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		unsigned long rstart = shared_regions[i].addr;
		unsigned long rsize = shared_regions[i].size;
		unsigned long rend;

		if (rsize == 0)
			continue;
		rend = rstart + rsize;

		if (len == 0) {
			if (addr >= rstart && addr < rend)
				return true;
		} else {
			if (addr < rend && rstart < end)
				return true;
		}
	}

	for (i = 0; i < nr_shared_regions_overflow; i++) {
		unsigned long rstart = shared_regions_overflow[i].addr;
		unsigned long rsize = shared_regions_overflow[i].size;
		unsigned long rend;

		if (rsize == 0)
			continue;
		rend = rstart + rsize;

		if (len == 0) {
			if (addr >= rstart && addr < rend)
				return true;
		} else {
			if (addr < rend && rstart < end)
				return true;
		}
	}

	return false;
}

/* Last syscall to trip a range_overlaps_shared() reject.  Last-write-wins;
 * a coarse hint for which sanitiser is doing the most work, not a precise
 * audit trail.  Process-local statics: each child has its own copy, the
 * writer and the reader (the periodic -v summary below) live in the same
 * single-threaded child, so plain accesses suffice.  Torn reads are
 * acceptable for a diagnostic anyway. */
static unsigned int last_reject_syscall_nr;
static unsigned char last_reject_do32bit;
static unsigned char last_reject_have_syscall;

bool range_overlaps_shared(unsigned long addr, unsigned long len)
{
	unsigned long end, check_end, first, last;
	bool overlap = false;
	unsigned long n;
	struct childdata *child;

	/* Treat wrapped ranges as overlapping so callers reject them. */
	if (len != 0 && addr > ULONG_MAX - len)
		return true;

	end = addr + len;

	/*
	 * Size-bucket bitmap short-circuit: when no tracked region of any
	 * size class exists, the address-keyed shared_region_bitmap is
	 * also empty by construction, and the word-scan below would walk
	 * SHARED_BITMAP_NWORDS words to confirm.  One load on
	 * tracked_size_bm proves the same negative in O(1).  This is the
	 * useful empty-fleet / pre-registration / fully-untracked state;
	 * it also covers the bypass condition from the spec ("len exceeds
	 * every set bit's bucket bound") vacuously when no bits are set.
	 *
	 * Per-process rate-limited counter feeds the -v summary below.
	 * Each child has its own static via fork CoW, mirroring the
	 * cadence of the rejects line at the tail of this function.
	 */
	if (tracked_size_bm == 0) {
		static unsigned long local_skip;
		unsigned long s;

		s = ++local_skip;
		if (verbosity > 1 &&
		    (s % RANGE_OVERLAPS_SHARED_BM_SKIP_REPORT_INTERVAL) == 0)
			output(1, "range_overlaps_shared_bm_skip: %lu cumulative bitmap-empty short-circuits\n",
				s);
		return false;
	}

	/* Bitmap accelerator used as a fast NEGATIVE prefilter:
	 * O(ceil(len/2MB)+1) bit reads to rule out the common case where
	 * no tracked region lives in any 2 MiB chunk the query touches.
	 * The bitmap only covers [0, SHARED_BITMAP_VA_SPAN); queries that
	 * start above the span (or straddle it) cannot use the bitmap as
	 * an authoritative negative -- shared_bitmap_mark() no-ops for
	 * those addresses, and the authoritative shared_regions[] linear
	 * scan below answers the membership question for them.  A
	 * zero-length probe collapses to a single bit read on the chunk
	 * containing addr.
	 *
	 * A bitmap HIT is only a candidate: it means at least one
	 * tracked region lives in a chunk that touches the query, but
	 * chunk rounding turns disjoint ranges in the same chunk into
	 * false positives.  The exact byte-range walk below confirms the
	 * hit (or clears it) before we reject. */
	if (addr < SHARED_BITMAP_VA_SPAN) {
		check_end = end;
		if (check_end > SHARED_BITMAP_VA_SPAN)
			check_end = SHARED_BITMAP_VA_SPAN;

		first = addr >> SHARED_BITMAP_GRANULARITY_LOG2;
		if (check_end > addr)
			last = (check_end - 1) >> SHARED_BITMAP_GRANULARITY_LOG2;
		else
			last = first;

		/* Word-at-a-time scan over shared_region_bitmap[]:
		 * mask the partial first/last words, then sweep any
		 * middle words and skip the zero-word common case in a
		 * single load.  A mostly-empty bitmap with a multi-MiB
		 * query length now costs one load per 64 chunks (128 MiB
		 * of VA), not one per chunk. */
		{
			unsigned long first_word = first / SHARED_BITMAP_BITS_PER_WORD;
			unsigned long last_word  = last  / SHARED_BITMAP_BITS_PER_WORD;
			unsigned long first_off  = first % SHARED_BITMAP_BITS_PER_WORD;
			unsigned long last_off   = last  % SHARED_BITMAP_BITS_PER_WORD;
			unsigned long w;

			if (first_word == last_word) {
				unsigned long width = last_off - first_off + 1;
				unsigned long mask  = (width == SHARED_BITMAP_BITS_PER_WORD)
					? ~0UL
					: (((1UL << width) - 1UL) << first_off);

				if (shared_region_bitmap[first_word] & mask)
					overlap = true;
			} else {
				unsigned long head_mask = ~0UL << first_off;

				if (shared_region_bitmap[first_word] & head_mask) {
					overlap = true;
				} else {
					for (w = first_word + 1; w < last_word; w++) {
						if (shared_region_bitmap[w]) {
							overlap = true;
							break;
						}
					}
					if (!overlap) {
						unsigned long tail_width = last_off + 1;
						unsigned long tail_mask  = (tail_width == SHARED_BITMAP_BITS_PER_WORD)
							? ~0UL
							: ((1UL << tail_width) - 1UL);

						if (shared_region_bitmap[last_word] & tail_mask)
							overlap = true;
					}
				}
			}
		}
	}

	/* Above-span / span-straddling queries cannot trust a bitmap
	 * negative: shared_bitmap_mark() no-ops for those addresses, so
	 * a registered region up there leaves no bitmap trace.  Force
	 * the candidate flag so the shared_regions[] linear scan below
	 * answers the membership question authoritatively. */
	if (addr >= SHARED_BITMAP_VA_SPAN ||
	    (len != 0 && len > SHARED_BITMAP_VA_SPAN - addr))
		overlap = true;

	if (!overlap)
		return false;

	/* Bitmap hit: confirm there is real byte-range overlap before
	 * rejecting.  This is the rarer path (bitmap-clear cases already
	 * returned above), so paying an O(N) walk here is cheap on the
	 * common fast path and only fires when the query genuinely
	 * shares a 2 MiB chunk with a tracked region. */
	if (!shared_regions_exact_overlap(addr, len, end))
		return false;

	child = this_child();
	if (child != NULL && child->stats_ring != NULL) {
		unsigned int nr = child->syscall.nr;
		bool do32 = child->syscall.do32bit;

		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_RANGE_OVERLAPS_SHARED_REJECTS,
				   0, 1);
		if (nr < MAX_NR_SYSCALL) {
			enum stats_field f = do32
				? STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_32
				: STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_64;
			stats_ring_enqueue(child->stats_ring, f,
					   (uint16_t)nr, 1);
		}

		last_reject_syscall_nr = nr;
		last_reject_do32bit = do32 ? 1 : 0;
		last_reject_have_syscall = 1;
	} else {
		/* Parent / pre-fork context: bump the aggregate directly. */
		parent_stats.range_overlaps_shared_rejects++;
	}

	/* Per-process monotonic counter feeding the verbose rate-limited
	 * log below.  The canonical aggregate now lives in parent-private
	 * memory and is not directly visible from child context, so the
	 * "fleet-wide every Nth reject" cadence the original counter
	 * provided cannot be recovered cheaply.  Each child rate-limits
	 * its own log lines independently; the parent does the same.
	 * Verbosity-gated, informational only. */
	{
		static unsigned long local_n;

		n = ++local_n;
	}

	if (verbosity > 1 &&
	    (n % RANGE_OVERLAPS_SHARED_REJECT_REPORT_INTERVAL) == 0) {
		const char *sname = "?";
		unsigned int snr;
		unsigned char s32;

		if (last_reject_have_syscall) {
			snr = last_reject_syscall_nr;
			s32 = last_reject_do32bit;
			sname = print_syscall_name(snr, s32 != 0);
		}

		output(1, "range_overlaps_shared: %lu cumulative rejects "
			"(latest syscall=%s addr=0x%lx len=%lu)\n",
			n, sname, addr, len);
	}
	return true;
}

/*
 * Precise containment check: is [addr, addr+len) fully inside at least
 * one entry of shared_regions[]?  Used by get_writable_address() to
 * confirm a freshly-picked pool address still resolves to a tracked
 * mapping before handing it back to a sanitiser.
 *
 * Distinct from range_overlaps_shared() in three ways the caller
 * relies on:
 *   1. Polarity is "fully inside", not "overlaps".  A scribbled slot
 *      can hold a value that happens to abut a tracked region without
 *      being inside it; over-acceptance there would defeat the guard.
 *   2. Walks shared_regions[] linearly.  The bitmap accelerator that
 *      backs range_overlaps_shared() rounds to 2 MiB chunks, which is
 *      the SAFETY direction for a reject-shaped sanitiser but the
 *      WRONG direction here -- a 2 MiB chunk that contains some
 *      tracked region would falsely accept addresses elsewhere in the
 *      same chunk.
 *   3. Does not bump range_overlaps_shared_rejects.  This is a
 *      validation lookup, not a sanitiser reject; folding it into the
 *      reject counter would lie to the operator about how often the
 *      mm-syscall guards are firing.
 *
 * Empty ranges (len == 0) match if @addr lies strictly inside any
 * region; the caller controls len so this is the consistent shape.
 * Wrapped ranges return false (no real allocation can wrap user VA).
 */
bool range_in_tracked_shared(unsigned long addr, unsigned long len)
{
	unsigned long end;
	unsigned int i;

	if (len != 0 && addr > ULONG_MAX - len)
		return false;

	end = addr + len;

	for (i = 0; i < nr_shared_regions; i++) {
		unsigned long rstart = shared_regions[i].addr;
		unsigned long rend = rstart + shared_regions[i].size;

		if (addr >= rstart && end <= rend)
			return true;
	}
	/* Same byte-precise walk over the overflow tail: a region parked
	 * there is no less tracked from the caller's perspective, and a
	 * false negative would let get_writable_address() hand back a
	 * pool slot that no longer resolves to a tracked mapping. */
	for (i = 0; i < nr_shared_regions_overflow; i++) {
		unsigned long rstart = shared_regions_overflow[i].addr;
		unsigned long rend = rstart + shared_regions_overflow[i].size;

		if (addr >= rstart && end <= rend)
			return true;
	}
	return false;
}

/*
 * Return the bytes remaining from @addr to the end of the tracked
 * shared region that contains it, or 0 if @addr does not fall inside
 * any tracked region.  Callers use the result as the writable extent
 * available at @addr -- a kernel-WRITES-buffer caller that picks a
 * length <= this value cannot make the kernel scribble past the
 * region into the abutting page.
 *
 * The overflow tail is walked with the same shape so a region that
 * arrived after shared_regions[] was full is no less lookup-able than
 * one in the main array.  A zero return is the documented "no companion
 * size resolvable" signal and the caller is expected to fall back to
 * the size-agnostic get_len() rather than guessing.
 */
unsigned long shared_region_size_for(unsigned long addr)
{
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		unsigned long rstart = shared_regions[i].addr;
		unsigned long rsize = shared_regions[i].size;

		if (rsize == 0)
			continue;
		if (addr >= rstart && addr < rstart + rsize)
			return rsize - (addr - rstart);
	}
	for (i = 0; i < nr_shared_regions_overflow; i++) {
		unsigned long rstart = shared_regions_overflow[i].addr;
		unsigned long rsize = shared_regions_overflow[i].size;

		if (rsize == 0)
			continue;
		if (addr >= rstart && addr < rstart + rsize)
			return rsize - (addr - rstart);
	}
	return 0;
}

#ifdef CONFIG_GUARD_SHARED
/*
 * Pure linear scan over shared_regions[] + overflow tail.  Returns true
 * iff [addr, addr+len) overlaps at least one tracked region; ignores the
 * bitmap and size-bucket accelerators entirely.  This is a deliberate
 * answers-the-truth oracle for the audit wrapper below: if the fast
 * path disagrees with this verdict on the same input, the accelerator
 * is desynced from the authoritative registry and the audit logs both
 * sides so the source of the divergence can be pinned to a single mm
 * sanitiser callsite.
 *
 * @entry_addr / @entry_size / @entry_origin are filled with the first
 * matching region's fields when non-NULL.  origin is the tag set by
 * track_shared_region_tagged() ("kcov-pc" / "kcov-cmp" for the buffers
 * the kcov investigation is chasing), or NULL for untagged registrants.
 */
bool range_overlaps_shared_slow(unsigned long addr, unsigned long len,
				unsigned long *entry_addr,
				unsigned long *entry_size,
				const char **entry_origin)
{
	unsigned long end;
	unsigned int i;

	if (len != 0 && addr > ULONG_MAX - len)
		return true;
	end = addr + len;

	for (i = 0; i < nr_shared_regions; i++) {
		unsigned long rstart = shared_regions[i].addr;
		unsigned long rsize = shared_regions[i].size;
		unsigned long rend;

		if (rsize == 0)
			continue;
		rend = rstart + rsize;
		if (len == 0 ? (addr >= rstart && addr < rend)
			     : (addr < rend && rstart < end)) {
			if (entry_addr)   *entry_addr = rstart;
			if (entry_size)   *entry_size = rsize;
			if (entry_origin) *entry_origin = shared_regions[i].origin;
			return true;
		}
	}
	for (i = 0; i < nr_shared_regions_overflow; i++) {
		unsigned long rstart = shared_regions_overflow[i].addr;
		unsigned long rsize = shared_regions_overflow[i].size;
		unsigned long rend;

		if (rsize == 0)
			continue;
		rend = rstart + rsize;
		if (len == 0 ? (addr >= rstart && addr < rend)
			     : (addr < rend && rstart < end)) {
			if (entry_addr)   *entry_addr = rstart;
			if (entry_size)   *entry_size = rsize;
			if (entry_origin) *entry_origin = shared_regions_overflow[i].origin;
			return true;
		}
	}
	return false;
}

/*
 * Per-child rolling log of the most recent fast-vs-slow audit
 * disagreements emitted by range_overlaps_shared_audited().  Sized to
 * comfortably exceed the on-fault diagnostic's "last ~16 lines"
 * recall.  Each slot stores a printf-style line already rendered to
 * text; readers (kcov_dump_audit_ring()) snprintf the slots out, no
 * extra formatting needed in signal context.
 *
 * COW-inherited into every forked child; never touched by the parent
 * once children are spawned.  Plain file-scope statics rather than
 * __thread because trinity children are single-threaded.
 */
#define KCOV_AUDIT_RING_SIZE	32U
#define KCOV_AUDIT_LINE_MAX	256U
static char kcov_audit_ring[KCOV_AUDIT_RING_SIZE][KCOV_AUDIT_LINE_MAX];
static unsigned int kcov_audit_ring_head;
static unsigned long kcov_audit_ring_writes;

static void kcov_audit_ring_push(const char *line)
{
	unsigned int slot = kcov_audit_ring_head % KCOV_AUDIT_RING_SIZE;
	size_t n = strlen(line);

	if (n >= KCOV_AUDIT_LINE_MAX)
		n = KCOV_AUDIT_LINE_MAX - 1;
	memcpy(kcov_audit_ring[slot], line, n);
	kcov_audit_ring[slot][n] = '\0';
	kcov_audit_ring_head = (slot + 1) % KCOV_AUDIT_RING_SIZE;
	kcov_audit_ring_writes++;
}

/*
 * Dump up to the last KCOV_AUDIT_RING_SIZE audit disagreements via
 * outputerr().  Called from the kcov_enable_trace on-fault path so the
 * accelerator-vs-truth disagreement history that preceded the SEGV is
 * visible alongside the fault diagnostic.  Best-effort -- safe to call
 * from a SIGSEGV/SIGBUS handler context because outputerr() is the
 * existing fault-path output channel and the ring slots are plain
 * pre-rendered character arrays.
 */
void kcov_audit_ring_dump(const char *prefix)
{
	unsigned int n = (kcov_audit_ring_writes < KCOV_AUDIT_RING_SIZE)
		? (unsigned int) kcov_audit_ring_writes : KCOV_AUDIT_RING_SIZE;
	unsigned int i;

	if (n == 0) {
		outputerr("%s: audit ring empty (no fast-vs-slow disagreements seen)\n",
			  prefix);
		return;
	}
	outputerr("%s: last %u audit disagreement(s) (oldest first):\n",
		  prefix, n);
	for (i = 0; i < n; i++) {
		unsigned int slot =
			(kcov_audit_ring_head + KCOV_AUDIT_RING_SIZE - n + i)
			% KCOV_AUDIT_RING_SIZE;
		outputerr("  %s\n", kcov_audit_ring[slot]);
	}
}

bool range_overlaps_shared_audited(const char *site,
				   unsigned long addr, unsigned long len)
{
	bool fast = range_overlaps_shared(addr, len);
	unsigned long e_addr = 0, e_size = 0;
	const char *e_origin = NULL;
	bool slow = range_overlaps_shared_slow(addr, len,
					       &e_addr, &e_size, &e_origin);
	char line[KCOV_AUDIT_LINE_MAX];

	if (fast == slow)
		return fast;

	/* Verdicts differ -- accelerator desync.  Render a single line
	 * to the per-child audit ring for later in-handler recall, and
	 * emit it via outputerr() so live runs surface the divergence
	 * immediately.  Format keeps the site / query / both verdicts /
	 * matching entry visible at a glance. */
	snprintf(line, sizeof(line),
		 "range_overlaps_shared_audit: site=%s query=0x%lx+0x%lx "
		 "fast=%s slow=%s overlap=0x%lx+0x%lx origin=%s",
		 site ? site : "?", addr, len,
		 fast ? "true" : "false",
		 slow ? "true" : "false",
		 slow ? e_addr : 0UL,
		 slow ? e_size : 0UL,
		 (slow && e_origin) ? e_origin : "(untagged)");
	kcov_audit_ring_push(line);
	outputerr("%s\n", line);
	return fast;
}

/*
 * Walk shared_regions[] for entries carrying the kcov-pc / kcov-cmp
 * origin tag and warn loudly if [addr, addr+len) overlaps any of them.
 * Called from the internal mprotect sites (freeze_sibling_childdata,
 * init_child's pids[] freeze, get_writable_address's own mprotect)
 * before the syscall fires -- an internal-mprotect overlap on a kcov
 * buffer is a distinct mechanism for the trace_buf write-fault we are
 * trying to localise from the externally-fuzzed mm-sanitiser path.
 *
 * @who   : short site tag for the log line ("freeze_sibling_childdata",
 *          "init_child:pids", "get_writable_address").
 * @prot  : the requested protection bits, rendered as the trailing
 *          "prot=0x%x" field so the log explicitly names whether a
 *          PROT_READ/PROT_NONE strip is in play.
 */
void internal_mprotect_audit_kcov(const char *who, unsigned long addr,
				  unsigned long len, int prot)
{
	unsigned long end;
	unsigned int i;

	if (len == 0)
		return;
	if (addr > ULONG_MAX - len)
		return;
	end = addr + len;

	for (i = 0; i < nr_shared_regions; i++) {
		const char *origin = shared_regions[i].origin;
		unsigned long rstart, rsize, rend;

		if (origin == NULL)
			continue;
		if (strncmp(origin, "kcov-", 5) != 0)
			continue;
		rstart = shared_regions[i].addr;
		rsize  = shared_regions[i].size;
		if (rsize == 0)
			continue;
		rend = rstart + rsize;
		if (addr < rend && rstart < end) {
			outputerr("internal_mprotect_audit: %s mprotect "
				  "[0x%lx+0x%lx) prot=0x%x overlaps "
				  "%s region [0x%lx+0x%lx)\n",
				  who, addr, len, (unsigned int) prot,
				  origin, rstart, rsize);
		}
	}
	for (i = 0; i < nr_shared_regions_overflow; i++) {
		const char *origin = shared_regions_overflow[i].origin;
		unsigned long rstart, rsize, rend;

		if (origin == NULL)
			continue;
		if (strncmp(origin, "kcov-", 5) != 0)
			continue;
		rstart = shared_regions_overflow[i].addr;
		rsize  = shared_regions_overflow[i].size;
		if (rsize == 0)
			continue;
		rend = rstart + rsize;
		if (addr < rend && rstart < end) {
			outputerr("internal_mprotect_audit: %s mprotect "
				  "[0x%lx+0x%lx) prot=0x%x overlaps "
				  "%s region [0x%lx+0x%lx) (overflow)\n",
				  who, addr, len, (unsigned int) prot,
				  origin, rstart, rsize);
		}
	}
}

/*
 * Scan /proc/self/maps for the entry covering @addr and report its
 * tracked-shared-region match status alongside the live VMA
 * protection bits.  Used both at registration time (to catch a setup-
 * side mistake where the buffer is already non-writable when we
 * register it) and from the on-fault diagnostic (to catch the
 * runtime-strip the SEGV is the symptom of).  Output goes to
 * outputerr() -- the existing fault-path channel; no new logging
 * mechanism.
 *
 * @who : short site tag.  @addr : the buffer address.  @size : the
 * length we expect the entry to span.
 */
void log_buffer_prot_from_proc_maps(const char *who, unsigned long addr,
				    unsigned long size)
{
	int fd;
	char buf[8192];
	ssize_t n;
	bool found = false;

	/* check-static: slow-ok */
	fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		outputerr("%s: open(/proc/self/maps) failed: errno=%d "
			  "addr=0x%lx size=0x%lx\n",
			  who, errno, addr, size);
		return;
	}

	/* Best-effort streaming scan: read into a fixed buffer, split on
	 * newlines, parse the leading "%lx-%lx %4s" of each line.  We do
	 * not need to scan the whole map -- the first line whose range
	 * covers @addr is the answer.  Tail-truncation across buffer
	 * boundaries is acceptable for a diagnostic that only needs the
	 * matching line. */
	while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
		char *p = buf;
		char *end_p = buf + n;
		*end_p = '\0';

		while (p < end_p) {
			char *nl = memchr(p, '\n', (size_t)(end_p - p));
			unsigned long lo = 0, hi = 0;
			char perms[5] = {0};

			if (nl) *nl = '\0';

			if (sscanf(p, "%lx-%lx %4s", &lo, &hi, perms) == 3 &&
			    addr >= lo && addr < hi) {
				outputerr("%s: addr=0x%lx size=0x%lx "
					  "/proc/self/maps prot=%s "
					  "vma=[0x%lx-0x%lx)\n",
					  who, addr, size, perms, lo, hi);
				found = true;
				goto out;
			}
			if (!nl)
				break;
			p = nl + 1;
		}
	}

out:
	if (!found)
		outputerr("%s: addr=0x%lx size=0x%lx no /proc/self/maps entry "
			  "covers this address\n", who, addr, size);
	close(fd);
}

/*
 * Look up whether [addr, addr+size) still matches a registered shared
 * region with the given origin tag.  Used by the on-fault diagnostic
 * to answer "is the kcov-pc registration still present at the addr
 * the child just faulted on?" without re-deriving the slot from the
 * caller context.  Returns true on exact-match (addr + size + origin
 * all line up), false otherwise.
 */
bool kcov_registration_still_present(unsigned long addr, unsigned long size,
				     const char *origin)
{
	unsigned int i;

	if (origin == NULL)
		return false;
	for (i = 0; i < nr_shared_regions; i++) {
		if (shared_regions[i].addr != addr ||
		    shared_regions[i].size != size)
			continue;
		if (shared_regions[i].origin == NULL)
			continue;
		if (strcmp(shared_regions[i].origin, origin) == 0)
			return true;
	}
	for (i = 0; i < nr_shared_regions_overflow; i++) {
		if (shared_regions_overflow[i].addr != addr ||
		    shared_regions_overflow[i].size != size)
			continue;
		if (shared_regions_overflow[i].origin == NULL)
			continue;
		if (strcmp(shared_regions_overflow[i].origin, origin) == 0)
			return true;
	}
	return false;
}
#endif	/* CONFIG_GUARD_SHARED */
