/*
 * Per-child breadcrumb ring for post_handler_corrupt_ptr fires.  The
 * headline counter and the (nr, do32bit) / (nr, do32bit, pc) attribution
 * shards already tell us "how many fires" and "which handler / which
 * PC".  This ring captures the per-fire payload the shards drop on the
 * floor: the scribbled pointer value itself, the syscall arg slot it
 * was caught on (when the caller knows), and a short site tag so a
 * triage pass can name the scribbler without an extra doc-archaeology
 * step.
 *
 * Ownership / coherence model mirrors prop_ring and the
 * local_corrupt_ptr_* shards: the owning child is the sole writer of
 * its own ring, the parent is the sole reader at periodic-dump time,
 * and a torn read on a single slot at dump time is acceptable
 * (.valid=false slots are skipped; a slot caught mid-write surfaces
 * stale-but-real data from the prior wraparound resident).  No atomics.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "breadcrumb_ring.h"
#include "child.h"
#include "pids.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

void corrupt_ptr_breadcrumb_push(const struct syscallrecord *rec,
				 unsigned int arg_idx,
				 unsigned long bad_ptr,
				 const char *site_tag)
{
	struct childdata *child = this_child();
	struct corrupt_ptr_breadcrumb_ring *ring;
	struct corrupt_ptr_breadcrumb *slot;
	unsigned int idx;

	if (child == NULL)
		return;

	ring = &child->breadcrumb_ring;
	idx = __atomic_load_n(&ring->head, __ATOMIC_RELAXED) &
	      (CORRUPT_PTR_BREADCRUMB_SLOTS - 1);
	slot = &ring->slots[idx];

	/* Invalidate before write so a concurrent dump-side read that
	 * lands mid-write skips this slot rather than serving a half-
	 * built record under a stale .valid flag.  Atomic relaxed store
	 * so -O2 dead-store elimination cannot drop this in favour of
	 * the .valid = true publish below: on the function-local view
	 * there is no intervening read of slot->valid, so a plain store
	 * is a redundant predecessor the optimiser is free to delete. */
	__atomic_store_n(&slot->valid, false, __ATOMIC_RELAXED);

	slot->bad_ptr = bad_ptr;
	slot->iter_at_fire = child->op_nr;
	if (rec != NULL) {
		slot->syscall_nr = rec->nr;
		slot->do32bit = rec->do32bit;
	} else {
		slot->syscall_nr = (unsigned int) ~0u;
		slot->do32bit = false;
	}
	slot->arg_idx = arg_idx;

	if (site_tag != NULL) {
		strncpy(slot->site_tag, site_tag, sizeof(slot->site_tag) - 1);
		slot->site_tag[sizeof(slot->site_tag) - 1] = '\0';
	} else {
		slot->site_tag[0] = '\0';
	}

	/* RELEASE pairs with the ACQUIRE load of .valid in
	 * linearise_child(): a dump-side reader that observes valid=true
	 * is guaranteed to see the payload stores above, not a stale
	 * resident from the prior wraparound.  Without the release on
	 * weakly-ordered cores (aarch64) the payload writes can be
	 * reordered past the valid=true publish and the reader copies a
	 * half-built record while believing it is fully populated. */
	__atomic_store_n(&slot->valid, true, __ATOMIC_RELEASE);
	__atomic_add_fetch(&ring->head, 1, __ATOMIC_RELAXED);
}

/* Linearise one child's ring into the merge buffer, oldest-first.  When
 * head has wrapped past the ring size every slot is populated and the
 * walk starts at head (the next-write index, i.e. the oldest entry).
 * Before wrap, only slots [0, head) are populated and the walk starts
 * at 0.  Skips slots whose .valid flag is clear so a freshly-cleaned
 * child contributes nothing to the dump.
 */
static unsigned int linearise_child(const struct corrupt_ptr_breadcrumb_ring *ring,
				    struct corrupt_ptr_breadcrumb *out,
				    unsigned int out_cap)
{
	unsigned int head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
	unsigned int populated = head < CORRUPT_PTR_BREADCRUMB_SLOTS
				 ? head : CORRUPT_PTR_BREADCRUMB_SLOTS;
	unsigned int start = head < CORRUPT_PTR_BREADCRUMB_SLOTS
			     ? 0
			     : head & (CORRUPT_PTR_BREADCRUMB_SLOTS - 1);
	unsigned int n = 0;
	unsigned int i;

	for (i = 0; i < populated && n < out_cap; i++) {
		unsigned int slot_idx = (start + i) &
					(CORRUPT_PTR_BREADCRUMB_SLOTS - 1);
		const struct corrupt_ptr_breadcrumb *s = &ring->slots[slot_idx];

		if (!__atomic_load_n(&s->valid, __ATOMIC_ACQUIRE))
			continue;
		out[n++] = *s;
	}
	return n;
}

/* Matches stats/periodic/counter-rates.c's DEFENSE_DUMP_INTERVAL_SEC.  The two periodic
 * surfaces share a cadence so a triage pass sees the breadcrumb log
 * line directly above the matching attribution-counter rate row. */
#define BREADCRUMB_DUMP_INTERVAL_SEC	600

void corrupt_ptr_breadcrumb_dump(unsigned int max_lines)
{
	static struct timespec last_dump;
	struct timespec now;
	struct corrupt_ptr_breadcrumb stack[CORRUPT_PTR_BREADCRUMB_SLOTS];
	unsigned int i;
	unsigned int emitted = 0;
	long total_seen = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so the very first periodic tick after
	 * boot does not flood the log with whatever has accumulated since
	 * fork. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		return;
	}
	if (now.tv_sec - last_dump.tv_sec < BREADCRUMB_DUMP_INTERVAL_SEC)
		return;

	for_each_child(i) {
		struct childdata *child;
		unsigned int n;
		unsigned int j;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		n = linearise_child(&child->breadcrumb_ring, stack,
				    CORRUPT_PTR_BREADCRUMB_SLOTS);
		if (n == 0)
			continue;
		total_seen += (long) n;

		/* Walk newest-first within this child by reversing the
		 * linearised range.  Across children we proceed in
		 * for_each_child() order -- not strictly global
		 * newest-first.  Keep counting total_seen even after
		 * emission hits max_lines so the "more not shown"
		 * tally below reflects every child's contribution. */
		for (j = n; j-- > 0; ) {
			const struct corrupt_ptr_breadcrumb *b = &stack[j];
			const char *name;
			const char *width;
			const char *tag;
			char arg_buf[8];

			if (emitted >= max_lines)
				break;

			if (b->syscall_nr == (unsigned int) ~0u) {
				name = "<deferred-free / non-syscall>";
				width = "(all)";
			} else {
				name = print_syscall_name(b->syscall_nr,
							  b->do32bit);
				width = b->do32bit ? "(32)" : "(64)";
			}

			if (b->arg_idx == CORRUPT_PTR_BREADCRUMB_NO_ARG) {
				arg_buf[0] = '-';
				arg_buf[1] = '\0';
			} else {
				snprintf(arg_buf, sizeof(arg_buf), "%u",
					 b->arg_idx);
			}

			tag = b->site_tag[0] != '\0' ? b->site_tag : "-";

			if (emitted == 0)
				stats_log_write("corrupt_ptr breadcrumbs "
						"(last %u, child-scan order, "
						"newest first per child):\n",
						max_lines);
			if (b->bad_ptr == CORRUPT_PTR_BREADCRUMB_BAD_UNKNOWN)
				stats_log_write("  nr=%u%s arg=%s bad=? "
						"label=- site=%s name=%s "
						"iter=%lu\n",
						b->syscall_nr,
						b->syscall_nr == (unsigned int) ~0u
						    ? "" : width,
						arg_buf, tag, name,
						b->iter_at_fire);
			else
				stats_log_write("  nr=%u%s arg=%s bad=0x%lx "
						"label=%s site=%s name=%s "
						"iter=%lu\n",
						b->syscall_nr,
						b->syscall_nr == (unsigned int) ~0u
						    ? "" : width,
						arg_buf, b->bad_ptr,
						corrupt_ptr_label(b->bad_ptr),
						tag, name, b->iter_at_fire);
			emitted++;
		}
	}

	if (emitted > 0 && total_seen > (long) emitted)
		stats_log_write("  (%ld more breadcrumbs not shown this "
				"window)\n", total_seen - (long) emitted);

	last_dump = now;
}
