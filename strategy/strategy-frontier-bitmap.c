/*
 * Producer-observer bitmap for the coverage-frontier spare-lane
 * classifier.  Split from strategy-frontier.c.
 */

#include <sched.h>		/* sched_yield */
#include <stdbool.h>
#include <stdint.h>

#include "arch.h"		/* biarch, ARCH_IS_BIARCH */
#include "object-types.h"	/* OBJ_NONE */
#include "syscall.h"		/* MAX_NR_SYSCALL, struct syscallentry */
#include "tables.h"		/* syscalls / syscalls_32bit / syscalls_64bit */

#include "strategy-frontier-internal.h"

/*
 * Saturation-cooldown spare-lane helper.
 *
 * Producer-observer bitmap: the silent-regime satcool predicate (see
 * frontier_satcool_spare below) spares syscalls whose syscallentry has
 * a non-OBJ_NONE ret_objtype -- the object-producer set (openat /
 * socket / memfd_create / mmap / io_uring_setup / bpf etc.) whose
 * payoff is delayed and credited downstream to the consumer of the
 * produced object.  ret_objtype is a static, compile-time property of
 * the syscallentry never modified at runtime, so the spared set is
 * precomputed into a per-arch bitmap at first call from the silent-
 * regime accept site and read with a plain bit-test on the hot path --
 * collapsing the per-pick get_syscall_entry() table indirection (plus
 * the biarch branch) the inline shape paid for.
 *
 * NULL entry (table slot empty OR nr >= max_nr_*_syscalls) is folded
 * into the spared set so an unknown nr cannot wrongly register as a
 * would-skip; this matches the original inline
 * `entry == NULL || entry->ret_objtype != OBJ_NONE` shape exactly --
 * the helper exists to remove the per-pick lookup, not to change the
 * spared set.
 *
 * Publish ordering: build_producer_observer() runs once-per-process
 * (each child has its own copy of the file-scope statics under
 * fork()-COW; the work is small and idempotent so each child paying
 * for one build is fine).  The publish is a RELEASE store to
 * producer_observer_ready and the read in frontier_satcool_spare is
 * an ACQUIRE load -- a partially-initialised bitmap is NEVER visible
 * to a concurrent reader.  A second caller racing the first sees
 * ready==0, loses the CAS to claim the build slot, and spins on the
 * acquire load until the winner publishes -- bounded spin (the build
 * is a few hundred bit-stores).
 */
#define FRONTIER_PRODUCER_OBSERVER_WORDS ((MAX_NR_SYSCALL + 63) / 64)

#ifdef ARCH_IS_BIARCH
static uint64_t producer_observer_bits_32[FRONTIER_PRODUCER_OBSERVER_WORDS];
static uint64_t producer_observer_bits_64[FRONTIER_PRODUCER_OBSERVER_WORDS];
#else
static uint64_t producer_observer_bits[FRONTIER_PRODUCER_OBSERVER_WORDS];
#endif

/*
 * 0 = not yet built, 1 = build in progress, 2 = built and published.
 * Three states (instead of a simple bool) so a racing caller can wait
 * on the publish without re-entering the build.
 */
static int producer_observer_ready;

static void build_producer_observer_bitmap(const struct syscalltable *table,
					   unsigned int table_nr,
					   uint64_t *bitmap)
{
	unsigned int i;
	unsigned int cap = (table_nr < MAX_NR_SYSCALL) ? table_nr
						       : MAX_NR_SYSCALL;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		bool is_spared;

		if (i >= cap) {
			/*
			 * Mirrors get_syscall_entry()'s out-of-range NULL
			 * return; the original inline shape treats a NULL
			 * entry as spared.
			 */
			is_spared = true;
		} else if (table[i].entry == NULL) {
			is_spared = true;
		} else {
			is_spared = (table[i].entry->ret_objtype != OBJ_NONE);
		}

		if (is_spared)
			bitmap[i / 64] |= ((uint64_t) 1) << (i % 64);
	}
}

void ensure_producer_observer_built(void)
{
	int state;
	int expected;

	state = __atomic_load_n(&producer_observer_ready, __ATOMIC_ACQUIRE);
	if (state == 2)
		return;

	expected = 0;
	if (__atomic_compare_exchange_n(&producer_observer_ready, &expected,
					1, false, __ATOMIC_ACQUIRE,
					__ATOMIC_ACQUIRE)) {
#ifdef ARCH_IS_BIARCH
		build_producer_observer_bitmap(syscalls_64bit,
					       max_nr_64bit_syscalls,
					       producer_observer_bits_64);
		build_producer_observer_bitmap(syscalls_32bit,
					       max_nr_32bit_syscalls,
					       producer_observer_bits_32);
#else
		build_producer_observer_bitmap(syscalls, max_nr_syscalls,
					       producer_observer_bits);
#endif
		__atomic_store_n(&producer_observer_ready, 2,
				 __ATOMIC_RELEASE);
		return;
	}

	/*
	 * Lost the CAS -- another caller is building.  Wait until they
	 * publish; the build is a bounded sequence of bit-stores so the
	 * spin terminates in microseconds.
	 */
	while (__atomic_load_n(&producer_observer_ready,
			       __ATOMIC_ACQUIRE) != 2)
		sched_yield();
}

bool producer_observer_lookup(unsigned int nr,
			      bool do32 __attribute__((unused)))
{
	const uint64_t *bm;

	if (nr >= MAX_NR_SYSCALL) {
		/*
		 * Mirrors get_syscall_entry()'s out-of-range NULL return:
		 * the original inline shape treats a NULL entry as spared.
		 */
		return true;
	}

#ifdef ARCH_IS_BIARCH
	bm = do32 ? producer_observer_bits_32 : producer_observer_bits_64;
#else
	bm = producer_observer_bits;
#endif

	return (bm[nr / 64] >> (nr % 64)) & 1;
}
