/*
 * Producer-observer bitmap for the coverage-frontier spare-lane classifier.
 */

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
 * Built once per process, on first use: each child has its own copy of
 * the file-scope statics under fork()-COW, and a child is single-
 * threaded, so no reader can find a build half done.  The build only
 * sets bits, so one interrupted and run again still ends complete.
 */
#define FRONTIER_PRODUCER_OBSERVER_WORDS ((MAX_NR_SYSCALL + 63) / 64)

#ifdef ARCH_IS_BIARCH
static uint64_t producer_observer_bits_32[FRONTIER_PRODUCER_OBSERVER_WORDS];
static uint64_t producer_observer_bits_64[FRONTIER_PRODUCER_OBSERVER_WORDS];
#else
static uint64_t producer_observer_bits[FRONTIER_PRODUCER_OBSERVER_WORDS];
#endif

static bool producer_observer_built;

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
	if (producer_observer_built)
		return;

#ifdef ARCH_IS_BIARCH
	build_producer_observer_bitmap(syscalls_64bit, max_nr_64bit_syscalls,
				       producer_observer_bits_64);
	build_producer_observer_bitmap(syscalls_32bit, max_nr_32bit_syscalls,
				       producer_observer_bits_32);
#else
	build_producer_observer_bitmap(syscalls, max_nr_syscalls,
				       producer_observer_bits);
#endif
	producer_observer_built = true;
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
