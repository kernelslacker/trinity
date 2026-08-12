#ifndef _TRINITY_STATS_SUBSYS_THP_SPLIT_REF_RACE_H
#define _TRINITY_STATS_SUBSYS_THP_SPLIT_REF_RACE_H

/*
 * Per-run counters for the thp_split_ref_race childop.
 *
 * split_trigger_rounds     -- total split-trigger + reference-walker round
 *                             iterations completed across all invocations.
 *                             Denominator for the race ratios below.
 * thp_split_while_ref_held -- rounds where process_vm_readv returned > 0
 *                             bytes, confirming the reference walker reached
 *                             folio_try_get() during or after the split
 *                             window (race landed, kernel handled it).
 *                             Non-zero here means the interesting kernel
 *                             paths are actually being exercised.
 * thp_no_race              -- rounds where both walkers observed nothing:
 *                             mincore returned only zeros and
 *                             process_vm_readv returned <= 0 bytes (pages
 *                             absent, no meaningful concurrency this round).
 *                             High ratio here vs split_trigger_rounds means
 *                             the race window is not being reached.
 * content_mismatch         -- rounds where process_vm_readv succeeded but
 *                             the returned bytes did not match the pre-split
 *                             cookie written to the arena (content oracle
 *                             fired -- indicates a kernel data-corruption
 *                             path through the folio split / ref-count
 *                             manipulation; any non-zero value is a bug).
 * mincore_pagewalk_dup     -- mincore() calls over the 16 MiB arena where
 *                             the byte written past the expected page-count
 *                             boundary changed from the sentinel value,
 *                             indicating the kernel's pagewalk cursor
 *                             advanced beyond the 4096-entry tmp buffer
 *                             (ACTION_AGAIN dup-walk).  Non-zero confirms
 *                             the race arm is live; KASAN catches the
 *                             actual OOB write on the adjacent kernel page.
 */
struct thp_split_ref_race_stats {
	unsigned long split_trigger_rounds;
	unsigned long thp_split_while_ref_held;
	unsigned long thp_no_race;
	unsigned long content_mismatch;
	unsigned long mincore_pagewalk_dup;
};

#endif /* _TRINITY_STATS_SUBSYS_THP_SPLIT_REF_RACE_H */
