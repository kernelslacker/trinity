#ifndef _TRINITY_STATS_SUBSYS_BLOB_H
#define _TRINITY_STATS_SUBSYS_BLOB_H

#include "syscall.h"	/* NR_GROUPS */

/*
 * blob-mutator content-authoring lane counters.
 *
 * The eight scalars below back the "blob_mutator" stat_category (see
 * stats/subsys/blob.c) that surfaces --blob-mutator's A/B observability
 * signal.  Kept self-contained so the whole subsystem is legible from a
 * single header pair; the surrounding struct stats_s composes an
 * instance of struct blob_stats as its "blob" member.
 */
struct blob_stats {
	/* --blob-mutator (default off): A/B observability counters for the
	 * content-authoring lane that backs ARG_BUF_SIZED args.  blob_fills
	 * is the gate (total invocations of blob_fill() that authored
	 * content into a buffer); blob_havoc_ops is the count of bounded
	 * byte-mutation ops the HAVOC rung applied on top of the FILL
	 * floor; blob_dict_inserts is the count of committed cmp-pool
	 * splats the CMPDICT rung applied on top of the HAVOC floor from
	 * the learned per-nr cmp_hints pool (one bump per successful
	 * cmp_hints_try_get pull + splat; pool misses are silent);
	 * blob_static_magic_inserts is the count of committed splats the
	 * CMPDICT rung sourced from the built-in well-known-magic table
	 * (ext4 / XFS / BTRFS / squashfs / ELF / gzip) instead of the
	 * learned pool.  Each CMPDICT iteration coin-flips between the
	 * two sources; the ratio of blob_static_magic_inserts to
	 * blob_dict_inserts is the observable A/B split (a static-draw
	 * that does not fit len falls back to the learned path and does
	 * not bump either counter until the fallback either commits or
	 * misses).  blob_dict_transform_inserts is an orthogonal axis:
	 * the count of committed splats (across both sources) that
	 * applied a non-plain splat form -- big-endian byte-swap or
	 * value ± 1 at width -- for endian and off-by-one boundary
	 * coverage.  Plain little-endian commits stay uncounted here,
	 * so the ratio of blob_dict_transform_inserts to
	 * (blob_dict_inserts + blob_static_magic_inserts) is the
	 * observable transform-vs-plain split.  All five counters are
	 * bumped only by CMPDICT -- the per-rung contribution stays
	 * isolated across an off / fill / havoc / cmpdict A/B.
	 * blob_havoc_prefix_len_ops is an arm-selection shadow of
	 * blob_havoc_ops: it counts the subset of havoc ops the
	 * prefix-len arm was picked for (stamp a plausible length /
	 * size value at buffer offset 0 to reach length-gated parsers
	 * -- TLV entry length, netlink attr nla_len, on-wire header
	 * size fields -- that uniform per-byte havoc almost never
	 * satisfies).  Bumped by HAVOC and CMPDICT rungs (both run
	 * blob_havoc()); its ratio to blob_havoc_ops is the observable
	 * per-arm selection rate. */
	unsigned long fills;
	unsigned long havoc_ops;
	unsigned long havoc_prefix_len_ops;
	unsigned long dict_inserts;
	unsigned long static_magic_inserts;
	unsigned long dict_transform_inserts;

	/* SHADOW ratio for the per-(nr, do32) blob corpus base source.
	 * Bumped once per blob_fill() invocation from
	 * blob_corpus_try_get_base(): base_from_corpus increments on a
	 * key-matching hit (HAVOC/CMPDICT ran on top of a productive
	 * saved base), base_from_random on a miss (the generate_rand_bytes
	 * fallback fired).  Their sum equals blob_fills by construction,
	 * so the hit ratio is (base_from_corpus /
	 * (base_from_corpus + base_from_random)) -- the observable
	 * "how often did the corpus have a productive base ready?"
	 * gauge.  Both bumped only by non-OFF blob_fill() calls; OFF
	 * short-circuits before the try_get_base call so the OFF arm
	 * stays byte-identical. */
	unsigned long base_from_corpus;
	unsigned long base_from_random;

	/* Per-group shadow of blob_fills.  Bumped once per non-OFF
	 * blob_fill() invocation, keyed on the group of the syscall
	 * whose (nr, do32) the caller passed in (looked up via
	 * get_syscall_entry(nr, do32)).  Sums to blob_fills by
	 * construction (modulo the entry == NULL / group >= NR_GROUPS
	 * defensive gate the bump site keeps).  Purpose: make the per-
	 * group blob_fill invocation distribution directly visible so
	 * the group-bias vs blob-starvation relationship is
	 * quantifiable from a single run without re-deriving the split
	 * from picker-side counters.  Pure observability: OFF short-
	 * circuits before the bump so the OFF arm stays byte-identical
	 * and no live selection logic reads this array. */
	unsigned long fills_by_group[NR_GROUPS];
};

#endif /* _TRINITY_STATS_SUBSYS_BLOB_H */
