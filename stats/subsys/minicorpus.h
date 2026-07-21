#ifndef _TRINITY_STATS_SUBSYS_MINICORPUS_H
#define _TRINITY_STATS_SUBSYS_MINICORPUS_H

/*
 * Minicorpus snapshot / ring accounting.
 *
 * last_snapshot_time:
 *   Wall-clock high-water-mark for the periodic minicorpus snapshot.
 *   Companion to minicorpus_shm->edges_at_last_snapshot but lives in
 *   shm->stats so the field is allocated alongside the rest of the
 *   snapshot trigger state and the operator's stats dump can surface
 *   it without crossing into the corpus-only shared region.  Short
 *   runs that die before the edge-delta threshold trips would
 *   otherwise lose the entire mid-run corpus.  Initialised at
 *   minicorpus_enable_snapshots() time and advanced by the single
 *   CAS-elected saver after minicorpus_save_file() returns.
 *
 * count_overcap_caught:
 *   Bumped from runid_corpus_entries_total() each time a per-syscall
 *   minicorpus ring is observed with count > CORPUS_RING_SIZE.  Every
 *   save path (in-run minicorpus_save_with_reason() and the on-disk
 *   loader) caps count at CORPUS_RING_SIZE before publishing, and the
 *   picker / snapshot readers also clamp before indexing entries[];
 *   a value above the cap is therefore not reachable through the
 *   documented writer flow and is a zero-false-positive signal that
 *   a sibling wild write has scribbled the ring's count word.
 *
 * Bespoke (non-category) RAW group.  Both writers store RELAXED /
 * ACQUIRE via __atomic_{store,load}_n.  The surrounding struct
 * stats_s composes an instance of struct minicorpus_stats as its
 * "minicorpus" member.
 */
struct minicorpus_stats {
	unsigned long last_snapshot_time;
	unsigned long count_overcap_caught;
};

#endif	/* _TRINITY_STATS_SUBSYS_MINICORPUS_H */
