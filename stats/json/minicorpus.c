/*
 * Minicorpus JSON emitters for --stats-json.  All read from
 * minicorpus_shm; the section wrapper short-circuits to
 * ",\"minicorpus\":null" when the corpus is not attached.
 */

#include <stdio.h>
#include "minicorpus.h"
#include "sequence.h"
#include "shm.h"
#include "stats-internal.h"
#include "stats/json/internal.h"
#include "utils.h"

static void json_emit_minicorpus_mutators(void)
{
	unsigned int i;

	fputs(",\"minicorpus\":{\"mutators\":[", stdout);
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t  = __atomic_load_n(&minicorpus_shm->mut_trials[i], __ATOMIC_RELAXED);
		unsigned long w  = __atomic_load_n(&minicorpus_shm->mut_wins[i],   __ATOMIC_RELAXED);
		unsigned long st = __atomic_load_n(&minicorpus_shm->mut_structured_trials[i],
						   __ATOMIC_RELAXED);
		unsigned long sw = __atomic_load_n(&minicorpus_shm->mut_structured_wins[i],
						   __ATOMIC_RELAXED);

		if (i > 0)
			putchar(',');
		fputs("{\"name\":", stdout);
		json_emit_string(op_names[i]);
		printf(",\"trials\":%lu,\"wins\":%lu"
		       ",\"structured_trials\":%lu,\"structured_wins\":%lu}",
		       t, w, st, sw);
	}
	putchar(']');
}

static void json_emit_minicorpus_xprop(void)
{
	unsigned long xp_hits = __atomic_load_n(
		&minicorpus_shm->xprop_hits, __ATOMIC_RELAXED);
	unsigned long xp_wins = __atomic_load_n(
		&minicorpus_shm->xprop_wins, __ATOMIC_RELAXED);
	/* xprop attempt/reject breakdown so the
	 * hit-rate xp_hits / xp_attempts and the dominant
	 * reject cause are directly readable from the
	 * end-of-run dump. */
	unsigned long xp_attempts = __atomic_load_n(
		&minicorpus_shm->xprop_attempts, __ATOMIC_RELAXED);
	unsigned long xp_r_target = __atomic_load_n(
		&minicorpus_shm->xprop_reject_target_not_fdarg,
		__ATOMIC_RELAXED);
	unsigned long xp_r_self = __atomic_load_n(
		&minicorpus_shm->xprop_reject_src_self,
		__ATOMIC_RELAXED);
	unsigned long xp_r_empty = __atomic_load_n(
		&minicorpus_shm->xprop_reject_src_empty,
		__ATOMIC_RELAXED);

	printf(",\"xprop\":{\"hits\":%lu,\"wins\":%lu,\"attempts\":%lu,"
	       "\"reject_target_not_fdarg\":%lu,"
	       "\"reject_src_self\":%lu,"
	       "\"reject_src_empty\":%lu}",
	       xp_hits, xp_wins, xp_attempts, xp_r_target,
	       xp_r_self, xp_r_empty);
}

static void json_emit_minicorpus_stack_depth_histogram(void)
{
	unsigned int i;

	fputs(",\"stack_depth_histogram\":{", stdout);
	for (i = 1; i <= STACK_MAX; i++) {
		unsigned long d = __atomic_load_n(
			&minicorpus_shm->stack_depth_histogram[i], __ATOMIC_RELAXED);

		if (i > 1)
			putchar(',');
		printf("\"%u\":%lu", i, d);
	}
	putchar('}');
}

static void json_emit_minicorpus_saves_and_evicts(void)
{
	/* Pure-addition fields: dashboards that pin a strict-schema reader
	 * against "minicorpus" must tolerate two new keys.  Tracks the
	 * CMP-source corpus-save gate (saves_by_reason.cmp) and the
	 * CMP-sourced subset of mutator wins (mut_attrib_cmp_wins); both
	 * are zero pre-intervention so an unaware reader sees the
	 * historical signal unchanged. */
	unsigned long saves_pc = __atomic_load_n(
		&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
		__ATOMIC_RELAXED);
	unsigned long saves_cmp = __atomic_load_n(
		&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
		__ATOMIC_RELAXED);
	unsigned long saves_errno = __atomic_load_n(
		&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_ERRNO],
		__ATOMIC_RELAXED);
	unsigned long cmp_wins = __atomic_load_n(
		&minicorpus_shm->mut_attrib_cmp_wins,
		__ATOMIC_RELAXED);
	unsigned long evicts_pc = __atomic_load_n(
		&minicorpus_shm->evicts_by_reason[CORPUS_SAVE_REASON_PC],
		__ATOMIC_RELAXED);
	unsigned long evicts_cmp = __atomic_load_n(
		&minicorpus_shm->evicts_by_reason[CORPUS_SAVE_REASON_CMP],
		__ATOMIC_RELAXED);
	unsigned long errno_would = __atomic_load_n(
		&shm->stats.errno_gradient.save_would_save,
		__ATOMIC_RELAXED);
	unsigned long errno_did = __atomic_load_n(
		&shm->stats.errno_gradient.save_did_save,
		__ATOMIC_RELAXED);

	printf(",\"saves_by_reason\":{\"pc\":%lu,\"cmp\":%lu,\"errno\":%lu}"
	       ",\"evicts_by_reason\":{\"pc\":%lu,\"cmp\":%lu}"
	       ",\"mut_attrib_cmp_wins\":%lu"
	       ",\"errno_grad_save\":{\"would_save\":%lu,\"did_save\":%lu}",
	       saves_pc, saves_cmp, saves_errno, evicts_pc, evicts_cmp,
	       cmp_wins, errno_would, errno_did);
}

static void json_emit_minicorpus_replay_wins_by_age(void)
{
	unsigned int i;

	/* Replay-wins-by-entry-age histogram. */
	fputs(",\"replay_wins_by_age\":{", stdout);
	for (i = 0; i < ARRAY_SIZE(minicorpus_shm->replay_wins_by_age); i++) {
		unsigned long v = __atomic_load_n(
			&minicorpus_shm->replay_wins_by_age[i], __ATOMIC_RELAXED);

		if (i > 0)
			putchar(',');
		printf("\"%u\":%lu", i, v);
	}
	putchar('}');
}

static void json_emit_minicorpus_sequence_chains(void)
{
	unsigned long c_iter, c_subst, c_save, c_replay;

	c_iter   = __atomic_load_n(&minicorpus_shm->chain_iter_count,         __ATOMIC_RELAXED);
	c_subst  = __atomic_load_n(&minicorpus_shm->chain_substitution_count, __ATOMIC_RELAXED);
	c_save   = chain_corpus_shm ? __atomic_load_n(&chain_corpus_shm->save_count,   __ATOMIC_RELAXED) : 0UL;
	c_replay = chain_corpus_shm ? __atomic_load_n(&chain_corpus_shm->replay_count, __ATOMIC_RELAXED) : 0UL;
	printf(",\"sequence_chains\":{\"iter_count\":%lu,\"substitutions\":%lu,"
		"\"corpus_saves\":%lu,\"corpus_replays\":%lu}",
		c_iter, c_subst, c_save, c_replay);
}

void json_emit_minicorpus_section(void)
{
	unsigned long s_hits, s_wins, r_count, r_wins;

	if (minicorpus_shm == NULL) {
		fputs(",\"minicorpus\":null", stdout);
		return;
	}

	json_emit_minicorpus_mutators();

	s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
	s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
	printf(",\"splice\":{\"hits\":%lu,\"wins\":%lu}", s_hits, s_wins);

	json_emit_minicorpus_xprop();
	json_emit_minicorpus_stack_depth_histogram();

	r_count = __atomic_load_n(&minicorpus_shm->replay_count, __ATOMIC_RELAXED);
	r_wins  = __atomic_load_n(&minicorpus_shm->replay_wins,  __ATOMIC_RELAXED);
	printf(",\"replay\":{\"count\":%lu,\"wins\":%lu}", r_count, r_wins);

	json_emit_minicorpus_saves_and_evicts();
	json_emit_minicorpus_replay_wins_by_age();
	json_emit_minicorpus_sequence_chains();

	putchar('}');
}
