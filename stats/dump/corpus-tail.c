#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

static void dump_corpus_mutator_productivity(void)
{
	unsigned long tot_trials = 0;
	unsigned int i;

	for (i = 0; i < MUT_NUM_OPS; i++)
		tot_trials += __atomic_load_n(&minicorpus_shm->mut_trials[i],
					      __ATOMIC_RELAXED);

	if (tot_trials == 0)
		return;

	output(0, "\nMutator productivity (wins/trials  [structured wins/trials]):\n");
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t  = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						   __ATOMIC_RELAXED);
		unsigned long w  = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						   __ATOMIC_RELAXED);
		unsigned long st = __atomic_load_n(
			&minicorpus_shm->mut_structured_trials[i],
			__ATOMIC_RELAXED);
		unsigned long sw = __atomic_load_n(
			&minicorpus_shm->mut_structured_wins[i],
			__ATOMIC_RELAXED);
		unsigned long spct10 = st ? (sw * 1000UL / st) : 0UL;
		unsigned long pct10 = t ? (w * 1000UL / t) : 0UL;

		output(0, "  %-10s %lu/%lu (%lu.%lu%%)  [%lu/%lu (%lu.%lu%%)]\n",
		       op_names[i], w, t, pct10 / 10, pct10 % 10,
		       sw, st, spct10 / 10, spct10 % 10);
	}
}

static void dump_corpus_xprop(void)
{
	unsigned long xp_hits = __atomic_load_n(
		&minicorpus_shm->xprop_hits, __ATOMIC_RELAXED);
	unsigned long xp_wins = __atomic_load_n(
		&minicorpus_shm->xprop_wins, __ATOMIC_RELAXED);
	unsigned long pct10;

	if (xp_hits == 0)
		return;

	pct10 = xp_wins * 1000UL / xp_hits;
	output(0, "Xprop: %lu hits  %lu wins (%lu.%lu%%)\n",
	       xp_hits, xp_wins, pct10 / 10, pct10 % 10);
}

static void dump_corpus_stack_depth(void)
{
	unsigned long histo_total = 0;
	char hbuf[80];
	int hpos = 0;
	int written;
	unsigned int i;

	for (i = 1; i <= STACK_MAX; i++)
		histo_total += __atomic_load_n(&minicorpus_shm->stack_depth_histogram[i],
					       __ATOMIC_RELAXED);
	if (histo_total == 0)
		return;

	for (i = 1; i <= STACK_MAX; i++) {
		unsigned long d = __atomic_load_n(
			&minicorpus_shm->stack_depth_histogram[i],
			__ATOMIC_RELAXED);
		/* Bound BEFORE snprintf — sizeof(hbuf)-hpos goes to
		 * zero when full, but snprintf still returns the
		 * would-have-written length and the next iteration's
		 * hbuf+hpos lands past the buffer.  Stop here. */
		if (hpos >= (int)sizeof(hbuf) - 1)
			break;
		written = snprintf(hbuf + hpos, sizeof(hbuf) - hpos,
				   " [%u]:%lu", i, d);
		if (written < 0)
			break;
		hpos += written;
	}
	output(0, "Stack depth:%s\n", hbuf);
}

/* CMP-source save / win telemetry.  Always emit when the
 * minicorpus block is being dumped -- a zero on saves_cmp is
 * itself a signal worth seeing ("the gate widening is in but
 * the path isn't firing"), per the falsification criteria in
 * the investigations/ analysis. */
static void dump_corpus_saves(void)
{
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
	unsigned long errno_would = __atomic_load_n(
		&shm->stats.errno_gradient.save_would_save,
		__ATOMIC_RELAXED);
	unsigned long errno_did = __atomic_load_n(
		&shm->stats.errno_gradient.save_did_save,
		__ATOMIC_RELAXED);

	output(0, "Corpus saves: pc=%lu cmp=%lu errno=%lu  mut wins (cmp-source): %lu\n",
	       saves_pc, saves_cmp, saves_errno, cmp_wins);
	output(0, "Errno-gradient save: would=%lu did=%lu (gate=%s)\n",
	       errno_would, errno_did,
	       corpus_save_errno_grad_live ? "live" : "shadow");
}

/*
 * Per-tag productivity for the C.2b post-fill struct-field
 * mutator.  Independent from the per-op MUT_NUM_OPS counters
 * dumped above -- different injection point, different
 * histogram axis.  Suppressed when the aggregate trial count
 * is zero so a build / fleet that never invoked the path
 * stays clean; a single non-zero slot brings the whole
 * histogram into view so per-tag relative productivity
 * (FT_FLAGS bit-flips vs FT_RAW noise) is greppable.
 * Skip-listed tags (FT_PTR_*, FT_LEN_*, FT_FD, FT_ADDRESS,
 * FT_BPF_PROGRAM, FT_TAGGED_UNION) stay zero by design and
 * are silently skipped to keep the output compact.
 */
static void dump_corpus_struct_field_mutator(void)
{
	static const char *const tag_names[FT_NUM_TAGS] = {
		[FT_RAW]		= "raw",
		[FT_ENUM]		= "enum",
		[FT_RANGE]		= "range",
		[FT_FLAGS]		= "flags",
		[FT_PTR_BYTES]		= "ptr_bytes",
		[FT_PTR_ARRAY]		= "ptr_array",
		[FT_PTR_STRUCT]		= "ptr_struct",
		[FT_LEN_BYTES]		= "len_bytes",
		[FT_LEN_COUNT]		= "len_count",
		[FT_FD]			= "fd",
		[FT_MAGIC]		= "magic",
		[FT_VERSION_MAGIC]	= "vermagic",
		[FT_ADDRESS]		= "address",
		[FT_TAGGED_UNION]	= "tagged_union",
		[FT_BPF_PROGRAM]	= "bpf_program",
		[FT_VOCAB]		= "vocab",
		[FT_PICKER]		= "picker",
		[FT_EMBEDDED_STRUCT]	= "embedded_struct",
	};
	unsigned long sf_total = 0;
	unsigned int t;

	for (t = 0; t < FT_NUM_TAGS; t++)
		sf_total += __atomic_load_n(
			&minicorpus_shm->mut_struct_field_trials[t],
			__ATOMIC_RELAXED);

	if (sf_total == 0)
		return;

	output(0, "\nStruct-field mutator wins/trials (per tag):\n");
	for (t = 0; t < FT_NUM_TAGS; t++) {
		unsigned long tr = __atomic_load_n(
			&minicorpus_shm->mut_struct_field_trials[t],
			__ATOMIC_RELAXED);
		unsigned long wn = __atomic_load_n(
			&minicorpus_shm->mut_struct_field_wins[t],
			__ATOMIC_RELAXED);
		unsigned long tag_pct10;

		if (tr == 0 || tag_names[t] == NULL)
			continue;
		tag_pct10 = wn * 1000UL / tr;
		output(0, "  %-12s %lu/%lu (%lu.%lu%%)\n",
		       tag_names[t], wn, tr,
		       tag_pct10 / 10, tag_pct10 % 10);
	}
}

static void dump_corpus_sequence_chains(void)
{
	unsigned long c_iter = __atomic_load_n(
		&minicorpus_shm->chain_iter_count,
		__ATOMIC_RELAXED);
	unsigned long c_subst = __atomic_load_n(
		&minicorpus_shm->chain_substitution_count,
		__ATOMIC_RELAXED);
	unsigned long c_save = chain_corpus_shm ? __atomic_load_n(
		&chain_corpus_shm->save_count,
		__ATOMIC_RELAXED) : 0UL;
	unsigned long c_replay = chain_corpus_shm ? __atomic_load_n(
		&chain_corpus_shm->replay_count,
		__ATOMIC_RELAXED) : 0UL;

	if (c_iter > 0)
		output(0, "Sequence chains: %lu iters  %lu substitutions  %lu corpus saves  %lu replays\n",
		       c_iter, c_subst, c_save, c_replay);
}

static void dump_stats_corpus_tail(void)
{
	unsigned long s_hits, s_wins, r_count, r_wins, torn, pct10;

	dump_corpus_mutator_productivity();

	s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
	s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
	if (s_hits > 0) {
		pct10 = s_wins * 1000UL / s_hits;
		output(0, "Splice: %lu hits  %lu wins (%lu.%lu%%)\n",
		       s_hits, s_wins, pct10 / 10, pct10 % 10);
	}

	dump_corpus_xprop();

	/* Lockless-reader torn-read validator firings (aggregate over
	 * xprop pick, replay common, replay burst).  Gated on non-zero
	 * because the expected steady-state value is 0 -- the writer's
	 * release-store publish pattern makes mid-publish reads rare.
	 * A non-zero rate here means the validator is doing real work
	 * and torn reads ARE happening at the printed rate. */
	torn = __atomic_load_n(&minicorpus_shm->replay_torn_rejects,
			       __ATOMIC_RELAXED);
	if (torn > 0)
		output(0, "Corpus torn-read rejects: %lu\n", torn);

	dump_corpus_stack_depth();

	r_count = __atomic_load_n(&minicorpus_shm->replay_count, __ATOMIC_RELAXED);
	r_wins  = __atomic_load_n(&minicorpus_shm->replay_wins,  __ATOMIC_RELAXED);
	if (r_count > 0) {
		pct10 = r_wins * 1000UL / r_count;
		output(0, "Corpus replay: %lu replays  %lu wins (%lu.%lu%%)\n",
		       r_count, r_wins, pct10 / 10, pct10 % 10);
	}

	dump_corpus_saves();
	dump_corpus_struct_field_mutator();
	dump_corpus_sequence_chains();
}

static void dump_stats_cmp_hints_tail(void)
{
	unsigned int total_hints = 0, syscalls_with_hints = 0;
	unsigned int i, a;

	/* Per-arch slots count individually -- same rationale as the
	 * JSON emitter above. */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		for (a = 0; a < 2; a++) {
			unsigned int n = cmp_hints_pool_safe_count(&cmp_hints_shm->pools[i][a]);

			if (n > 0) {
				total_hints += n;
				syscalls_with_hints++;
			}
		}
	}
	stat_row("cmp_hints", "values_total",        total_hints);
	stat_row("cmp_hints", "syscalls_with_hints", syscalls_with_hints);
}

/*
 * Periodic snapshot of /proc/sys/kernel/tainted so successive
 * stats dumps record when the kernel became tainted and which
 * flags were set, without waiting for is_tainted()'s mask-gated
 * "became tainted" trip.  Skipped on a clean kernel to match
 * the "suppress when zero" convention of the surrounding blocks.
 * mask row carries the raw bitmask; one row per recognised flag
 * makes the decoded set greppable.
 */
static void dump_stats_taint_snapshot(void)
{
	static const struct {
		const char *name;
		int bit;
	} taint_flags[] = {
		{ "PROPRIETARY_MODULE",    TAINT_PROPRIETARY_MODULE },
		{ "FORCED_MODULE",         TAINT_FORCED_MODULE },
		{ "UNSAFE_SMP",            TAINT_UNSAFE_SMP },
		{ "FORCED_RMMOD",          TAINT_FORCED_RMMOD },
		{ "MACHINE_CHECK",         TAINT_MACHINE_CHECK },
		{ "BAD_PAGE",              TAINT_BAD_PAGE },
		{ "USER",                  TAINT_USER },
		{ "DIE",                   TAINT_DIE },
		{ "OVERRIDDEN_ACPI_TABLE", TAINT_OVERRIDDEN_ACPI_TABLE },
		{ "WARN",                  TAINT_WARN },
		{ "CRAP",                  TAINT_CRAP },
		{ "FIRMWARE_WORKAROUND",   TAINT_FIRMWARE_WORKAROUND },
		{ "OOT_MODULE",            TAINT_OOT_MODULE },
	};
	int current_taint = get_taint();
	unsigned int t;

	if (current_taint != 0) {
		stat_row("taint", "mask", (unsigned long)current_taint);
		for (t = 0; t < ARRAY_SIZE(taint_flags); t++)
			if (current_taint & (1U << taint_flags[t].bit))
				stat_row("taint", taint_flags[t].name, 1);
	}
}

void dump_stats_corpus_and_taint_tail(void)
{
	if (minicorpus_shm != NULL)
		dump_stats_corpus_tail();

	if (cmp_hints_shm != NULL)
		dump_stats_cmp_hints_tail();

	dump_stats_taint_snapshot();
}
