/*
 * Typed hypothesis pool-grid render lane.
 *
 * Walks hyp_pools[nr][do32] to expose live pool occupancy: per-syscall
 * saturation top-N (with per-kind fill breakdown) and the per-entry
 * outcome aggregates (corpus_save_wins / destructive_skips /
 * context_skips) that have no kcov_shm scalar twin.  Read-side only;
 * counters are RELAXED against lockless observe / scrub bumps and
 * every count is clamped to CMP_HYP_PER_SYSCALL / CMP_HYP_PER_KIND so
 * a torn load cannot drive a downstream divide or fixed-width column
 * past its cap.  Called only from kcov_cmp_stats_periodic_dump() in
 * stats/kcov/cmp/periodic.c.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdio.h>
#include "arch.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "params.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "stats/kcov/cmp/internal.h"

/*
 * Per-syscall typed-hypothesis store SATURATION: top-N (nr, do32) pools
 * ranked by pool->count, with the per_kind_count[] breakdown so the
 * (nr, kind) cells that crowd the store are visible.
 *
 * pool->count and pool->per_kind_count[] have no kcov_shm scalar twin:
 * the cumulative cmp_hyp_kind_full / inserted_by_kind producer counters
 * never surface the live occupancy, so an exhausted (nr, kind) cell is
 * invisible from the cumulative producer view alone.
 *
 * Read-side only: relaxed loads against lockless observe / scrub bumps,
 * count clamped to CMP_HYP_PER_SYSCALL and per_kind to CMP_HYP_PER_KIND
 * so a torn load cannot drive a downstream divide or fixed-width column
 * past its cap.  Gated on any-occupancy so an empty store stays quiet.
 */
void kcov_cmp_hyp_saturation_block_render(long elapsed __unused__)
{
#define KCOV_CMP_HYP_SAT_TOPN	32
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	struct sat_row {
		unsigned int nr;
		unsigned int do32;
		unsigned int count;
		unsigned int per_kind[CMP_HYP_KIND_NR];
	};
	struct sat_row top[KCOV_CMP_HYP_SAT_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_scan[2];
	unsigned int nr_i, do32_i, k, j;
	unsigned long occupied_pools = 0;
	unsigned long total_entries = 0;

	if (cmp_hints_shm == NULL)
		return;

	nr_scan[0] = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	nr_scan[1] = biarch ? max_nr_32bit_syscalls : 0;
	for (do32_i = 0; do32_i < 2; do32_i++)
		if (nr_scan[do32_i] > MAX_NR_SYSCALL)
			nr_scan[do32_i] = MAX_NR_SYSCALL;

	for (do32_i = 0; do32_i < 2; do32_i++) {
		for (nr_i = 0; nr_i < nr_scan[do32_i]; nr_i++) {
			struct cmp_hyp_pool *p =
				&cmp_hints_shm->hyp_pools[nr_i][do32_i];
			unsigned int count = __atomic_load_n(
				&p->count, __ATOMIC_RELAXED);
			struct sat_row cand;

			if (count == 0)
				continue;
			if (count > CMP_HYP_PER_SYSCALL)
				count = CMP_HYP_PER_SYSCALL;

			occupied_pools++;
			total_entries += count;

			cand.nr = nr_i;
			cand.do32 = do32_i;
			cand.count = count;
			for (k = 0; k < CMP_HYP_KIND_NR; k++) {
				unsigned int pk = __atomic_load_n(
					&p->per_kind_count[k], __ATOMIC_RELAXED);

				if (pk > CMP_HYP_PER_KIND)
					pk = CMP_HYP_PER_KIND;
				cand.per_kind[k] = pk;
			}

			for (j = top_count;
			     j > 0 && count > top[j - 1].count;
			     j--) {
				if (j < KCOV_CMP_HYP_SAT_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_CMP_HYP_SAT_TOPN) {
				top[j] = cand;
				if (top_count < KCOV_CMP_HYP_SAT_TOPN)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	stats_log_write("KCOV CMP hyp store per-syscall saturation over last %lds (top-%u of %lu occupied pools, %lu entries, cap %u/pool):\n",
			elapsed, top_count, occupied_pools,
			total_entries, CMP_HYP_PER_SYSCALL);
	{
		char hdr[CMP_HYP_KIND_NR * 12 + 1];
		int off = 0;

		hdr[0] = '\0';
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			int w = snprintf(hdr + off, sizeof(hdr) - off,
					 " %11s", kind_labels[k]);
			if (w < 0 || (size_t)w >= sizeof(hdr) - (size_t)off)
				break;
			off += w;
		}
		stats_log_write("  %-24s %4s %9s %5s%s\n",
				"syscall", "arch", "count/cap", "fill%", hdr);
	}

	for (j = 0; j < top_count; j++) {
		const struct sat_row *r = &top[j];
		const struct syscalltable *tab;
		struct syscallentry *entry;
		const char *name;
		const char *arch_tag;
		unsigned int nr_max;
		unsigned int pct;
		char count_buf[16];
		char row[CMP_HYP_KIND_NR * 12 + 1];
		int off = 0;

		if (biarch) {
			if (r->do32) {
				tab = syscalls_32bit;
				nr_max = max_nr_32bit_syscalls;
				arch_tag = "32";
			} else {
				tab = syscalls_64bit;
				nr_max = max_nr_64bit_syscalls;
				arch_tag = "64";
			}
		} else {
			tab = syscalls;
			nr_max = max_nr_syscalls;
			arch_tag = "-";
		}
		entry = (r->nr < nr_max) ? tab[r->nr].entry : NULL;
		name = entry ? entry->name : "???";
		pct = (unsigned int)(((unsigned long)r->count * 100UL) /
				     CMP_HYP_PER_SYSCALL);

		snprintf(count_buf, sizeof(count_buf), "%u/%u",
			 r->count, CMP_HYP_PER_SYSCALL);

		row[0] = '\0';
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			int w = snprintf(row + off, sizeof(row) - off,
					 " %11u", r->per_kind[k]);
			if (w < 0 || (size_t)w >= sizeof(row) - (size_t)off)
				break;
			off += w;
		}

		stats_log_write("  %-24s %4s %9s %4u%%%s\n",
				name, arch_tag, count_buf, pct, row);
	}
#undef KCOV_CMP_HYP_SAT_TOPN
}
/*
 * SHADOW per-hypothesis outcome aggregates that have no kcov_shm
 * flat-counter twin (corpus_save_wins / destructive_skips /
 * context_skips).  Walk the hyp_pools[][] grid once per window and
 * sum the per-entry u64s; render gated on any-delta so the section
 * stays quiet until a future credit site fires.  The walk is bounded
 * (MAX_NR_SYSCALL * 2 pools * CMP_HYP_PER_SYSCALL entries) and runs
 * at parent stats cadence, well below any noticeable cost.  Reads
 * are RELAXED against credit-side bumps; a torn sum at most under-
 * counts a single in-flight credit on this window and converges on
 * the next render.
 */
void kcov_cmp_render_hyp_per_hypothesis_aggregates_block(long elapsed)
{
	if (cmp_hints_shm == NULL)
		return;

	static uint64_t prev_hyp_corpus_save_wins;
	static uint64_t prev_hyp_destructive_skips;
	static uint64_t prev_hyp_context_skips;
	uint64_t cur_hyp_corpus_save_wins = 0;
	uint64_t cur_hyp_destructive_skips = 0;
	uint64_t cur_hyp_context_skips = 0;
	uint64_t delta_hyp_corpus_save_wins;
	uint64_t delta_hyp_destructive_skips;
	uint64_t delta_hyp_context_skips;
	unsigned int nr_i, do32_i, e_i;

	for (nr_i = 0; nr_i < MAX_NR_SYSCALL; nr_i++) {
		for (do32_i = 0; do32_i < 2; do32_i++) {
			struct cmp_hyp_pool *p =
				&cmp_hints_shm->hyp_pools[nr_i][do32_i];
			unsigned int n = p->count;

			if (n > CMP_HYP_PER_SYSCALL)
				n = CMP_HYP_PER_SYSCALL;
			for (e_i = 0; e_i < n; e_i++) {
				struct cmp_hypothesis *h = &p->entries[e_i];

				cur_hyp_corpus_save_wins +=
					__atomic_load_n(&h->corpus_save_wins,
							__ATOMIC_RELAXED);
				cur_hyp_destructive_skips +=
					__atomic_load_n(&h->destructive_skips,
							__ATOMIC_RELAXED);
				cur_hyp_context_skips +=
					__atomic_load_n(&h->context_skips,
							__ATOMIC_RELAXED);
			}
		}
	}

	delta_hyp_corpus_save_wins = sat_sub_ul(cur_hyp_corpus_save_wins, prev_hyp_corpus_save_wins);
	delta_hyp_destructive_skips = sat_sub_ul(cur_hyp_destructive_skips, prev_hyp_destructive_skips);
	delta_hyp_context_skips = sat_sub_ul(cur_hyp_context_skips, prev_hyp_context_skips);

	if ((delta_hyp_corpus_save_wins | delta_hyp_destructive_skips |
	     delta_hyp_context_skips) != 0) {
		stats_log_write("KCOV CMP hyp per-hypothesis aggregates over last %lds:\n", elapsed);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_corpus_save_wins",
				(unsigned long)delta_hyp_corpus_save_wins,
				(unsigned long)cur_hyp_corpus_save_wins);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_destructive_skips",
				(unsigned long)delta_hyp_destructive_skips,
				(unsigned long)cur_hyp_destructive_skips);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_context_skips",
				(unsigned long)delta_hyp_context_skips,
				(unsigned long)cur_hyp_context_skips);
	}

	prev_hyp_corpus_save_wins = cur_hyp_corpus_save_wins;
	prev_hyp_destructive_skips = cur_hyp_destructive_skips;
	prev_hyp_context_skips = cur_hyp_context_skips;
}
