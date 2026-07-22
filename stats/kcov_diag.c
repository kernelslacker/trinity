/*
 * KCOV diag counter dumps + minicorpus mutation-attribution canary.
 *
 * Carved verbatim out of stats.c.  Contains
 * minicorpus_mut_attrib_canary_check (the mid-run parent-side
 * cross-check that scans the MUT_NUM_OPS attribution counters for
 * accidental double-attribution or missed wins), the descriptor-
 * driven per-syscall KCOV diagnostic block emitter
 * kcov_diag_emit_block, and the truncation top-N walker
 * kcov_diag_emit_truncation_topn.  kcov_diag_load is the shared
 * per-slot loader those two emitters use.
 *
 * Every exported entry point is already declared in an existing
 * header (minicorpus_mut_attrib_canary_check in include/minicorpus.h;
 * the two kcov_diag_emit_* in stats-internal.h) so no additions to
 * stats-internal.h are needed for this cluster.  kcov_diag_load
 * stays file-static -- its only callers are the two emit helpers
 * in this same TU.
 */

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

void __cold minicorpus_mut_attrib_canary_check(void)
{
	static time_t last_check_mono;
	static bool first_witness_emitted;
	struct timespec ts;
	time_t now;
	unsigned int i;

	if (minicorpus_shm == NULL)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	/* First call seeds the gate without scanning -- mirrors the
	 * kcov_bitmap_canary_check() first-call seed.  Subsequent calls
	 * scan no more than once per MUT_ATTRIB_CANARY_INTERVAL_SEC, with
	 * the timestamp stamped from CLOCK_MONOTONIC so a backward NTP
	 * step cannot suppress an otherwise-due check. */
	if (last_check_mono == 0) {
		last_check_mono = now;
		return;
	}
	if ((unsigned long)(now - last_check_mono) <
	    MUT_ATTRIB_CANARY_INTERVAL_SEC)
		return;
	last_check_mono = now;

	/* Sample trials BEFORE wins for each pair so any in-flight
	 * producer that bumps both between the two loads biases the
	 * observed (wins - trials) DOWNWARD (the matching trial bump is
	 * already in the trials sample, the matching win bump may not
	 * be in the wins sample yet) and cannot manufacture a false
	 * inversion.  The opposite order is the one with the per-CPU
	 * skew window, hence the load order. */
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

		if (w > t + MUT_ATTRIB_INVERSION_TOL) {
			__atomic_fetch_add(&shm->stats.plateau.mut_attrib_inversion_caught,
					   1UL, __ATOMIC_RELAXED);
			if (!first_witness_emitted) {
				stats_log_write("CANARY: minicorpus mut_wins[%u]=%lu > mut_trials[%u]=%lu (tol=%lu, op=%s) -- counter word scribbled\n",
						i, w, i, t,
						MUT_ATTRIB_INVERSION_TOL,
						op_names[i]);
				first_witness_emitted = true;
			}
		}

		if (sw > st + MUT_ATTRIB_INVERSION_TOL) {
			__atomic_fetch_add(&shm->stats.plateau.mut_attrib_inversion_caught,
					   1UL, __ATOMIC_RELAXED);
			if (!first_witness_emitted) {
				stats_log_write("CANARY: minicorpus mut_structured_wins[%u]=%lu > mut_structured_trials[%u]=%lu (tol=%lu, op=%s) -- counter word scribbled\n",
						i, sw, i, st,
						MUT_ATTRIB_INVERSION_TOL,
						op_names[i]);
				first_witness_emitted = true;
			}
		}
	}
}

/* Per-syscall KCOV diagnostic blocks.  One block per counter in
 * struct kcov_per_syscall_diag, emitted as a top-20-non-zero list
 * sorted descending by counter value.  The block is skipped entirely
 * when no (nr, arch) slot has a non-zero value -- silence is the
 * diagnostic signal for the truncation/overflow counters in a
 * well-sized run, and an empty top-20 stanza would only be noise.
 *
 * Counter ordering across the dump is alphabetical by counter name.
 * Keep it that way: future additions to kcov_per_syscall_diag slot
 * in deterministically and log-grep over historical dumps stays
 * stable.
 */

#define KCOV_DIAG_TOPN	20

struct kcov_diag_entry {
	unsigned int nr;
	bool do32;
	uint64_t value;
};

static uint64_t kcov_diag_load(const struct kcov_per_syscall_diag *d,
			       enum kcov_diag_counter c)
{
	switch (c) {
	case KCOV_DIAG_BUCKET_BITS_REAL:
		return __atomic_load_n(&d->bucket_bits_real, __ATOMIC_RELAXED);
	case KCOV_DIAG_CMP_TRACE_TRUNCATED:
		return __atomic_load_n(&d->cmp_trace_truncated, __ATOMIC_RELAXED);
	case KCOV_DIAG_DEDUP_PROBE_OVERFLOW:
		return __atomic_load_n(&d->dedup_probe_overflow, __ATOMIC_RELAXED);
	case KCOV_DIAG_DISTINCT_PCS:
		return __atomic_load_n(&d->distinct_pcs, __ATOMIC_RELAXED);
	case KCOV_DIAG_MAX_TRACE_SIZE:
		return __atomic_load_n(&d->max_trace_size, __ATOMIC_RELAXED);
	case KCOV_DIAG_TRACE_TRUNCATED:
		return __atomic_load_n(&d->trace_truncated, __ATOMIC_RELAXED);
	}
	return 0;
}

void kcov_diag_emit_block(const char *counter_name,
				 enum kcov_diag_counter counter)
{
	struct kcov_diag_entry top[KCOV_DIAG_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_per_arch[2];
	unsigned int arch, i;
	int j;

	/* Mirror the arch-dim scan bounds used by the existing per-syscall
	 * top-N blocks: under biarch iterate both tables, under uniarch
	 * only the single active table.  do32=true rows are always zero in
	 * uniarch builds and the (skipped) arch=1 column drops out
	 * naturally. */
	if (biarch) {
		nr_per_arch[0] = max_nr_64bit_syscalls;
		nr_per_arch[1] = max_nr_32bit_syscalls;
	} else {
		nr_per_arch[0] = max_nr_syscalls;
		nr_per_arch[1] = 0;
	}
	for (arch = 0; arch < 2; arch++)
		if (nr_per_arch[arch] > MAX_NR_SYSCALL)
			nr_per_arch[arch] = MAX_NR_SYSCALL;

	for (arch = 0; arch < 2; arch++) {
		bool do32 = (arch == 1);

		for (i = 0; i < nr_per_arch[arch]; i++) {
			uint64_t value = kcov_diag_load(
				&kcov_shm->per_syscall_cmp.per_syscall_diag[i][do32 ? 1 : 0],
				counter);

			if (value == 0)
				continue;

			/* Insertion sort, descending by value, capped at
			 * KCOV_DIAG_TOPN -- same shape as the sibling
			 * top-edges block above. */
			for (j = (int)top_count;
			     j > 0 && value > top[j - 1].value; j--) {
				if (j < KCOV_DIAG_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_DIAG_TOPN) {
				top[j].nr = i;
				top[j].do32 = do32;
				top[j].value = value;
				if (top_count < KCOV_DIAG_TOPN)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	output(0, "Top syscalls by %s:\n", counter_name);
	for (j = 0; j < (int)top_count; j++) {
		const char *name = print_syscall_name(top[j].nr, top[j].do32);

		output(0, "  nr=%u (%s) [arch=%s] %" PRIu64 "\n",
		       top[j].nr, name,
		       top[j].do32 ? "32" : "64",
		       top[j].value);
	}
}

/* combined top-N table joining
 * per-syscall trace_truncated + cmp_trace_truncated + max_trace_size
 * (with its share of KCOV_TRACE_SIZE) on the same row, plus a single
 * summary line for dedup-probe-overflow.
 *
 * Sibling kcov_diag_emit_block calls already rank each counter on its
 * own; that flattens the cross-counter signal -- a syscall whose trace
 * mostly saturates without an outright truncation event drops off the
 * trace_truncated block, and one whose CMP buffer truncates appears in
 * a separate stanza from the trace one.  This combined view ranks by
 * max(trace_truncated, max_trace_size) so saturation-without-trunc and
 * trunc-with-modest-max both surface, and prints the CMP counterpart in
 * the same row -- the data needed to decide between a global
 * --kcov-trace-size knob and a targeted large-trace child pool
 * (buffer knob).  Diagnostic only; no collection, buffer, or
 * reward path is touched.
 */
#define KCOV_DIAG_TRUNC_TOPN	10

struct kcov_diag_trunc_entry {
	unsigned int nr;
	bool do32;
	uint64_t trace_truncated;
	uint64_t cmp_trace_truncated;
	uint64_t max_trace_size;
	/* per_syscall_calls[] and per_syscall_edges[] are indexed by nr
	 * only, not by arch; under biarch both rows for the same nr show
	 * the same denominator.  The ratio still answers "what share of
	 * this syscall's calls produced an arch-N trunc" / "how many
	 * edge-winning calls landed for each truncation on this syscall". */
	uint64_t calls;
	uint64_t edge_wins;
	uint64_t rank;
};

void kcov_diag_emit_truncation_topn(void)
{
	struct kcov_diag_trunc_entry top[KCOV_DIAG_TRUNC_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_per_arch[2];
	unsigned int arch, i;
	int j;
	uint64_t dedup_per_syscall_sum = 0;
	uint64_t dedup_global;
	unsigned int dedup_syscall_count = 0;

	if (biarch) {
		nr_per_arch[0] = max_nr_64bit_syscalls;
		nr_per_arch[1] = max_nr_32bit_syscalls;
	} else {
		nr_per_arch[0] = max_nr_syscalls;
		nr_per_arch[1] = 0;
	}
	for (arch = 0; arch < 2; arch++)
		if (nr_per_arch[arch] > MAX_NR_SYSCALL)
			nr_per_arch[arch] = MAX_NR_SYSCALL;

	for (arch = 0; arch < 2; arch++) {
		bool do32 = (arch == 1);

		for (i = 0; i < nr_per_arch[arch]; i++) {
			const struct kcov_per_syscall_diag *d =
				&kcov_shm->per_syscall_cmp.per_syscall_diag[i][do32 ? 1 : 0];
			uint64_t tt = __atomic_load_n(&d->trace_truncated,
						      __ATOMIC_RELAXED);
			uint64_t ct = __atomic_load_n(&d->cmp_trace_truncated,
						      __ATOMIC_RELAXED);
			uint64_t mt = __atomic_load_n(&d->max_trace_size,
						      __ATOMIC_RELAXED);
			uint64_t dpo = __atomic_load_n(&d->dedup_probe_overflow,
						       __ATOMIC_RELAXED);
			uint64_t calls = per_syscall_calls_total(i);
			uint64_t ew = per_syscall_edges_total(i);
			uint64_t rank;

			if (dpo > 0) {
				dedup_per_syscall_sum += dpo;
				dedup_syscall_count++;
			}

			rank = (tt > mt) ? tt : mt;
			if (rank == 0 && ct == 0)
				continue;
			if (rank == 0)
				rank = ct;

			for (j = (int)top_count;
			     j > 0 && rank > top[j - 1].rank; j--) {
				if (j < KCOV_DIAG_TRUNC_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_DIAG_TRUNC_TOPN) {
				top[j].nr = i;
				top[j].do32 = do32;
				top[j].trace_truncated = tt;
				top[j].cmp_trace_truncated = ct;
				top[j].max_trace_size = mt;
				top[j].calls = calls;
				top[j].edge_wins = ew;
				top[j].rank = rank;
				if (top_count < KCOV_DIAG_TRUNC_TOPN)
					top_count++;
			}
		}
	}

	if (top_count > 0) {
		output(0, "Top syscalls by trace truncation / max trace (kcov_trace_size=%u longs):\n",
		       kcov_trace_size);
		output(0, "  %5s %-24s %-4s %14s %14s %14s %7s %8s %8s\n",
		       "nr", "name", "arch",
		       "trace_trunc", "cmp_trace_tr", "max_trace",
		       "pct_max", "tt/call", "ew/tt");
		for (j = 0; j < (int)top_count; j++) {
			const char *name = print_syscall_name(top[j].nr,
							      top[j].do32);
			unsigned int pct10 = (unsigned int)
				((top[j].max_trace_size * 1000ULL) /
				 (uint64_t)kcov_trace_size);
			char tt_call_str[32];
			char ew_tt_str[32];

			if (top[j].calls > 0) {
				uint64_t p = (top[j].trace_truncated * 1000ULL) /
					     top[j].calls;
				snprintf(tt_call_str, sizeof(tt_call_str),
					 "%5" PRIu64 ".%" PRIu64 "%%",
					 p / 10, p % 10);
			} else {
				snprintf(tt_call_str, sizeof(tt_call_str),
					 "%8s", "-");
			}
			if (top[j].trace_truncated > 0) {
				uint64_t p = (top[j].edge_wins * 1000ULL) /
					     top[j].trace_truncated;
				snprintf(ew_tt_str, sizeof(ew_tt_str),
					 "%5" PRIu64 ".%" PRIu64 "%%",
					 p / 10, p % 10);
			} else {
				snprintf(ew_tt_str, sizeof(ew_tt_str),
					 "%8s", "-");
			}

			output(0, "  %5u %-24s %-4s %14" PRIu64
				  " %14" PRIu64 " %14" PRIu64
				  " %4u.%u%% %8s %8s\n",
			       top[j].nr, name,
			       top[j].do32 ? "32" : "64",
			       top[j].trace_truncated,
			       top[j].cmp_trace_truncated,
			       top[j].max_trace_size,
			       pct10 / 10, pct10 % 10,
			       tt_call_str, ew_tt_str);
		}
	}

	dedup_global = __atomic_load_n(&kcov_shm->dedup.dedup_probe_overflow,
				       __ATOMIC_RELAXED);
	if (dedup_global > 0 || dedup_per_syscall_sum > 0) {
		output(0, "kcov dedup probe overflow: global=%" PRIu64
			  " per_syscall_sum=%" PRIu64
			  " syscalls_affected=%u\n",
		       dedup_global, dedup_per_syscall_sum,
		       dedup_syscall_count);
	}
}
