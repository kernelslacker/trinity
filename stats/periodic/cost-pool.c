
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

/*
 * Per-pool active-count snapshot for the cost-pool selector foundation.
 *
 * The picker still draws from the flat shm->active_syscalls*[] arrays;
 * the cheap / expensive pools maintained beside them by the activate /
 * deactivate paths are storage-only in this phase.  This dump surfaces
 * the pool populations so the operator can watch the partition stay
 * consistent with the flat count (invariant: cheap + exp == flat) and
 * see the cheap / expensive split of the active set at run-end and at
 * every periodic tick.  RELAXED atomic reads: pool counts only shift
 * on -x auto-disable / validation-failure deactivation, which is
 * infrequent, and any torn read biases the surface by at most one
 * activation between the flat and pool halves.
 *
 * Self-rate-limited on DEFENSE_DUMP_INTERVAL_SEC so the 10-minute cadence
 * matches the surrounding periodic surfaces and long-fuzz logs stay
 * legible; the caller in run_periodic_surfaces() fires it every tick
 * and this gate absorbs the frequency.
 */
void __cold cost_pool_periodic_dump(void)
{
	static struct timespec last_dump;
	struct timespec now;
	long elapsed;

	clock_gettime(CLOCK_MONOTONIC, &now);

	if (last_dump.tv_sec == 0) {
		last_dump = now;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	last_dump = now;

	if (biarch == true) {
		unsigned int flat32 = __atomic_load_n(&shm->nr_active_32bit_syscalls,
						      __ATOMIC_RELAXED);
		unsigned int flat64 = __atomic_load_n(&shm->nr_active_64bit_syscalls,
						      __ATOMIC_RELAXED);
		unsigned int c32 = __atomic_load_n(&shm->nr_active_cheap_32bit,
						   __ATOMIC_RELAXED);
		unsigned int e32 = __atomic_load_n(&shm->nr_active_exp_32bit,
						   __ATOMIC_RELAXED);
		unsigned int c64 = __atomic_load_n(&shm->nr_active_cheap_64bit,
						   __ATOMIC_RELAXED);
		unsigned int e64 = __atomic_load_n(&shm->nr_active_exp_64bit,
						   __ATOMIC_RELAXED);

		stats_log_write("cost-pool active: 32bit flat=%u cheap=%u exp=%u  "
				"64bit flat=%u cheap=%u exp=%u\n",
				flat32, c32, e32, flat64, c64, e64);
	} else {
		unsigned int flat = __atomic_load_n(&shm->nr_active_syscalls,
						    __ATOMIC_RELAXED);
		unsigned int cheap = __atomic_load_n(&shm->nr_active_cheap,
						     __ATOMIC_RELAXED);
		unsigned int exp = __atomic_load_n(&shm->nr_active_exp,
						   __ATOMIC_RELAXED);

		stats_log_write("cost-pool active: flat=%u cheap=%u exp=%u\n",
				flat, cheap, exp);
	}

	/* Cost-pool selector shadow / live counters -- emitted alongside
	 * the pool-active snapshot above so an operator can watch the
	 * closed-form section 4.1 identity hold empirically as the run
	 * progresses.  RELAXED atomic reads: each counter is an
	 * independent aggregate so no cross-counter tearing invariant
	 * matters here; the analytical (ppm-scaled) fraction can be
	 * off by at most one pick-worth-of-ppm relative to shadow_picks
	 * across a torn snapshot, which is well below the noise floor
	 * of a real run.  Rendered only when the observer engaged
	 * (mode != OFF) OR the live-attribution pair accumulated (which
	 * happens on every run regardless of mode) so a fixed-seed
	 * --dry-run under OFF still emits the live-actual fraction as a
	 * baseline reference. */
	{
		unsigned long shadow_picks = __atomic_load_n(
			&shm->stats.cost_pool_selector_shadow_picks,
			__ATOMIC_RELAXED);
		unsigned long shadow_ppm_sum = __atomic_load_n(
			&shm->stats.cost_pool_selector_shadow_expensive_ppm_sum,
			__ATOMIC_RELAXED);
		unsigned long live_cheap = __atomic_load_n(
			&shm->stats.cost_pool_selector_live_cheap_picks,
			__ATOMIC_RELAXED);
		unsigned long live_exp = __atomic_load_n(
			&shm->stats.cost_pool_selector_live_expensive_picks,
			__ATOMIC_RELAXED);
		unsigned long predraw_cheap = __atomic_load_n(
			&shm->stats.cost_pool_selector_predraw_cheap_picks,
			__ATOMIC_RELAXED);
		unsigned long predraw_exp = __atomic_load_n(
			&shm->stats.cost_pool_selector_predraw_expensive_picks,
			__ATOMIC_RELAXED);
		unsigned long live_total = live_cheap + live_exp;
		unsigned long predraw_total = predraw_cheap + predraw_exp;
		unsigned long shadow_exp_ppm = 0;
		unsigned long live_exp_ppm = 0;
		unsigned long predraw_exp_ppm = 0;
		const char *mode_name;

		if (shadow_picks > 0)
			shadow_exp_ppm = shadow_ppm_sum / shadow_picks;
		if (live_total > 0)
			live_exp_ppm = (1000000UL * live_exp) / live_total;
		if (predraw_total > 0)
			predraw_exp_ppm = (1000000UL * predraw_exp) / predraw_total;

		switch (cost_pool_selector_mode) {
		case COST_POOL_SELECTOR_MODE_OFF:
			mode_name = "off"; break;
		case COST_POOL_SELECTOR_MODE_SHADOW_ONLY:
			mode_name = "shadow-only"; break;
		case COST_POOL_SELECTOR_MODE_COMBINED:
			mode_name = "combined"; break;
		default:
			mode_name = "?"; break;
		}

		stats_log_write("cost-pool selector: mode=%s "
				"shadow picks=%lu exp_ppm=%lu  "
				"predraw cheap=%lu exp=%lu exp_ppm=%lu  "
				"live cheap=%lu exp=%lu exp_ppm=%lu\n",
				mode_name,
				shadow_picks, shadow_exp_ppm,
				predraw_cheap, predraw_exp, predraw_exp_ppm,
				live_cheap, live_exp, live_exp_ppm);
	}
}
