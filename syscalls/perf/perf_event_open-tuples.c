/*
 * perf_event_open: tuple-aware (type, config) picker + vocab tables.
 *
 * Split out of syscalls/perf/perf_event_open.c so the hw_tuple_configs
 * / sw_tuple_configs vocabularies, the perf_tuples[] descriptor table
 * and the pick_perf_tuple driver that keeps attr->type and attr->config
 * co-derived live away from the sanitise glue and syscall descriptor.
 * pick_perf_tuple is reached by the create_mostly_valid_* attr builders
 * in the sibling attr TU via the internal-header prototype; the vocab
 * tables and the perf_tuple struct stay file-static because
 * pick_perf_tuple is their only consumer.
 */

#include "perf.h"
#include "perf_event.h"
#include "rnd.h"
#include "trinity.h"
#include "utils.h"

#include "perf_event_open-internal.h"

/*
 * Tuple-aware (type, config) picker.
 *
 * Historically attr->type and attr->config were chosen on independent
 * axes (random_event_type() / random_event_config()).  The kernel
 * validates the pair jointly in pmu_lookup(); the vast majority of
 * independent rolls land on a (type, config) the active PMU rejects,
 * the call dies with EINVAL before perf_event_alloc() runs, and the
 * deep PMU CMP volcano never sees fuzz traffic.
 *
 * Pick a tuple from a small table so type and config are co-derived.
 * About 1/16 of calls fall back to the legacy independent picker so
 * we keep coverage on newly-added kernel types and oddball encodings.
 *
 * Deliberately left to the legacy fallback:
 *   PERF_TYPE_TRACEPOINT       - config is a live tracepoint id read
 *                                from /sys/kernel/debug/tracing/...
 *                                Runtime enumeration of the tracepoint
 *                                set is out of scope here.
 *   PERF_TYPE_RAW              - config is a uarch-specific raw event
 *                                code.  A hardcoded subset would bias
 *                                coverage toward whatever CPU this
 *                                binary is built on.
 *   PERF_TYPE_READ_FROM_SYSFS  - random_sysfs_config() already walks
 *                                the sysfs PMU directory and synthesises
 *                                a tuple-correct (type, config[, config1,
 *                                config2]) from real PMU formats.
 */
static const __u64 hw_tuple_configs[] = {
	PERF_COUNT_HW_CPU_CYCLES,
	PERF_COUNT_HW_INSTRUCTIONS,
	PERF_COUNT_HW_CACHE_REFERENCES,
	PERF_COUNT_HW_CACHE_MISSES,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
	PERF_COUNT_HW_BRANCH_MISSES,
	PERF_COUNT_HW_BUS_CYCLES,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND,
	PERF_COUNT_HW_REF_CPU_CYCLES,
};

static const __u64 sw_tuple_configs[] = {
	PERF_COUNT_SW_CPU_CLOCK,
	PERF_COUNT_SW_TASK_CLOCK,
	PERF_COUNT_SW_PAGE_FAULTS,
	PERF_COUNT_SW_CONTEXT_SWITCHES,
	PERF_COUNT_SW_CPU_MIGRATIONS,
	PERF_COUNT_SW_PAGE_FAULTS_MIN,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ,
	PERF_COUNT_SW_ALIGNMENT_FAULTS,
	PERF_COUNT_SW_EMULATION_FAULTS,
	PERF_COUNT_SW_DUMMY,
	PERF_COUNT_SW_BPF_OUTPUT,
	PERF_COUNT_SW_CGROUP_SWITCHES,
};

struct perf_tuple {
	__u32 type;
	const __u64 *valid_configs;
	size_t n_configs;
	bool synth_cache_config;	/* HW_CACHE: synthesise (cache|op<<8|result<<16) */
	bool needs_bp_extras;		/* BREAKPOINT: also fill bp_type/bp_addr/bp_len */
};

static const struct perf_tuple perf_tuples[] = {
	{ PERF_TYPE_HARDWARE,   hw_tuple_configs, ARRAY_SIZE(hw_tuple_configs), false, false },
	{ PERF_TYPE_SOFTWARE,   sw_tuple_configs, ARRAY_SIZE(sw_tuple_configs), false, false },
	{ PERF_TYPE_HW_CACHE,   NULL, 0, true,  false },
	{ PERF_TYPE_BREAKPOINT, NULL, 0, false, true  },
};

bool pick_perf_tuple(struct perf_event_attr *attr)
{
	const struct perf_tuple *t;

	/* ~1/16 fall through to the legacy independent picker. */
	if (rnd_modulo_u32(16) == 0)
		return false;

	t = &perf_tuples[rnd_modulo_u32(ARRAY_SIZE(perf_tuples))];
	attr->type = t->type;

	if (t->synth_cache_config)
		attr->config = random_cache_config();
	else if (t->valid_configs != NULL)
		attr->config = t->valid_configs[rnd_modulo_u32(t->n_configs)];
	else
		attr->config = 0;

	if (t->needs_bp_extras)
		setup_breakpoints(attr);

	return true;
}
