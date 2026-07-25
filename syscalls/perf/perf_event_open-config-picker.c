/*
 * perf_event_open: type/config pickers.
 *
 * Split out of syscalls/perf/perf_event_open.c so the per-type config
 * randomizers (hw/sw/cache/tracepoint/raw/breakpoint) and the top-level
 * random_event_config dispatch live away from the sanitise glue and
 * syscall descriptor.  random_sysfs_config, the PMU-sysfs-driven path
 * reached through PERF_TYPE_READ_FROM_SYSFS, lives with the PMU
 * enumeration TU (perf_event_open-pmu-discovery.c) and is called here
 * via the internal-header prototype.  setup_breakpoints fills the
 * bp_type / bp_addr / bp_len union fields for PERF_TYPE_BREAKPOINT and
 * is reachable from both the tuple picker and the attr builders.
 */

#include "child-api.h"
#include "maps.h"
#include "perf.h"
#include "perf_event.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

#include "perf_event_open-internal.h"

#include "kernel/hw_breakpoint.h"

/* arbitrary high number unlikely to be used by perf_event */
#define PERF_TYPE_READ_FROM_SYSFS 1027


long long random_cache_config(void)
{

	int cache_id, hw_cache_op_id, hw_cache_op_result_id;

	switch (rnd_modulo_u32(8)) {
	case 0:
		cache_id = PERF_COUNT_HW_CACHE_L1D;
		break;
	case 1:
		cache_id = PERF_COUNT_HW_CACHE_L1I;
		break;
	case 2:
		cache_id = PERF_COUNT_HW_CACHE_LL;
		break;
	case 3:
		cache_id = PERF_COUNT_HW_CACHE_DTLB;
		break;
	case 4:
		cache_id = PERF_COUNT_HW_CACHE_ITLB;
		break;
	case 5:
		cache_id = PERF_COUNT_HW_CACHE_BPU;
		break;
	case 6:
		cache_id = PERF_COUNT_HW_CACHE_NODE;
		break;
	case 7:
		cache_id = RAND_BYTE();
		break;
	default:
		cache_id = 0;
		break;
	}

	switch (rnd_modulo_u32(4)) {
	case 0:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_READ;
		break;
	case 1:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_WRITE;
		break;
	case 2:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_PREFETCH;
		break;
	case 3:
		hw_cache_op_id = RAND_BYTE();
		break;
	default:
		hw_cache_op_id = 0;
		break;
	}

	switch (rnd_modulo_u32(3)) {
	case 0:
		hw_cache_op_result_id = PERF_COUNT_HW_CACHE_RESULT_ACCESS;
		break;
	case 1:
		hw_cache_op_result_id = PERF_COUNT_HW_CACHE_RESULT_MISS;
		break;
	case 2:
		hw_cache_op_result_id = RAND_BYTE();
		break;
	default:
		hw_cache_op_result_id = 0;
		break;
	}

	return (cache_id) | (hw_cache_op_id << 8) | (hw_cache_op_result_id << 16);
}

int random_event_type(void)
{

	int type=0;

	switch (rnd_modulo_u32(8)) {
	case 0:
		type = PERF_TYPE_HARDWARE;
		break;
	case 1:
		type = PERF_TYPE_SOFTWARE;
		break;
	case 2:
		type = PERF_TYPE_TRACEPOINT;
		break;
	case 3:
		type = PERF_TYPE_HW_CACHE;
		break;
	case 4:
		type = PERF_TYPE_RAW;
		break;
	case 5:
		type = PERF_TYPE_BREAKPOINT;
		break;
	case 6:
		type = PERF_TYPE_READ_FROM_SYSFS;
		break;
	case 7:
		type = rand32();
		break;
	default:
		break;
	}
	return type;
}

static long long random_hw_config(void)
{
	unsigned long long config = 0;

	switch (rnd_modulo_u32(11)) {
	case 0:
		config = PERF_COUNT_HW_CPU_CYCLES;
		break;
	case 1:
		config = PERF_COUNT_HW_INSTRUCTIONS;
		break;
	case 2:
		config = PERF_COUNT_HW_CACHE_REFERENCES;
		break;
	case 3:
		config = PERF_COUNT_HW_CACHE_MISSES;
		break;
	case 4:
		config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
		break;
	case 5:
		config = PERF_COUNT_HW_BRANCH_MISSES;
		break;
	case 6:
		config = PERF_COUNT_HW_BUS_CYCLES;
		break;
	case 7:
		config = PERF_COUNT_HW_STALLED_CYCLES_FRONTEND;
		break;
	case 8:
		config = PERF_COUNT_HW_STALLED_CYCLES_BACKEND;
		break;
	case 9:
		config = PERF_COUNT_HW_REF_CPU_CYCLES;
		break;
	case 10:
		config = rand64();
		break;
	default:
		break;
	}
	return config;
}

static long long random_sw_config(void)
{
	unsigned long long config = 0;

	switch (rnd_modulo_u32(13)) {
	case 0:
		config = PERF_COUNT_SW_CPU_CLOCK;
		break;
	case 1:
		config = PERF_COUNT_SW_TASK_CLOCK;
		break;
	case 2:
		config = PERF_COUNT_SW_PAGE_FAULTS;
		break;
	case 3:
		config = PERF_COUNT_SW_CONTEXT_SWITCHES;
		break;
	case 4:
		config = PERF_COUNT_SW_CPU_MIGRATIONS;
		break;
	case 5:
		config = PERF_COUNT_SW_PAGE_FAULTS_MIN;
		break;
	case 6:
		config = PERF_COUNT_SW_PAGE_FAULTS_MAJ;
		break;
	case 7:
		config = PERF_COUNT_SW_ALIGNMENT_FAULTS;
		break;
	case 8:
		config = PERF_COUNT_SW_EMULATION_FAULTS;
		break;
	case 9:
		config = PERF_COUNT_SW_DUMMY;
		break;
	case 10:
		config = PERF_COUNT_SW_BPF_OUTPUT;
		break;
	case 11:
		config = PERF_COUNT_SW_CGROUP_SWITCHES;
		break;
	case 12:
		config = rand64();
		break;
	default:
		break;
	}
	return config;
}

long long random_event_config(__u32 *event_type,
					__u64 *config1,
					__u64 *config2)
{
	unsigned long long config=0;

	switch (*event_type) {
	case PERF_TYPE_HARDWARE:
		config = random_hw_config();
		break;
	case PERF_TYPE_SOFTWARE:
		config = random_sw_config();
		break;
	case PERF_TYPE_TRACEPOINT:
		/* Live ids enumerated once from /sys/kernel/tracing/events/...
		 * by init_tracepoint_ids(); random_tracepoint_config() draws
		 * from that pool ~7/8 of the time and falls back to the
		 * legacy random/rand64 roll for novelty coverage. */
		config = random_tracepoint_config();
		break;
	case PERF_TYPE_HW_CACHE:
		config = random_cache_config();
		break;
	case PERF_TYPE_RAW:
		/* can be arbitrary 64-bit value */
		/* there are some constraints we can add */
		/* to make it more likely to be a valid event */
		config = rand64();
		break;
	case PERF_TYPE_BREAKPOINT:
		/* PERF_TYPE_BREAKPOINT normally requires config == 0.  Keep that
		 * valid shape half the time, and deliberately fuzz non-zero
		 * config values the other half to exercise validation paths. */
		if (RAND_BOOL())
			config = rand64();
		else
			config = 0;
		break;

	case PERF_TYPE_READ_FROM_SYSFS:
		config = random_sysfs_config(event_type,config1,config2);
		break;

	default:
		config = rand64();
		*config1 = rand64();
		*config2 = rand64();
		break;
	}
	return config;
}

void setup_breakpoints(struct perf_event_attr *attr)
{

	switch (rnd_modulo_u32(6)) {
	case 0:
		attr->bp_type = HW_BREAKPOINT_EMPTY;
		break;
	case 1:
		attr->bp_type = HW_BREAKPOINT_R;
		break;
	case 2:
		attr->bp_type = HW_BREAKPOINT_W;
		break;
	case 3:
		attr->bp_type = HW_BREAKPOINT_RW;
		break;
	case 4:
		attr->bp_type = HW_BREAKPOINT_X;
		break;
	case 5:
		attr->bp_type = rand32();
		break;
	default:
		break;
	}

	/* This might be more interesting if this were    */
	/* a valid executable address for HW_BREAKPOINT_X */
	/* or a valid mem location for R/W/RW             */
	attr->bp_addr = (long)get_address();

	switch (rnd_modulo_u32(9)) {
	case 0:
		attr->bp_len = HW_BREAKPOINT_LEN_1;
		break;
	case 1:
		attr->bp_len = HW_BREAKPOINT_LEN_2;
		break;
	case 2:
		attr->bp_len = HW_BREAKPOINT_LEN_3;
		break;
	case 3:
		attr->bp_len = HW_BREAKPOINT_LEN_4;
		break;
	case 4:
		attr->bp_len = HW_BREAKPOINT_LEN_5;
		break;
	case 5:
		attr->bp_len = HW_BREAKPOINT_LEN_6;
		break;
	case 6:
		attr->bp_len = HW_BREAKPOINT_LEN_7;
		break;
	case 7:
		attr->bp_len = HW_BREAKPOINT_LEN_8;
		break;
	case 8:
		attr->bp_len = rand64();
		break;
	default:
		break;
	}
}
