/*
 * SYSCALL_DEFINE5(perf_event_open,
	 struct perf_event_attr __user *, attr_uptr,
	 pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
 */

#include <unistd.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include "cgroup.h"
#include "child.h"
#include "csfu.h"
#include "fd-event.h"
#include "maps.h"
#include "objects.h"
#include "perf.h"
#include "perf_event.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"
#include "pids.h"

#include "perf_event_open-internal.h"


#include "kernel/fcntl.h"
static long long random_sysfs_config(__u32 *type,
				__u64 *config1,
				__u64 *config2) {

	int i,j;
	long long c=0,c1=0,c2=0;

	if (num_pmus==0) {
		/* PMU sysfs enumeration failed or found no PMUs.  Fall back to
		 * fully random config values so the generator remains usable
		 * and avoids a modulo/divide-by-zero path. */
		*type=rand32();
		*config1=rand64();
		return rand64();
	}

	i=rnd_modulo_u32(num_pmus);

	*type=pmus[i].type;

	switch(rnd_modulo_u32(3)) {
		/* Random by Format */
		case 0:
			if (pmus[i].num_formats==0) goto out;
			for(j=0;j<pmus[i].num_formats;j++) {
				/* 50% chance of having field set */
				if (rnd_modulo_u32(2)) {
					if (pmus[i].formats[j].field==FIELD_CONFIG) {
						c|=(rand64()&pmus[i].formats[j].mask);
					} else if (pmus[i].formats[j].field==FIELD_CONFIG1) {
						c1|=(rand64()&pmus[i].formats[j].mask);
					} else {
						c2|=(rand64()&pmus[i].formats[j].mask);
					}
				}
			}
			break;


		/* Random by generic event */
		case 1:
			if (pmus[i].num_generic_events==0) goto out;
			j=rnd_modulo_u32(pmus[i].num_generic_events);
			c=pmus[i].generic_events[j].config;
			c1=pmus[i].generic_events[j].config1;
			c2=pmus[i].generic_events[j].config2;
			break;

		case 2:
			goto out;
	}
	*config1=c1;
	*config2=c2;
	return c;
out:
	*config1=rnd_modulo_u32(64);
	return rnd_modulo_u32(64);
}

/* arbitrary high number unlikely to be used by perf_event */
#define PERF_TYPE_READ_FROM_SYSFS 1027


static long long random_cache_config(void)
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

static int random_event_type(void)
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

static long long random_event_config(__u32 *event_type,
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

static void setup_breakpoints(struct perf_event_attr *attr)
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

static long long random_sample_type(void)
{

	long long sample_type = 0;

	if (RAND_BOOL())
		return rand64();

	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_IP;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_TID;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_TIME;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_ADDR;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_READ;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_CALLCHAIN;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_ID;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_CPU;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_PERIOD;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_STREAM_ID;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_RAW;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_BRANCH_STACK;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_REGS_USER;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_STACK_USER;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_WEIGHT;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_DATA_SRC;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_IDENTIFIER;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_TRANSACTION;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_REGS_INTR;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_PHYS_ADDR;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_AUX;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_CGROUP;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_DATA_PAGE_SIZE;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_CODE_PAGE_SIZE;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_WEIGHT_STRUCT;

	return sample_type;
}

static long long random_read_format(void)
{

	long long read_format = 0;

	if (RAND_BOOL())
		return rand64();

	if (RAND_BOOL())
		read_format |= PERF_FORMAT_GROUP;
	if (RAND_BOOL())
		read_format |= PERF_FORMAT_ID;
	if (RAND_BOOL())
		read_format |= PERF_FORMAT_TOTAL_TIME_ENABLED;
	if (RAND_BOOL())
		read_format |= PERF_FORMAT_TOTAL_TIME_RUNNING;
	if (RAND_BOOL())
		read_format |= PERF_FORMAT_LOST;

	return read_format;
}

static long long random_branch_sample_type(void)
{

	long long branch_sample = 0;

	if (RAND_BOOL())
		return rand64();

	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_USER;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_KERNEL;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_HV;

	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_ANY;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_ANY_CALL;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_ANY_RETURN;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_IND_CALL;

	/* Transactional Memory Types */
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_ABORT_TX;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_IN_TX;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_NO_TX;


	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_COND;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_CALL_STACK;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_IND_JUMP;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_CALL;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_NO_FLAGS;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_NO_CYCLES;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_TYPE_SAVE;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_HW_INDEX;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_PRIV_SAVE;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_COUNTERS;


	return branch_sample;
}


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

static bool pick_perf_tuple(struct perf_event_attr *attr)
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

static void create_mostly_valid_counting_event(struct perf_event_attr *attr,
						int group_leader)
{

	if (!pick_perf_tuple(attr)) {
		attr->type = random_event_type();
		attr->config = random_event_config(&attr->type,
						&attr->config1,
						&attr->config2);
	}

	/* no freq for counting event */
	/* no sample type for counting event */

	attr->read_format = random_read_format();

	/* Bitfield parameters, mostly boolean */
	attr->disabled = RAND_BOOL();
	attr->inherit = RAND_BOOL();
	if (group_leader) {
		attr->pinned = RAND_BOOL();
	}
	attr->exclusive = RAND_BOOL();
	attr->exclude_user = RAND_BOOL();
	attr->exclude_kernel = RAND_BOOL();
	attr->exclude_hv = RAND_BOOL();
	attr->exclude_idle = RAND_BOOL();
	attr->mmap = RAND_BOOL();
	attr->comm = RAND_BOOL();
	attr->freq = RAND_BOOL();
	attr->inherit_stat = RAND_BOOL();
	attr->enable_on_exec = RAND_BOOL();
	attr->task = RAND_BOOL();
	attr->watermark = RAND_BOOL();
	attr->precise_ip = rnd_modulo_u32(4);	// two bits
	attr->mmap_data = RAND_BOOL();
	attr->sample_id_all = RAND_BOOL();
	attr->exclude_host = RAND_BOOL();
	attr->exclude_guest = RAND_BOOL();
	attr->exclude_callchain_kernel = RAND_BOOL();
	attr->exclude_callchain_user = RAND_BOOL();
	attr->mmap2 = RAND_BOOL();
	attr->comm_exec = RAND_BOOL();
	attr->use_clockid = RAND_BOOL();
	attr->context_switch = RAND_BOOL();
	attr->write_backward = RAND_BOOL();
	attr->namespaces = RAND_BOOL();
	attr->ksymbol = RAND_BOOL();
	attr->bpf_event = RAND_BOOL();
	attr->aux_output = RAND_BOOL();
	attr->cgroup = RAND_BOOL();
	attr->text_poke = RAND_BOOL();
	attr->build_id = RAND_BOOL();
	attr->inherit_thread = RAND_BOOL();
	attr->remove_on_exec = RAND_BOOL();
	attr->sigtrap = RAND_BOOL();

	/* wakeup events not relevant */

	/* breakpoint events unioned with config */
	if (attr->type == PERF_TYPE_BREAKPOINT) {
		setup_breakpoints(attr);
	} else {
		/* Non-breakpoint events already had config1/config2 populated
		 * by the earlier type-specific path; only breakpoint events
		 * need the union fields rebuilt here. */
	}

	/* branch_sample_type not relevant if not sampling */

	/* sample_regs_user not relevant if not sampling */

	/* sample_stack_user not relevant if not sampling */

	/* aux_watermark not relevant if not sampling */

	/* sample_max_stack not relevant if not sampling */
}

static void create_mostly_valid_sampling_event(struct perf_event_attr *attr,
						int group_leader)
{

	if (!pick_perf_tuple(attr)) {
		attr->type = random_event_type();
		attr->config = random_event_config(&attr->type,
						&attr->config1,
						&attr->config2);
	}

	/* low values more likely to have "interesting" results */
	attr->sample_period = rand64();
	attr->sample_type = random_sample_type();
	attr->read_format = random_read_format();

	/* Bitfield parameters, mostly boolean */
	attr->disabled = RAND_BOOL();
	attr->inherit = RAND_BOOL();
	/* only group leaders can be pinned */
	if (group_leader) {
		attr->pinned = RAND_BOOL();
	} else {
		attr->pinned = 0;
	}
	attr->exclusive = RAND_BOOL();
	attr->exclude_user = RAND_BOOL();
	attr->exclude_kernel = RAND_BOOL();
	attr->exclude_hv = RAND_BOOL();
	attr->exclude_idle = RAND_BOOL();
	attr->mmap = RAND_BOOL();
	attr->comm = RAND_BOOL();
	attr->freq = RAND_BOOL();
	attr->inherit_stat = RAND_BOOL();
	attr->enable_on_exec = RAND_BOOL();
	attr->task = RAND_BOOL();
	attr->watermark = RAND_BOOL();
	attr->precise_ip = rnd_modulo_u32(4);	// two bits
	attr->mmap_data = RAND_BOOL();
	attr->sample_id_all = RAND_BOOL();
	attr->exclude_host = RAND_BOOL();
	attr->exclude_guest = RAND_BOOL();
	attr->exclude_callchain_kernel = RAND_BOOL();
	attr->exclude_callchain_user = RAND_BOOL();
	attr->mmap2 = RAND_BOOL();
	attr->comm_exec = RAND_BOOL();
	attr->use_clockid = RAND_BOOL();
	attr->context_switch = RAND_BOOL();
	attr->write_backward = RAND_BOOL();
	attr->namespaces = RAND_BOOL();
	attr->ksymbol = RAND_BOOL();
	attr->bpf_event = RAND_BOOL();
	attr->aux_output = RAND_BOOL();
	attr->cgroup = RAND_BOOL();
	attr->text_poke = RAND_BOOL();
	attr->build_id = RAND_BOOL();
	attr->inherit_thread = RAND_BOOL();
	attr->remove_on_exec = RAND_BOOL();
	attr->sigtrap = RAND_BOOL();

	attr->wakeup_events = rand32();

	if (attr->type == PERF_TYPE_BREAKPOINT) {
		setup_breakpoints(attr);
	}
	else {
		/* breakpoint fields unioned with config fields */
		/* config1 set earlier */
	}

	attr->branch_sample_type = random_branch_sample_type();

	/* sample_regs_user is a bitmask of CPU registers to record.     */
	/* The values come from arch/ARCH/include/uapi/asm/perf_regs.h   */
	/* Most architectures have fewer than 64 registers...            */
	switch(rnd_modulo_u32(3)) {
		case 0:		attr->sample_regs_user = rnd_modulo_u32(16);
				break;
		case 1:		attr->sample_regs_user = rnd_modulo_u32(64);
				break;
		case 2:		attr->sample_regs_user = rand64();
				break;
		default:
				break;
	}

	/* sample_stack_user is the size of user stack backtrace we want  */
	/* if we pick too large of a value the kernel in theory truncates */
	attr->sample_stack_user = rand32();

	if (attr->use_clockid) {
		switch(rnd_modulo_u32(6)) {
			case 0:	attr->clockid = CLOCK_MONOTONIC;
				break;
			case 1: attr->clockid = CLOCK_MONOTONIC_RAW;
				break;
			case 2: attr->clockid = CLOCK_REALTIME;
				break;
			case 3: attr->clockid = CLOCK_BOOTTIME;
				break;
			/* Most possible values < 32 */
			case 4: attr->clockid = RAND_BYTE();
				break;
			case 5:	attr->clockid = rnd_u32();
				break;
		}
	}

	attr->aux_watermark = rand32();
	attr->sample_max_stack = rand32();
}


/* Creates a global event: one that is not per-process, but system-wide	*/
/* To be valid must be created with pid=-1 and cpu being a valid CPU.   */
/* Also usually only root can create these unless                       */
/*    /proc/sys/kernel/perf_event_paranoid is less than 1.              */
/* Most custom PMU types (uncore/northbridge/RAPL) are covered here.    */

static void create_mostly_valid_global_event(struct perf_event_attr *attr,
						int group_leader)
{

	if (!pick_perf_tuple(attr)) {
		attr->type = random_event_type();
		attr->config = random_event_config(&attr->type,
						&attr->config1,
						&attr->config2);
	}

	attr->read_format = random_read_format();

	/* Bitfield parameters, mostly boolean */
	attr->disabled = RAND_BOOL();
	attr->inherit = RAND_BOOL();
	if (group_leader) {
		attr->pinned = RAND_BOOL();
	}

	/* Not setting most other paramaters */
	/* As they tend to be not valid in a global event */
}

/* Creates a completely random event, unlikely to be valid */
static void create_random_event(struct perf_event_attr *attr)
{

	attr->type = random_event_type();

	attr->config = random_event_config(&attr->type,
					&attr->config1,
					&attr->config2);

	attr->sample_period = rand64();
	attr->sample_type = random_sample_type();
	attr->read_format = random_read_format();

	/* bitfields */
	attr->disabled = RAND_BOOL();
	attr->inherit = RAND_BOOL();
	attr->pinned = RAND_BOOL();
	attr->exclusive = RAND_BOOL();
	attr->exclude_user = RAND_BOOL();
	attr->exclude_kernel = RAND_BOOL();
	attr->exclude_hv = RAND_BOOL();
	attr->exclude_idle = RAND_BOOL();
	attr->mmap = RAND_BOOL();
	attr->comm = RAND_BOOL();
	attr->freq = RAND_BOOL();
	attr->inherit_stat = RAND_BOOL();
	attr->enable_on_exec = RAND_BOOL();
	attr->task = RAND_BOOL();
	attr->watermark = RAND_BOOL();
	attr->precise_ip = rnd_modulo_u32(4);
	attr->mmap_data = RAND_BOOL();
	attr->sample_id_all = RAND_BOOL();
	attr->exclude_host = RAND_BOOL();
	attr->exclude_guest = RAND_BOOL();
	attr->exclude_callchain_kernel = RAND_BOOL();
	attr->exclude_callchain_user = RAND_BOOL();
	attr->mmap2 = RAND_BOOL();
	attr->comm_exec = RAND_BOOL();
	attr->use_clockid = RAND_BOOL();
	attr->context_switch = RAND_BOOL();
	attr->write_backward = RAND_BOOL();
	attr->namespaces = RAND_BOOL();
	attr->ksymbol = RAND_BOOL();
	attr->bpf_event = RAND_BOOL();
	attr->aux_output = RAND_BOOL();
	attr->cgroup = RAND_BOOL();
	attr->text_poke = RAND_BOOL();
	attr->build_id = RAND_BOOL();
	attr->inherit_thread = RAND_BOOL();
	attr->remove_on_exec = RAND_BOOL();
	attr->sigtrap = RAND_BOOL();

	attr->wakeup_events=rand32();

	/* Breakpoints are unioned with the config values */
	if (RAND_BOOL()) {
		setup_breakpoints(attr);
	}
	else {
		/* config1 set earlier */
		attr->config2 = rand64();
	}

	attr->branch_sample_type = rand64();
	attr->sample_regs_user = rand64();
	attr->sample_stack_user = rand32();

}

#ifndef PERF_ATTR_SIZE_VER0
#define PERF_ATTR_SIZE_VER0	64
#endif
#ifndef PERF_ATTR_SIZE_VER1
#define PERF_ATTR_SIZE_VER1	72
#endif
#ifndef PERF_ATTR_SIZE_VER2
#define PERF_ATTR_SIZE_VER2	80
#endif
#ifndef PERF_ATTR_SIZE_VER3
#define PERF_ATTR_SIZE_VER3	96
#endif
#ifndef PERF_ATTR_SIZE_VER4
#define PERF_ATTR_SIZE_VER4	104
#endif
#ifndef PERF_ATTR_SIZE_VER5
#define PERF_ATTR_SIZE_VER5	112
#endif
#ifndef PERF_ATTR_SIZE_VER6
#define PERF_ATTR_SIZE_VER6	120
#endif
#ifndef PERF_ATTR_SIZE_VER7
#define PERF_ATTR_SIZE_VER7	128
#endif
#ifndef PERF_ATTR_SIZE_VER8
#define PERF_ATTR_SIZE_VER8	136
#endif
#ifndef PERF_ATTR_SIZE_VER9
#define PERF_ATTR_SIZE_VER9	144
#endif

/*
 * Pre-ksize ABI floors for the csfu UNDERSIZE bucket.  The kernel
 * accepts a perf_event_open call whose attr->size matches any prior
 * ABI version and zero-pads the remainder.  build_csfu_struct()
 * draws uniformly from this pool for UNDERSIZE; PERF_ATTR_SIZE_VER9
 * equals sizeof(struct perf_event_attr) on a current kernel and is
 * kept in the pool so the table stays self-documenting and remains
 * correct once the kernel grows a further ABI version.
 */
static const size_t perf_event_attr_known_sizes[] = {
	PERF_ATTR_SIZE_VER0,
	PERF_ATTR_SIZE_VER1,
	PERF_ATTR_SIZE_VER2,
	PERF_ATTR_SIZE_VER3,
	PERF_ATTR_SIZE_VER4,
	PERF_ATTR_SIZE_VER5,
	PERF_ATTR_SIZE_VER6,
	PERF_ATTR_SIZE_VER7,
	PERF_ATTR_SIZE_VER8,
	PERF_ATTR_SIZE_VER9,
};

static const struct csfu_desc desc_perf_event_attr = {
	.name = "perf_event_attr",
	.ksize = sizeof(struct perf_event_attr),
	.known_sizes = perf_event_attr_known_sizes,
	.n_known_sizes = ARRAY_SIZE(perf_event_attr_known_sizes),
};

static void pick_perf_cpu(struct syscallrecord *rec)
{
	/* cpu */
	/* requires ROOT to select specific CPU if pid==-1 (all processes) */
	/* -1 means all CPUs */

	if (RAND_BOOL()) {
		/* Any CPU */
		rec->a3 = -1;
	} else {
		/* Default to the get_cpu() value */
		/* set by ARG_CPU                 */
	}
}

static int pick_perf_group_fd(struct syscallrecord *rec)
{
	int group_leader = 0;

	/* group_fd is usually -1 or another perf_event fd.  Random non--1
	 * values mostly fail unless they name a compatible group leader,
	 * but they still exercise the kernel's validation path. */
	switch (rnd_modulo_u32(3)) {
	case 0:
		rec->a4 = -1;
		group_leader = 1;
		break;
	case 1:
		/* Try to get a previous random perf_event_open() fd  */
		rec->a4 = get_rand_perf_fd();
		break;
	case 2:
		/* Rely on ARG_FD */
		break;
	default:
		break;
	}

	return group_leader;
}

static unsigned long pick_perf_flags(void)
{
	unsigned long flags = 0;

	/* flags */
	/* You almost never set these unless you're playing with cgroups */
	if (RAND_BOOL()) {
		flags = rand64();
	} else {
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_NO_GROUP;
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_OUTPUT;
		if (RAND_BOOL())
			flags |= PERF_FLAG_PID_CGROUP;
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_CLOEXEC;
	}

	return flags;
}

static pid_t pick_perf_pid(unsigned long flags)
{
	pid_t pid;

	/* pid */
	/* requires ROOT to select pid that doesn't belong to us */

	if (flags & PERF_FLAG_PID_CGROUP) {
		/* PERF_FLAG_PID_CGROUP makes the kernel interpret 'pid' as
		 * a cgroup directory fd (an O_PATH dir under /sys/fs/cgroup).
		 * Pull from the cgroup pool so the cgroup-pinned perf path
		 * actually exercises real cgroup attachment instead of
		 * bouncing off EBADF on the first random fd we hand it.
		 * If the pool is empty (no cgroupfs mounted, init failed),
		 * fall back to a generic random fd to keep this path firing. */
		pid = get_rand_cgroup_fd();
		if (pid < 0)
			pid = get_random_fd();
	} else {
		switch(rnd_modulo_u32(4)) {
		case 0:	/* use current thread */
			pid = 0;
			break;
		case 1: /* get an arbitrary pid */
			pid = get_pid();
			break;
		case 2:	/* measure *all* pids.  Might require root */
			pid = -1;
			break;
		case 3: /* measure our actual pid */
			pid=mypid();
			break;
		default:
			pid = 0;
			break;
		}
	}

	return pid;
}

static void maybe_fill_perf_attr_body(struct perf_event_attr *attr,
				      enum csfu_bucket bucket,
				      int group_leader)
{
	/*
	 * Non-EXACT buckets exercise the size validator only -- the
	 * kernel rejects on attr->size before reading any body field,
	 * and OVERSIZE_NONZERO / TAIL_MISMATCH need their tail garbage
	 * preserved.  Skip the structured fill on those paths; the
	 * zmalloc_tracked() buffer is already zeroed where the kernel
	 * cares to look.
	 */
	if (bucket != CSFU_BUCKET_EXACT)
		return;

	switch (rnd_modulo_u32(4)) {
	case 0:
		create_mostly_valid_counting_event(attr, group_leader);
		break;
	case 1:
		create_mostly_valid_sampling_event(attr, group_leader);
		break;
	case 2:
		create_mostly_valid_global_event(attr, group_leader);
		break;
	case 3:
		create_random_event(attr);
		break;
	default:
		break;
	}
}

void sanitise_perf_event_open(struct syscallrecord *rec)
{
	struct csfu_buf buf = build_csfu_struct(&desc_perf_event_attr);
	struct perf_event_attr *attr = buf.ptr;
	unsigned long flags;
	pid_t pid;
	int group_leader;

	if (!attr)
		return;

	/*
	 * perf_event_open has no separate usize syscall arg; the kernel
	 * pulls attr->size out of the user buffer itself and drives
	 * copy_struct_from_user against that.  Plant the csfu-picked
	 * usize here so the validator gets exercised across all five
	 * bucket shapes instead of the open-coded VER0..VER8 + raw
	 * garbage roll that used to live in random_attr_size().
	 */
	attr->size = buf.usize;

	rec->a1 = (unsigned long) attr;

	/*
	 * Stash the csfu buffer in rec->post_state so the unconditional
	 * .cleanup hook frees it.  Cleanup must be independent of whether
	 * the .post handler runs: when reject_corrupt_retfd() flags retfd,
	 * handle_syscall_ret() skips .post entirely, and a post-side free
	 * would leak the snap.  post_perf_event_open does not touch
	 * post_state, so it is free to carry the buffer.
	 */
	rec->post_state = (unsigned long) attr;

	pick_perf_cpu(rec);

	group_leader = pick_perf_group_fd(rec);

	flags = pick_perf_flags();
	rec->a5 = flags;

	pid = pick_perf_pid(flags);
	rec->a2 = pid;

	maybe_fill_perf_attr_body(attr, buf.bucket, group_leader);

	avoid_shared_buffer_inout(&rec->a1, buf.usize);
}

static void post_perf_event_open(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd >= 0 && fd < (1 << 20)) {
		unsigned long flags = get_arg_snapshot(rec, 5);
		bool needs_immediate_teardown =
			(flags & (PERF_FLAG_PID_CGROUP | PERF_FLAG_FD_OUTPUT)) != 0;

		if (needs_immediate_teardown) {
			struct childdata *child = this_child();

			/*
			 * Cgroup-pinned and FD_OUTPUT-redirected events hold
			 * kernel-side references that outlive our fd: the
			 * cgroup keeps cgroup-pinned events scheduled across
			 * every task in the cgroup, and the FD_OUTPUT producer
			 * keeps writing into the consumer's ring buffer until
			 * its own deferred teardown.  Letting the dispatcher
			 * stash the fd into the OBJ_FD_PERF pool and waiting
			 * for child teardown to close it would leave both
			 * paths firing under the iteration scope of a child
			 * that may run for hours.  Walk the event off
			 * synchronously here, then coerce rec->retval = -1UL
			 * so register_returned_fd()'s (long)retval < 0 gate
			 * skips the about-to-be-closed fd -- handle_success()
			 * already ran above this layer, so the success tally
			 * is preserved.
			 */
			if (child != NULL)
				notify_child_fd_closed(child, fd);

			remove_object_by_fd(fd);

			ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
			close(fd);

			rec->retval = -1UL;
		}
		/*
		 * Common path: leave the fd open.  The dispatcher's
		 * register_returned_fd() runs after this handler and claims
		 * the fd into the OBJ_FD_PERF OBJ_LOCAL pool via the
		 * .ret_objtype annotation.  perffd_destructor handles
		 * IOC_DISABLE+close at child teardown -- and walks the pool
		 * for any peers whose group_fd matches the leader, disabling
		 * and closing those too.
		 */
	} else if (fd != -1) {
		outputerr("post_perf_event_open: rejecting out-of-bound fd=%d\n", fd);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	rec->a1 = 0;
}

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)
#endif

static unsigned long perf_event_open_flags[] = {
	PERF_FLAG_FD_NO_GROUP, PERF_FLAG_FD_OUTPUT, PERF_FLAG_PID_CGROUP,
	PERF_FLAG_FD_CLOEXEC,
};

static void cleanup_perf_event_open(struct syscallrecord *rec)
{
	cleanup_release_post_state(rec);
}

struct syscallentry syscall_perf_event_open = {
	.name = "perf_event_open",
	.num_args = 5,
	.argtype = { [0] = ARG_STRUCT_PTR_IN, [1] = ARG_PID, [2] = ARG_CPU, [3] = ARG_FD_PERF, [4] = ARG_LIST },
	.argname = { [0] = "attr_uptr", [1] = "pid", [2] = "cpu", [3] = "group_fd", [4] = "flags" },
	.arg_params[4].list = ARGLIST(perf_event_open_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_PERF,
	.sanitise = sanitise_perf_event_open,
	.post = post_perf_event_open,
	.cleanup = cleanup_perf_event_open,
	.init = init_pmus,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_PROCESS,
	/* a5 (flags) gates the synchronous-teardown decision in
	 * post_perf_event_open: PERF_FLAG_PID_CGROUP / FD_OUTPUT mark
	 * events whose kernel-side references outlive our fd and must
	 * be walked off here (rec->retval forced -1), vs. plain events
	 * left for the OBJ_FD_PERF pool to close at child teardown.
	 * Shadow a5 so a sibling stomp between dispatch and post cannot
	 * flip that gate -- leaking a pinned event into the pool, or
	 * tearing down a plain fd the caller still owns.  Mismatch
	 * bumps arg_shadow_stomp from inside get_arg_snapshot(). */
	.arg_snapshot_mask = (1u << 4),
};
