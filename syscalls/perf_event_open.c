/*
 * SYSCALL_DEFINE5(perf_event_open,
	 struct perf_event_attr __user *, attr_uptr,
	 pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
 */

#include <stdlib.h>
#include <string.h>
#include "perf_event.h"
#include "random.h"
#include "sanitise.h"
#include "compat.h"
#include "maps.h"
#include "shm.h"

static long long random_cache_config(void)
{

	int cache_id, hw_cache_op_id, hw_cache_op_result_id;

	switch (rand() % 8) {
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
	default:
		cache_id = rand();
		break;
	}

	switch (rand() % 4) {
	case 0:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_READ;
		break;
	case 1:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_WRITE;
		break;
	case 2:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_PREFETCH;
		break;
	default:
		hw_cache_op_id = rand();
		break;
	}

	switch (rand() % 3) {
	case 0:
		hw_cache_op_result_id = PERF_COUNT_HW_CACHE_RESULT_ACCESS;
		break;
	case 1:
		hw_cache_op_result_id = PERF_COUNT_HW_CACHE_RESULT_MISS;
		break;
	default:
		hw_cache_op_result_id = rand();
		break;
	}

	return (cache_id) | (hw_cache_op_id << 8) | (hw_cache_op_result_id << 16);
}

static int random_event_type(void)
{

	int type;

	switch (rand() % 6) {
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
	default:
		type = rand();
		break;
	}
	return type;
}

static long long random_event_config(long long event_type)
{
	unsigned long long config;

	switch (event_type) {
	case PERF_TYPE_HARDWARE:
		switch (rand() % 11) {
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
		default:
			config = rand64();
			break;
		}
		break;
	case PERF_TYPE_SOFTWARE:
		switch (rand() % 10) {
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
		default:
			config = rand64();
			break;
		}
		break;
	case PERF_TYPE_TRACEPOINT:
		/* Actual values to use can be found under */
		/* debugfs tracing/events// *//*/id         */
		config = rand64();
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
		/* Breakpoint type only valid if config==0 */
		/* Set it to something else too anyway     */
		if (rand_bool())
			config = rand64();
		else
			config = 0;
		break;

/* FIXME: value can also be one of the ones found in */
/* /sys/bus/event_source/devices                     */

	default:
		config = rand64();
		break;
	}
	return config;
}

static void setup_breakpoints(struct perf_event_attr *attr)
{

	switch (rand() % 6) {
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
	default:
		attr->bp_type = rand();
		break;
	}

	/* This might be more interesting if this were    */
	/* a valid executable address for HW_BREAKPOINT_X */
	/* or a valid mem location for R/W/RW             */
	attr->bp_addr = rand();

	switch (rand() % 5) {
	case 0:
		attr->bp_len = HW_BREAKPOINT_LEN_1;
		break;
	case 1:
		attr->bp_len = HW_BREAKPOINT_LEN_2;
		break;
	case 2:
		attr->bp_len = HW_BREAKPOINT_LEN_4;
		break;
	case 3:
		attr->bp_len = HW_BREAKPOINT_LEN_8;
		break;
	default:
		attr->bp_len = rand();
		break;
	}
}

static long long random_sample_type(void)
{

	long long sample_type = 0;

	if (rand() % 2)
		return rand();

	if (rand_bool())
		sample_type |= PERF_SAMPLE_IP;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_TID;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_TIME;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_ADDR;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_READ;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_CALLCHAIN;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_ID;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_CPU;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_PERIOD;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_STREAM_ID;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_RAW;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_BRANCH_STACK;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_REGS_USER;
	if (rand_bool())
		sample_type |= PERF_SAMPLE_STACK_USER;

	return sample_type;
}

static long long random_read_format(void)
{

	long long read_format = 0;

	if (rand_bool())
		return rand();

	if (rand_bool())
		read_format |= PERF_FORMAT_GROUP;
	if (rand_bool())
		read_format |= PERF_FORMAT_ID;
	if (rand_bool())
		read_format |= PERF_FORMAT_TOTAL_TIME_ENABLED;
	if (rand_bool())
		read_format |= PERF_FORMAT_TOTAL_TIME_RUNNING;

	return read_format;
}

static void create_mostly_valid_counting_event(struct perf_event_attr *attr)
{

	attr->type = random_event_type();

	attr->size = sizeof(struct perf_event_attr);
	/* FIXME: can typically be 64,72,80,96 depending on kernel */
	/* Other values will likely not create a valid event       */

	attr->config = random_event_config(attr->type);
	if (attr->type == PERF_TYPE_BREAKPOINT) {
		setup_breakpoints(attr);
	}
	attr->read_format = random_read_format();

	/* Boolean parameters */
	attr->disabled = rand_bool();
	attr->inherit = rand_bool();
	attr->pinned = rand_bool();
	attr->exclusive = rand_bool();
	attr->exclude_user = rand_bool();
	attr->exclude_kernel = rand_bool();
	attr->exclude_hv = rand_bool();
	attr->exclude_idle = rand_bool();
	attr->mmap = rand_bool();
	attr->comm = rand_bool();
	// freq not relevant
	attr->inherit_stat = rand_bool();
	attr->enable_on_exec = rand_bool();
	attr->task = rand_bool();
	attr->watermark = rand_bool();
	attr->precise_ip = rand() % 4;	// two bits
	attr->mmap_data = rand_bool();
	attr->sample_id_all = rand_bool();
	attr->exclude_host = rand_bool();
	attr->exclude_guest = rand_bool();
	attr->exclude_callchain_kernel = rand_bool();
	attr->exclude_callchain_user = rand_bool();

	attr->wakeup_events = rand();	// also wakeup_watermark

	//attr->config1 = rand64();
	//attr->config2 = rand64();
	// only valid with certain event combinations

	//attr->branch_sample_type = rand64();
	//attr->sample_regs_user = rand64();
	//attr->saple_stack_user = rand();

}

static void create_mostly_valid_sampling_event(struct perf_event_attr *attr)
{

	attr->type = random_event_type();
	attr->size = sizeof(struct perf_event_attr);
	attr->config = random_event_config(attr->type);
	if (attr->type == PERF_TYPE_BREAKPOINT) {
		setup_breakpoints(attr);
	}
	attr->sample_period = rand();	/* low values more likely to have "interesting" results */
	attr->sample_type = random_sample_type();
	attr->read_format = random_read_format();

	/* Boolean parameters */
	attr->disabled = rand_bool();
	attr->inherit = rand_bool();
	attr->pinned = rand_bool();
	attr->exclusive = rand_bool();
	attr->exclude_user = rand_bool();
	attr->exclude_kernel = rand_bool();
	attr->exclude_hv = rand_bool();
	attr->exclude_idle = rand_bool();
	attr->mmap = rand_bool();
	attr->comm = rand_bool();

	attr->inherit_stat = rand_bool();
	attr->enable_on_exec = rand_bool();
	attr->task = rand_bool();
	attr->watermark = rand_bool();
	attr->precise_ip = rand() % 4;	// two bits
	attr->mmap_data = rand_bool();
	attr->sample_id_all = rand_bool();
	attr->exclude_host = rand_bool();
	attr->exclude_guest = rand_bool();
	attr->exclude_callchain_kernel = rand_bool();
	attr->exclude_callchain_user = rand_bool();

	attr->wakeup_events = rand();	// also wakeup_watermark

	//attr->config1 = rand64();
	//attr->config2 = rand64();
	// only valid with certain event combinations

	//attr->branch_sample_type = rand64();
	//attr->sample_regs_user = rand64();
	//attr->saple_stack_user = rand();

}

static void create_random_event(struct perf_event_attr *attr)
{

	attr->type = random_event_type();
	attr->config = random_event_config(attr->type);
	setup_breakpoints(attr);

	switch (rand_bool()) {
	case 0:
		attr->size = sizeof(struct perf_event_attr);
		break;
	case 1:
		attr->size = get_len();
	default:
		break;
	}

	attr->sample_type = random_sample_type();
	attr->read_format = random_read_format();

	/* booleans */
	attr->exclude_user = rand_bool();
	attr->exclude_kernel = rand_bool();	/* doesn't require root unless paranoid set to 2 */
	attr->exclude_hv = rand_bool();
}

static void sanitise_perf_event_open(int childno)
{
	struct perf_event_attr *attr;
	unsigned long flags;
	pid_t pid;
	int group_fd;

	shm->a1[childno] = (unsigned long)page_rand;
	attr = (struct perf_event_attr *)shm->a1[childno];

	/* this makes sure we clear out the reserved fields. */
	memset(page_rand, 0, sizeof(struct perf_event_attr));

	/* cpu */
	/* requires ROOT to select CPU if paranoid level not 0 */
	/* -1 means all CPUs */
	//shm->a3[childno] = cpu;
	// the default get_cpu() is good enough here

	/* group_fd */
	/* should usually be -1 or another perf_event fd         */
	/* Anything but -1 unlikely to work unless the other pid */
	/* was properly set up to be a group master              */
	if (rand() % 2) {
		group_fd = -1;
	} else {
		group_fd = get_pid();
	}
	shm->a4[childno] = group_fd;

	/* flags */
	/* You almost never set these unless you're playing with cgroups */
	flags = 0;
	if (rand() % 2) {
		flags = rand64();
	} else {
		if (rand_bool())
			flags |= PERF_FLAG_FD_NO_GROUP;
		if (rand_bool())
			flags |= PERF_FLAG_FD_OUTPUT;
		if (rand_bool())
			flags |= PERF_FLAG_PID_CGROUP;
	}
	shm->a5[childno] = flags;

	/* pid */
	/* requires ROOT to select pid that doesn't belong to us */
	/* pid of 0 means current process */
	/* pid of -1 means all processes  */
	pid = 0;
	if (flags & PERF_FLAG_PID_CGROUP) {
		/* In theory in this case we should pass in */
		/* a file descriptor from /dev/cgroup       */
		pid = get_random_fd();
	} else if (rand() % 2) {
		pid = 0;
	} else {
		pid = get_pid();
	}
	shm->a2[childno] = pid;

	/* set up attr structure */
	switch (rand() % 3) {
	case 0:
		create_mostly_valid_counting_event(attr);
		break;
	case 1:
		create_mostly_valid_sampling_event(attr);
		break;
	default:
		create_random_event(attr);
		break;
	}
}

struct syscall syscall_perf_event_open = {
	.name = "perf_event_open",
	.num_args = 5,
	.arg1name = "attr_uptr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "pid",
	.arg2type = ARG_PID,
	.arg3name = "cpu",
	.arg3type = ARG_CPU,
	.arg4name = "group_fd",
	.arg4type = ARG_FD,
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = {
		.num = 3,
		.values = {
			PERF_FLAG_FD_NO_GROUP, PERF_FLAG_FD_OUTPUT, PERF_FLAG_PID_CGROUP
		},
	},
	.sanitise = sanitise_perf_event_open,
	.flags = NEED_ALARM,
};
