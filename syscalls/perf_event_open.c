/*
 * SYSCALL_DEFINE5(perf_event_open,
	 struct perf_event_attr __user *, attr_uptr,
	 pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
 */

#include <stdlib.h>
#include <linux/perf_event.h>

#include "trinity.h"
#include "sanitise.h"
#include "compat.h"
#include "shm.h"

static void sanitise_perf_event_open(int childno)
{
	struct perf_event_attr *hw;

	shm->a1[childno] = (unsigned long) page_rand;
	hw = (struct perf_event_attr *) shm->a1[childno];

	switch(rand() % 6) {
		case 0:	hw->type = PERF_TYPE_HARDWARE;
			switch(rand() % 9) {
				case 0: hw->config=PERF_COUNT_HW_CPU_CYCLES;
					break;
				case 1: hw->config=PERF_COUNT_HW_INSTRUCTIONS;
					break;
				case 2: hw->config=PERF_COUNT_HW_CACHE_REFERENCES;
					break;
				case 3: hw->config=PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
					break;
				case 4: hw->config=PERF_COUNT_HW_BRANCH_MISSES;
					break;
				case 5: hw->config=PERF_COUNT_HW_BUS_CYCLES;
					break;
				case 6: hw->config=PERF_COUNT_HW_STALLED_CYCLES_FRONTEND;
					break;
				case 7: hw->config=PERF_COUNT_HW_STALLED_CYCLES_BACKEND;
					break;
				case 8: hw->config = rand();
					break;
				default: break;
			}
			break;
		case 1: hw->type = PERF_TYPE_SOFTWARE;
			switch(rand() % 10) {
				case 0: hw->config=PERF_COUNT_SW_CPU_CLOCK;
					break;
				case 1: hw->config=PERF_COUNT_SW_TASK_CLOCK;
					break;
				case 2: hw->config=PERF_COUNT_SW_PAGE_FAULTS;
					break;
				case 3: hw->config=PERF_COUNT_SW_CONTEXT_SWITCHES;
					break;
				case 4: hw->config=PERF_COUNT_SW_CPU_MIGRATIONS;
					break;
				case 5: hw->config=PERF_COUNT_SW_PAGE_FAULTS_MIN;
					break;
				case 6: hw->config=PERF_COUNT_SW_PAGE_FAULTS_MAJ;
					break;
				case 7: hw->config=PERF_COUNT_SW_ALIGNMENT_FAULTS;
					break;
				case 8: hw->config=PERF_COUNT_SW_EMULATION_FAULTS;
					break;
				case 9: hw->config=rand();
				default: break;
			}
			break;
		case 2: hw->type = PERF_TYPE_TRACEPOINT;
			break;
		case 3: hw->type = PERF_TYPE_HW_CACHE;
			break;
		case 4: hw->type = PERF_TYPE_RAW;
			/* can be arbitrary 64-bit value */
			/* there are some constraints we can add */
			/* to make it more likely to be a valid event */
			hw->config = rand();

			break;
		case 5: hw->type = PERF_TYPE_BREAKPOINT;
			break;
		default: break;
	}

	switch(rand() % 2) {
		case 0: hw->size = sizeof(struct perf_event_attr);
			break;
		case 1: hw->size = rand();
		default: break;
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
		.values = { PERF_FLAG_FD_NO_GROUP, PERF_FLAG_FD_OUTPUT, PERF_FLAG_PID_CGROUP },
	},
	.sanitise = sanitise_perf_event_open,
	.flags = NEED_ALARM,
};
