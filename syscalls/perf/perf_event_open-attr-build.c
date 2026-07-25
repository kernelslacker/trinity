/*
 * perf_event_open: perf_event_attr body builders.
 *
 * Split out of syscalls/perf/perf_event_open.c so the four
 * create_mostly_valid_* / create_random_event body-fill routines and
 * the maybe_fill_perf_attr_body dispatcher live away from the sanitise
 * glue and the syscall descriptor.  Each builder composes the shared
 * per-type tuple picker (pick_perf_tuple) or the legacy independent
 * random_event_type / random_event_config fallback with the sample /
 * read-format / branch-sample pickers and the breakpoint-union helper
 * to shape one variant of a valid-ish perf_event_attr.
 *
 * maybe_fill_perf_attr_body is the sole caller of the four builders --
 * only it is externalised via the internal header; the individual
 * create_* builders stay file-static.
 */

#include "csfu.h"
#include "perf.h"
#include "perf_event.h"
#include "random.h"
#include "rnd.h"
#include "trinity.h"

#include "perf_event_open-internal.h"

#include "kernel/time.h"

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

void maybe_fill_perf_attr_body(struct perf_event_attr *attr,
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
