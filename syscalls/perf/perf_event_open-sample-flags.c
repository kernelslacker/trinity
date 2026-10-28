/*
 * perf_event_open: sample_type / read_format / branch_sample_type bit pickers,
 * and the pickers of the register-sampling and the defer and AUX fields.
 *
 * The wide RAND_BOOL chains that OR up attr->sample_type, attr->read_format
 * and attr->branch_sample_type from the PERF_SAMPLE_* / PERF_FORMAT_* /
 * PERF_SAMPLE_BRANCH_* vocabularies.  Each picker returns rand64() directly
 * half the time, so the bit-flag validators see bits outside the vocabulary.
 */

#include "perf.h"
#include "perf_event.h"
#include "random.h"
#include "rnd.h"
#include "trinity.h"

#include "perf_event_open-internal.h"

long long random_sample_type(void)
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

long long random_read_format(void)
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

long long random_branch_sample_type(void)
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

/* Bits 0..11 name a register on every architecture trinity builds for:
 * AX..SS on x86, X0..X11 on arm64, r0..r11 on arm. */
#define PERF_REGS_PORTABLE	0xfff

/*
 * A sample_regs_user / sample_regs_intr mask.  perf_reg_validate() refuses an
 * empty one, and one that names a register the arch lacks, with -EINVAL:
 * x86-64 turns away DS..GS (bits 12..15), i386 R8..R15 (16..23), and arm64
 * and the 32-bit arches anything past their last register.  A mask drawn
 * from the portable low bits is accepted on all of them.  One draw in eight
 * probes the validator instead, with the empty mask, which is all an unset
 * field ever gave it, and with a 64-bit splat.
 */
long long random_sample_regs(void)
{
	switch (rnd_modulo_u32(16)) {
	case 0:
		return 0;
	case 1:
		return rand64();
	default:
		return 1 + rnd_modulo_u32(PERF_REGS_PORTABLE);
	}
}

/*
 * The VER10 sample_simd_* fields, drawn the way perf_simd_reg_validate() on
 * x86 takes them: a vector width of 2, 4 or 8 qwords (XMM, YMM, ZMM) with a
 * mask that holds every register of that width or none, and the same for the
 * 1-qword opmask.  The kernel reads them only for an attr whose sample_type
 * asks for REGS_USER or REGS_INTR, so one of the two is set, and the type is
 * cut to the bits the kernel defines and loses BRANCH_STACK and STACK_USER,
 * whose companion fields the builders fill at random and perf_copy_attr()
 * refuses.  Only x86_pmu_hw_config() asks for PERF_PMU_CAP_SIMD_REGS, so an
 * event on any other PMU gets as far as the sample path with these too.  The
 * size grows to VER10 with them: a kernel that predates it answers -E2BIG to
 * the tail.
 */
void random_simd_regs(struct perf_event_attr *attr)
{
	unsigned int width = rnd_modulo_u32(4);		/* none, XMM, YMM, ZMM */
	__u64 full = 0xffff;

	attr->sample_type &= (PERF_SAMPLE_MAX - 1) &
			     ~(PERF_SAMPLE_BRANCH_STACK | PERF_SAMPLE_STACK_USER);
	switch (rnd_modulo_u32(3)) {
	case 0:
		attr->sample_type |= PERF_SAMPLE_REGS_USER;
		break;
	case 1:
		attr->sample_type |= PERF_SAMPLE_REGS_INTR;
		break;
	default:
		attr->sample_type |= PERF_SAMPLE_REGS_USER | PERF_SAMPLE_REGS_INTR;
		break;
	}
	attr->sample_regs_user = random_sample_regs();
	attr->sample_regs_intr = random_sample_regs();

	attr->sample_simd_regs_enabled = ONE_IN(8) ? 1 + rnd_modulo_u32(0xffff) : 1;

	if (width != 0) {
		attr->sample_simd_vec_reg_qwords = 1 << width;
		/* ZMM names 32 registers, XMM and YMM 16 and take the 32 too. */
		if (width == 3 || RAND_BOOL())
			full = 0xffffffff;
		attr->sample_simd_vec_reg_intr = ONE_IN(4) ? 0 : full;
		attr->sample_simd_vec_reg_user = ONE_IN(4) ? 0 : full;
	}

	if (RAND_BOOL()) {
		attr->sample_simd_pred_reg_qwords = 1;
		attr->sample_simd_pred_reg_intr = ONE_IN(4) ? 0 : 0xff;
		attr->sample_simd_pred_reg_user = ONE_IN(4) ? 0 : 0xff;
	}

	attr->size = PERF_ATTR_SIZE_VER10;
}

/*
 * defer_callchain, defer_output and the aux_action bits, which perf_copy_attr()
 * checks for nothing but the reserved bits around them, drawn the way the rest
 * of the kernel takes them:
 *
 *  - defer_callchain is read only by perf_callchain(), for an event that takes
 *    a user callchain, so it goes on one that does.  defer_output makes an
 *    event a sink for the side-band PERF_RECORD_CALLCHAIN_DEFERRED records,
 *    which any event may be.
 *  - aux_pause and aux_resume are alternatives (perf_event_alloc() answers
 *    -EINVAL to both and -EOPNOTSUPP next to aux_output), and
 *    perf_get_aux_event() refuses either unless the event joins a group
 *    whose leader sits on a PMU that can pause, so they go on a group member
 *    and clear aux_output.
 *  - aux_start_paused is perf_event_alloc()'s -EOPNOTSUPP on a PMU that
 *    cannot pause, so it goes on an event of one that can.
 *
 * A kernel that predates the bits answers -EINVAL to each through its
 * reserved ones, so the unconditional ones are a minority draw.
 */
void random_defer_aux_flags(struct perf_event_attr *attr, int group_leader)
{
	if ((attr->sample_type & PERF_SAMPLE_CALLCHAIN) &&
	    !attr->exclude_callchain_user)
		attr->defer_callchain = RAND_BOOL();

	attr->defer_output = ONE_IN(8);

	if (!group_leader && ONE_IN(8)) {
		attr->aux_output = 0;
		if (RAND_BOOL())
			attr->aux_pause = 1;
		else
			attr->aux_resume = 1;
	}

	if (perf_pmu_aux_pausable(attr->type) && RAND_BOOL())
		attr->aux_start_paused = 1;
}
