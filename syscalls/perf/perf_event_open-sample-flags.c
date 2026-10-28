/*
 * perf_event_open: sample_type / read_format / branch_sample_type bit pickers,
 * and the sample_regs_* mask picker.
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
