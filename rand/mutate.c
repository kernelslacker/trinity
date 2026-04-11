/*
 * Value mutation strategies for kernel argument fuzzing.
 *
 * These functions perturb existing values in ways that target common
 * kernel bug classes: sign-extension across width boundaries, alignment
 * assumptions, endianness mismatches, and bitwise negation.  The
 * mutations are domain-specific to how the kernel handles integers
 * internally (casting between u8/u16/u32/u64, page alignment, etc.)
 * rather than generic arithmetic perturbation.
 */
#include <limits.h>
#include <stdlib.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"

/*
 * Truncate to a random narrower integer width, preserving only the low
 * 8, 16, or 32 bits.  Kernel code frequently casts between integer
 * widths; passing a value that looks sane at 64 bits but has unexpected
 * bits set after truncation triggers type confusion bugs.
 */
static unsigned long mutate_truncate(unsigned long val)
{
	switch (rand() % 3) {
	case 0: return val & 0xff;
	case 1: return val & 0xffff;
	case 2: return val & 0xffffffff;
	}
	return val;
}

/*
 * Set the sign bit at a random width boundary (bit 7, 15, or 31) to
 * probe sign-extension bugs.  When the kernel narrows a u64 to a
 * signed i8/i16/i32, having the high bit set turns a positive value
 * negative, which often triggers unexpected codepaths.
 */
static unsigned long mutate_sign_extend(unsigned long val)
{
	switch (rand() % 3) {
	case 0: return val | 0x80;
	case 1: return val | 0x8000;
	case 2: return val | 0x80000000UL;
	}
	return val;
}

/*
 * Perturb alignment.  Kernel code frequently assumes that sizes and
 * addresses are page-aligned, cacheline-aligned, or power-of-2 aligned.
 * This either snaps a value to a nearby alignment boundary (potentially
 * triggering off-by-one when the kernel adjusts) or deliberately
 * misaligns it.
 */
static unsigned long mutate_alignment(unsigned long val)
{
	switch (rand() % 4) {
	case 0:
		/* Align down to page boundary */
		return val & ~(page_size - 1);
	case 1:
		/* One byte past a page boundary (first byte of next page) */
		return (val | (page_size - 1)) + 1;
	case 2:
		/* Align to cacheline (64 bytes) */
		return val & ~63UL;
	case 3:
		/* Misalign: set one of the low 3 bits */
		return val | (1UL << (rand() % 3));
	}
	return val;
}

/*
 * Zero-extend or sign-extend a narrow slice of val to 64 bits.
 *
 * Zero-extension produces values like 0x000000000000FFFF; sign-extension
 * produces values like 0xFFFFFFFFFFFF8000.  Both patterns exercise kernel
 * code that reads a 64-bit syscall argument and then casts it to a narrow
 * signed type and back — a common source of sign-extension bugs.
 */
static unsigned long mutate_cross_width(unsigned long val)
{
	switch (rand() % 6) {
	case 0: return (unsigned long)(unsigned char) val;		/* zero-extend 8→64 */
	case 1: return (unsigned long)(unsigned short) val;		/* zero-extend 16→64 */
	case 2: return (unsigned long)(unsigned int) val;		/* zero-extend 32→64 */
	case 3: return (unsigned long)(signed long)(signed char) val;	/* sign-extend 8→64 */
	case 4: return (unsigned long)(signed long)(short) val;		/* sign-extend 16→64 */
	case 5: return (unsigned long)(signed long)(int) val;		/* sign-extend 32→64 */
	}
	return val;
}

/*
 * Apply a random mutation to an existing value.
 *
 * Strategies target kernel-specific bug classes:
 *   truncate      -- width narrowing (u64 -> u8/u16/u32)
 *   sign extend   -- set sign bit at a width boundary
 *   alignment     -- page/cacheline alignment perturbation
 *   negate        -- sign confusion (positive <-> negative)
 *   byte swap     -- catches endianness assumptions
 *   single-bit    -- flip one random bit (flag toggling)
 *   arith delta   -- add/subtract small value (off-by-one, overflow)
 *   cross-width   -- zero/sign extend narrow value to 64 bits
 */
unsigned long mutate_value(unsigned long val)
{
	switch (rand() % 8) {
	case 0:
		return mutate_truncate(val);
	case 1:
		return mutate_sign_extend(val);
	case 2:
		return mutate_alignment(val);
	case 3:
		/* Bitwise negate -- sign confusion */
		return ~val;
	case 4:
		/* Byte swap (32-bit or 64-bit) */
		if (RAND_BOOL()) {
			unsigned int lo = (unsigned int) val;
			lo = __builtin_bswap32(lo);
			return (val & ~0xffffffffUL) | lo;
		}
		return __builtin_bswap64(val);
	case 5:
		/* Single-bit flip -- toggles one flag/permission bit */
		return val ^ (1UL << (rand() % WORD_BIT));
	case 6: {
		/* Arithmetic delta +/- 1..128 */
		unsigned long delta = (rand() % 128) + 1;
		if (RAND_BOOL())
			return val + delta;
		return val - delta;
	}
	case 7:
		return mutate_cross_width(val);
	}
	return val;
}

/*
 * Shift a flag value left or right by one bit position to probe for
 * adjacent undocumented flags.  Kernel flag fields often have gaps or
 * internal-only bits next to the documented ones.
 */
unsigned long shift_flag_bit(unsigned long flag)
{
	if (!flag)
		return 1;

	if (RAND_BOOL())
		return flag << 1;

	return flag >> 1;
}
