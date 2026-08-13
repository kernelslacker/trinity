/*
 * struct_field_bounds_test.c -- unsigned-overflow guard for the
 * struct-field sanitiser bounds predicate.
 *
 * Defect (review C2): every bounds check in scrub_field_array() and
 * struct_fill_passes() used the form:
 *
 *     if (f->offset + f->size > size) continue;
 *
 * Both members are `unsigned int`; `size` is `unsigned int`.  When
 * f->offset + f->size exceeds UINT_MAX the result wraps modulo 2^32
 * *before* the comparison.  A pair like {.offset = UINT_MAX-4,
 * .size = 8} sums to 3, which is less than any realistic buffer size,
 * so the guard is bypassed and the subsequent memcpy walks 4 GB past
 * the buffer end.
 *
 * Fix: replace with the non-wrapping two-disjunct form:
 *
 *     if (f->offset > size || f->size > size - f->offset) continue;
 *
 * The first disjunct establishes f->offset <= size before the
 * subtraction, so `size - f->offset` cannot underflow.
 *
 * Test procedure:
 *   - Set up a 16-byte buffer filled with a sentinel byte (0xAA).
 *   - Build a single-field array: {.tag = FT_FLAGS, .offset = UINT_MAX-4,
 *     .size = 8, .u.flags.mask = 0xFF}.
 *   - Call struct_fill_passes(buf, 16, fields, 1, NULL).
 *   - With the *old* predicate the sum wraps to 3, the guard is not
 *     taken, fill_field_flags() writes 8 bytes to buf + (UINT_MAX-4),
 *     and the process crashes with SIGSEGV (test FAILS before fix).
 *   - With the *fixed* predicate the first disjunct fires (UINT_MAX-4 > 16),
 *     the field is skipped, the buffer is untouched (test PASSES after fix).
 *
 * rec is passed as NULL; struct_fill_passes does not dereference rec
 * in Pass 1 for a scalar FT_FLAGS field, so this is safe.
 */

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "args-internal.h"
#include "struct_catalog.h"

/* Entry point declared in test_main.c. */
void struct_field_bounds_self_check(void);

void struct_field_bounds_self_check(void)
{
	/*
	 * 1. Verify the arithmetic: UINT_MAX-4 + 8 wraps to 3 in
	 *    unsigned int, which would pass the old guard against any
	 *    size >= 3.  Document this so the test is self-annotating
	 *    without needing a comment outside the function.
	 */
	unsigned int bad_sum = (unsigned int)(UINT_MAX - 4) + (unsigned int)8;

	assert(bad_sum == 3u); /* wraps: the old predicate is blind to this */

	/*
	 * 2. The *fixed* predicate must catch the same pair.
	 */
	unsigned int off = UINT_MAX - 4;
	unsigned int fsz = 8;
	unsigned int bufsz = 16;
	int skipped_new = (off > bufsz || fsz > bufsz - off);

	assert(skipped_new); /* fixed predicate catches the wrapping case */

	/*
	 * 3. Call the real struct_fill_passes() with the wrapping field.
	 *
	 *    Before the fix: fill_field_flags() is reached and performs
	 *    memcpy(buf + (UINT_MAX-4), …, 8), which addresses a location
	 *    ~4 GiB beyond buf.  On a 64-bit kernel this maps to
	 *    unmapped memory and raises SIGSEGV -- the test binary
	 *    terminates non-zero (FAIL).
	 *
	 *    After the fix: the first disjunct (UINT_MAX-4 > 16) is
	 *    TRUE, the loop takes `continue`, fill_field_flags() is
	 *    never called, and buf is untouched (PASS).
	 */
	static const struct struct_field fields[1] = {{
		.name          = "wrap_probe",
		.offset        = UINT_MAX - 4,
		.size          = 8,
		.tag           = FT_FLAGS,
		.mutate_weight = 0,
		.u.flags.mask  = 0xFF,
	}};

	unsigned char buf[16];

	memset(buf, 0xAA, sizeof(buf));

	/* NULL rec: struct_fill_passes does not touch rec for FT_FLAGS
	 * in Pass 1 or for a field that is continued before the tag
	 * switch in Passes 2 and 3. */
	struct_fill_passes(buf, sizeof(buf), fields, 1, NULL);

	/* Buffer must be untouched -- every byte still 0xAA. */
	unsigned char expected[16];

	memset(expected, 0xAA, sizeof(expected));
	assert(memcmp(buf, expected, sizeof(buf)) == 0);

	printf("    struct_field_bounds: predicate arithmetic OK, "
	       "struct_fill_passes skipped wrapping field OK\n");
}
