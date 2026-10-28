/*
 * Unsigned-overflow guard for the struct-field bounds predicate in
 * scrub_field_array() and struct_fill_passes(): a field {offset = UINT_MAX-4,
 * size = 8} wraps offset + size to 3, so a sum-then-compare check passes it
 * and the fill writes 4 GB past the buffer.  The predicate must be the
 * non-wrapping `offset > size || f->size > size - f->offset`.
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "args-internal.h"
#include "debug.h"		/* BUG_ON */
#include "struct_catalog.h"

/* Entry point declared in test_main.c. */
void struct_field_bounds_self_check(void);

void struct_field_bounds_self_check(void)
{
	/*
	 * 1. Verify the arithmetic: UINT_MAX-4 + 8 wraps to 3 in
	 *    unsigned int, which passes a guard of the form
	 *    `offset + size > bufsz` for any bufsz >= 3.  Document this so
	 *    the test is self-annotating without needing a comment outside
	 *    the function.
	 */
	unsigned int bad_sum = (unsigned int)(UINT_MAX - 4) + (unsigned int)8;

	BUG_ON(bad_sum != 3u); /* wraps: a summing predicate is blind to this */

	/*
	 * 2. The non-wrapping predicate must catch the same pair.
	 */
	unsigned int off = UINT_MAX - 4;
	unsigned int fsz = 8;
	unsigned int bufsz = 16;
	int skipped_new = (off > bufsz || fsz > bufsz - off);

	BUG_ON(!skipped_new); /* the two-disjunct predicate catches the wrap */

	/*
	 * 3. Call the real struct_fill_passes() with the wrapping field.
	 *
	 *    Without the bound, fill_field_flags() is reached and performs
	 *    memcpy(buf + (UINT_MAX-4), …, 8), which addresses a location
	 *    ~4 GiB beyond buf.  On a 64-bit kernel this maps to
	 *    unmapped memory and raises SIGSEGV -- the test binary
	 *    terminates non-zero (FAIL).
	 *
	 *    With it, the first disjunct (UINT_MAX-4 > 16) is TRUE, the
	 *    loop takes `continue`, fill_field_flags() is never called,
	 *    and buf is untouched (PASS).
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
	BUG_ON(memcmp(buf, expected, sizeof(buf)) != 0);

	printf("    struct_field_bounds: predicate arithmetic OK, "
	       "struct_fill_passes skipped wrapping field OK\n");
}
