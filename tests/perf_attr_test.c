/*
 * Self-check for the perf_event_attr body builders: fills attrs through
 * maybe_fill_perf_attr_body(), the entry point the sanitiser reaches, and
 * holds them to what perf_copy_attr() and perf_reg_validate() in the kernel
 * ask of one.  The kernel half of each rule is cited where the check is.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "csfu.h"
#include "debug.h"		/* BUG */
#include "perf_event.h"
#include "struct_catalog-internal.h"	/* perf_event_attr_fields */
#include "syscalls/perf/perf_event_open-internal.h"

void perf_attr_self_check(void);

/* Attrs per case: enough that a rule the builders meet in one draw in eight
 * is seen hundreds of times. */
#define NR_ATTRS	20000

/* The registers every architecture trinity builds for names: perf_reg_validate()
 * refuses a mask outside the arch's register file, and bits 0..11 are inside
 * every one (AX..SS on x86, X0..X11 on arm64, r0..r11 on arm). */
#define PORTABLE_REGS	0xfffULL

static unsigned int failed;

static void expect(bool ok, const char *what, unsigned long got)
{
	if (ok)
		return;
	fprintf(stderr, "perf attr: %s (got %lu)\n", what, got);
	failed++;
}

/*
 * sample_regs_intr is read only when sample_type asks for PERF_SAMPLE_REGS_INTR,
 * and then perf_reg_validate() refuses an empty mask, or one the arch's
 * register file does not hold, with -EINVAL: x86 (arch/x86/kernel/perf_regs.c)
 * and arm64 (arch/arm64/kernel/perf_regs.c) both start with !mask.  An attr
 * that draws the sample type and leaves the mask at zero never gets past it.
 */
static void check_regs_intr(void)
{
	struct perf_event_attr attr;
	unsigned long drawn = 0, accepted = 0, i;

	for (i = 0; i < NR_ATTRS; i++) {
		memset(&attr, 0, sizeof(attr));
		maybe_fill_perf_attr_body(&attr, CSFU_BUCKET_EXACT, i & 1);
		if (!(attr.sample_type & PERF_SAMPLE_REGS_INTR))
			continue;
		drawn++;
		if (attr.sample_regs_intr != 0 &&
		    (attr.sample_regs_intr & ~PORTABLE_REGS) == 0)
			accepted++;
	}

	expect(drawn > NR_ATTRS / 16, "REGS_INTR is drawn at all", drawn);
	expect(accepted * 4 >= drawn * 3,
	       "three in four REGS_INTR attrs carry a mask every arch accepts",
	       accepted);
}

/*
 * perf_event_open() has no size argument: the kernel takes attr->size, which
 * the sanitiser plants from the csfu bucket, and for the EXACT bucket that is
 * sizeof(struct perf_event_attr), VER10 now.  A kernel that predates the VER10
 * tail takes a longer size only when the extra bytes are zero, so the body
 * has to declare the size it fills: VER9 while the tail is empty, VER10 once
 * a builder has drawn into it.
 */
static void check_declared_size(void)
{
	unsigned char buf[PERF_ATTR_SIZE_VER10 + 32];
	struct perf_event_attr *attr = (struct perf_event_attr *) buf;
	unsigned long ver9 = 0, i;
	unsigned int b;

	for (i = 0; i < NR_ATTRS; i++) {
		bool tail_set = false;

		memset(buf, 0, sizeof(buf));
		attr->size = PERF_ATTR_SIZE_VER10;
		maybe_fill_perf_attr_body(attr, CSFU_BUCKET_EXACT, i & 1);

		for (b = PERF_ATTR_SIZE_VER9; b < PERF_ATTR_SIZE_VER10; b++)
			tail_set |= buf[b] != 0;

		if (tail_set) {
			expect(attr->size == PERF_ATTR_SIZE_VER10,
			       "a drawn VER10 field is declared", attr->size);
		} else {
			ver9++;
			expect(attr->size == PERF_ATTR_SIZE_VER9,
			       "an empty VER10 tail is left undeclared", attr->size);
		}
	}

	expect(ver9 > NR_ATTRS / 2, "most attrs stay at VER9", ver9);
}

/*
 * The struct_field rows that describe perf_event_attr stand for the whole
 * struct: a row that is not filled in (PERF_EVENT_ATTR_FIELDS_N ran past the
 * initialisers) has no name and no width, and rows that stop short of
 * sizeof(struct perf_event_attr) are a header that grew without the table.
 */
static void check_catalog(void)
{
	unsigned long end = 0, i;

	for (i = 0; i < PERF_EVENT_ATTR_FIELDS_N; i++) {
		const struct struct_field *f = &perf_event_attr_fields[i];

		expect(f->name != NULL && f->size != 0, "a catalog row is filled", i);
		expect(f->offset <= sizeof(struct perf_event_attr) &&
		       f->size <= sizeof(struct perf_event_attr) - f->offset,
		       "a catalog row lies inside the struct", i);
		if (f->offset + f->size > end)
			end = f->offset + f->size;
	}

	expect(end == sizeof(struct perf_event_attr),
	       "the catalog rows reach the end of the struct", end);
}

void perf_attr_self_check(void)
{
	check_regs_intr();
	check_declared_size();
	check_catalog();

	if (failed != 0)
		BUG("perf attr: a check failed");
}
