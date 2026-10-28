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

void perf_attr_self_check(void)
{
	check_regs_intr();

	if (failed != 0)
		BUG("perf attr: a check failed");
}
