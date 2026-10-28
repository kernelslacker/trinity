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
#include "utils-macros.h"		/* ARRAY_SIZE */
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

/* A rule broken by every draw would print NR_ATTRS lines; the first few say it. */
static void expect(bool ok, const char *what, unsigned long got)
{
	if (ok)
		return;
	if (failed++ < 10)
		fprintf(stderr, "perf attr: %s (got %lu)\n", what, got);
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

/* arch/x86/kernel/perf_regs.c: bitmap_full(&mask, nbits), the low nbits set. */
static bool low_bits_set(unsigned long long mask, unsigned int nbits)
{
	unsigned long long want = (1ULL << nbits) - 1;

	return (mask & want) == want;
}

/*
 * perf_simd_reg_validate() on x86: a mask needs a width, the width is 2, 4 or
 * 8 qwords for the vectors and 1 for the opmask, a mask names every register
 * of the width or none ("Only full-register sampling is allowed": the low 16
 * for XMM and YMM, the low 32 for ZMM, all 8 of k0..k7), and the dump a mask
 * asks for has to stay under U16_MAX / 2.
 */
static bool simd_regs_valid(unsigned int vec_qwords, unsigned long long vec_mask,
			    unsigned int pred_qwords, unsigned int pred_mask)
{
	if (!vec_qwords && !pred_qwords && (vec_mask || pred_mask))
		return false;

	if (vec_qwords) {
		if (vec_qwords != 2 && vec_qwords != 4 && vec_qwords != 8)
			return false;
		if (vec_mask & ~0xffffffffULL)
			return false;
		if (vec_mask && !low_bits_set(vec_mask, vec_qwords == 8 ? 32 : 16))
			return false;
	}

	if (pred_qwords) {
		if (pred_qwords != 1)
			return false;
		if (pred_mask & ~0xffU)
			return false;
		if (pred_mask && !low_bits_set(pred_mask, 8))
			return false;
	}

	return 32 + (__builtin_popcountll(vec_mask) * vec_qwords +
		     __builtin_popcount(pred_mask) * pred_qwords) * 8 < 0xffff / 2;
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
	unsigned long ver9 = 0, ver10 = 0, valid10 = 0, i;
	unsigned int b;

	for (i = 0; i < NR_ATTRS; i++) {
		bool tail_set = false;

		memset(buf, 0, sizeof(buf));
		attr->size = PERF_ATTR_SIZE_VER10;
		maybe_fill_perf_attr_body(attr, CSFU_BUCKET_EXACT, i & 1);

		for (b = PERF_ATTR_SIZE_VER9; b < PERF_ATTR_SIZE_VER10; b++)
			tail_set |= buf[b] != 0;

		if (tail_set) {
			ver10++;
			expect(attr->size == PERF_ATTR_SIZE_VER10,
			       "a drawn VER10 field is declared", attr->size);
			/* The sampling builder draws masks the kernel takes; only the
			 * random builder draws them whole at random. */
			valid10 += simd_regs_valid(attr->sample_simd_vec_reg_qwords,
						   attr->sample_simd_vec_reg_intr,
						   attr->sample_simd_pred_reg_qwords,
						   attr->sample_simd_pred_reg_intr) &&
				   (attr->sample_type &
				    (PERF_SAMPLE_REGS_USER | PERF_SAMPLE_REGS_INTR)) != 0;
		} else {
			ver9++;
			expect(attr->size == PERF_ATTR_SIZE_VER9,
			       "an empty VER10 tail is left undeclared", attr->size);
		}
	}

	expect(ver9 > NR_ATTRS / 2, "most attrs stay at VER9", ver9);
	expect(ver10 > NR_ATTRS / 32, "VER10 fields are drawn at all", ver10);
	expect(valid10 > ver10 / 4,
	       "the sampling builder draws VER10 fields the kernel takes", valid10);
}

/* perf_reg_validate(mask, true) on x86-64: a mask may be empty when SIMD is
 * sampled, but DS..GS are not registers there and the file ends at SSP. */
static bool regs_valid_simd(unsigned long long mask)
{
	return (mask & (0xfULL << 12)) == 0 && (mask >> 41) == 0;
}

/*
 * What perf_copy_attr() asks of an attr that carries the SIMD fields, drawn
 * on top of a sample_type the sampling builder has already made.
 */
static void check_simd_regs(void)
{
	unsigned long width[9] = { 0 }, pred = 0, empty = 0, full = 0;
	unsigned long regs = 0, regs_ok = 0, i;
	struct perf_event_attr attr;

	for (i = 0; i < NR_ATTRS; i++) {
		memset(&attr, 0, sizeof(attr));
		attr.sample_type = random_sample_type();
		random_simd_regs(&attr);

		expect(attr.size == PERF_ATTR_SIZE_VER10,
		       "the SIMD fields are declared", attr.size);
		expect((attr.sample_type & ~(PERF_SAMPLE_MAX - 1ULL)) == 0,
		       "sample_type keeps to the bits the kernel defines",
		       attr.sample_type);
		expect((attr.sample_type &
			(PERF_SAMPLE_REGS_USER | PERF_SAMPLE_REGS_INTR)) != 0,
		       "a register dump asks for the SIMD fields to be read",
		       attr.sample_type);
		expect((attr.sample_type &
			(PERF_SAMPLE_BRANCH_STACK | PERF_SAMPLE_STACK_USER)) == 0,
		       "no stack or branch field is left to refuse the attr",
		       attr.sample_type);
		expect(attr.sample_simd_regs_enabled != 0,
		       "the SIMD switch is on", 0);
		expect(attr.__reserved_4 == 0, "the reserved word is zero", 0);

		expect(simd_regs_valid(attr.sample_simd_vec_reg_qwords,
				       attr.sample_simd_vec_reg_intr,
				       attr.sample_simd_pred_reg_qwords,
				       attr.sample_simd_pred_reg_intr),
		       "the interrupt masks pass perf_simd_reg_validate()", i);
		expect(simd_regs_valid(attr.sample_simd_vec_reg_qwords,
				       attr.sample_simd_vec_reg_user,
				       attr.sample_simd_pred_reg_qwords,
				       attr.sample_simd_pred_reg_user),
		       "the user masks pass perf_simd_reg_validate()", i);

		if (attr.sample_simd_vec_reg_qwords < ARRAY_SIZE(width))
			width[attr.sample_simd_vec_reg_qwords]++;
		pred += attr.sample_simd_pred_reg_qwords;
		empty += attr.sample_simd_vec_reg_intr == 0;
		full += attr.sample_simd_vec_reg_intr != 0;

		if (attr.sample_type & PERF_SAMPLE_REGS_USER) {
			regs++;
			regs_ok += regs_valid_simd(attr.sample_regs_user);
		}
		if (attr.sample_type & PERF_SAMPLE_REGS_INTR) {
			regs++;
			regs_ok += regs_valid_simd(attr.sample_regs_intr);
		}
	}

	expect(width[0] > NR_ATTRS / 8 && width[2] > NR_ATTRS / 8 &&
	       width[4] > NR_ATTRS / 8 && width[8] > NR_ATTRS / 8,
	       "every vector width is drawn, and none", width[2]);
	expect(pred > NR_ATTRS / 4, "the opmask is drawn", pred);
	expect(empty > NR_ATTRS / 16 && full > NR_ATTRS / 16,
	       "empty and full vector masks are both drawn", empty);
	expect(regs_ok * 4 >= regs * 3,
	       "three in four register masks are ones x86 takes", regs_ok);
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
	check_simd_regs();
	check_catalog();

	if (failed != 0)
		BUG("perf attr: a check failed");
}
