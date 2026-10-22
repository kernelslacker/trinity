/*
 * Self-check for the struct-field scans cmp_hints_collect() can drive
 * (cmp_hints/field.c, cmp_hints/hyp-len-correlated.c).  They are gated
 * off: a collect must not resolve struct args, walk alloc_track or
 * record anything, and must still hand every record to the hint pool.
 */

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "child.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "debug.h"		/* BUG */
#include "deferred-free.h"	/* alloc_track_lookup_size */
#include "kcov.h"
#include "locks.h"
#include "signals.h"
#include "struct_catalog.h"
#include "syscall.h"
#include "utils-mem.h"		/* range_readable_user */

/* Owned by cmp_hints.c, kcov/ and the fault handler in production. */
struct cmp_hints_shared *cmp_hints_shm;
struct kcov_shared *kcov_shm;
bool cmp_hints_strip[2][MAX_NR_SYSCALL];
sigjmp_buf cmp_field_recover;
volatile sig_atomic_t cmp_field_read_active;

extern struct childdata *fake_this_child;	/* fake_shm.c */

#define SCAN_NR		7U
#define SCAN_RECORDS	24U
#define SCAN_LEN	0x40U
#define SCAN_VAL	0x1234U
/* KCOV_CMP_CONST with a 4-byte operand (size index 2 in bits 1..2). */
#define SCAN_CMP_TYPE	((2UL << 1) | 1UL)

static const struct struct_field scan_fields[] = {
	{ .name = "len", .offset = 0, .size = 4, .tag = FT_LEN_BYTES },
	{ .name = "val", .offset = 4, .size = 4, .tag = FT_RAW },
};

static const struct struct_desc scan_desc = {
	.name = "cmp_field_scan",
	.struct_size = 8,
	.fields = scan_fields,
	.num_fields = 2,
};

static struct syscallentry scan_entry = {
	.name = "cmp_field_scan",
	.num_args = 1,
	.argtype = { [0] = ARG_STRUCT_PTR_IN },
};

static uint32_t scan_buf[2] __attribute__((aligned(8))) = {
	SCAN_LEN, SCAN_VAL,
};

static unsigned long trace_buf[1 + SCAN_RECORDS * 4];

static bool scan_armed;
static unsigned int alloc_track_lookups;
static unsigned int desc_lookups;
static struct cmp_hints_pending flushed[SCAN_RECORDS];
static unsigned int nr_flushed;

/* The struct-field scans reach alloc_track only through this lookup:
 * count it, and answer for scan_buf alone while a collect runs. */
size_t __real_alloc_track_lookup_size(void *ptr);
size_t __wrap_alloc_track_lookup_size(void *ptr);
size_t __wrap_alloc_track_lookup_size(void *ptr)
{
	if (!scan_armed)
		return __real_alloc_track_lookup_size(ptr);
	alloc_track_lookups++;
	return ptr == scan_buf ? sizeof(scan_buf) : 0;
}

const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx,
					    bool do32bit,
					    struct syscallrecord *rec)
{
	(void) rec;
	desc_lookups++;
	if (nr == SCAN_NR && arg_idx == 1 && !do32bit)
		return &scan_desc;
	return NULL;
}

bool range_readable_user(const void *addr, size_t len)
{
	(void) addr;
	(void) len;
	return true;
}

unsigned long kcov_canon_cmp_ip(unsigned long ip)
{
	return ip;
}

void lock(lock_t *lk)
{
	(void) lk;
}

void unlock(lock_t *lk)
{
	(void) lk;
}

void pool_lock(struct cmp_hint_pool *pool)
{
	(void) pool;
}

void pool_unlock(struct cmp_hint_pool *pool)
{
	(void) pool;
}

bool cmp_hints_pool_corrupted(struct cmp_hint_pool *pool,
			      unsigned int observed_count)
{
	(void) pool;
	(void) observed_count;
	return false;
}

/* Every record is new to the bloom, so every record reaches the pool. */
bool cmp_hints_bloom_check_and_set(struct cmp_hints_bloom *b,
				   unsigned long ip, unsigned long val,
				   unsigned int size)
{
	(void) b;
	(void) ip;
	(void) val;
	(void) size;
	return false;
}

unsigned int cmp_hints_flush_pending(struct cmp_hint_pool *pool,
				     unsigned int nr, bool do32,
				     const struct cmp_hints_pending *batch,
				     unsigned int n)
{
	(void) pool;
	(void) nr;
	(void) do32;
	if (n > SCAN_RECORDS - nr_flushed)
		BUG("cmp field scan: more records flushed than collected");
	memcpy(&flushed[nr_flushed], batch, n * sizeof(*batch));
	nr_flushed += n;
	return n;
}

static unsigned long scan_arg1(unsigned int i)
{
	return 0x1000UL + i;
}

/* Thirds: the "val" field, the "len" field, neither. */
static unsigned long scan_arg2(unsigned int i)
{
	switch (i % 3) {
	case 0:
		return SCAN_VAL;
	case 1:
		return SCAN_LEN;
	default:
		return 0xdeadUL;
	}
}

static unsigned long scan_ip(unsigned int i)
{
	return 0x10000UL + i * 16UL;
}

/* One cmp_hints_collect() call for a syscall whose only arg points at
 * scan_buf, over SCAN_RECORDS 4-byte KCOV_CMP_CONST records. */
static void run_collect(void)
{
	struct childdata *child;
	unsigned int i;

	kcov_shm = calloc(1, sizeof(*kcov_shm));
	cmp_hints_shm = calloc(1, sizeof(*cmp_hints_shm));
	child = calloc(1, sizeof(*child));
	if (kcov_shm == NULL || cmp_hints_shm == NULL || child == NULL)
		BUG("cmp field scan: calloc failed");

	child->syscall.entry = &scan_entry;
	child->syscall.dispatch_args[0] = (unsigned long) scan_buf;
	child->syscall.dispatch_args_valid = true;

	trace_buf[0] = SCAN_RECORDS;
	for (i = 0; i < SCAN_RECORDS; i++) {
		unsigned long *rec = &trace_buf[1 + i * 4];

		rec[0] = SCAN_CMP_TYPE;
		rec[1] = scan_arg1(i);
		rec[2] = scan_arg2(i);
		rec[3] = scan_ip(i);
	}

	alloc_track_lookups = 0;
	desc_lookups = 0;
	nr_flushed = 0;
	fake_this_child = child;
	scan_armed = true;

	cmp_hints_collect(trace_buf, SCAN_NR, false);

	scan_armed = false;
	fake_this_child = NULL;
	free(child);
}

static void free_shm(void)
{
	free(cmp_hints_shm);
	free(kcov_shm);
	cmp_hints_shm = NULL;
	kcov_shm = NULL;
}

/* The live path: every record, in order, went to the hint pool. */
static void check_flushed(void)
{
	unsigned int i;

	if (nr_flushed != SCAN_RECORDS)
		BUG("cmp field scan: the hint pool lost records");
	for (i = 0; i < SCAN_RECORDS; i++) {
		if (flushed[i].ip != scan_ip(i) ||
		    flushed[i].val != scan_arg1(i) ||
		    flushed[i].size != 4)
			BUG("cmp field scan: the hint pool got the wrong records");
	}
}

static const struct cmp_hypothesis *find_len_correlated(void)
{
	const struct cmp_hyp_pool *pool = &cmp_hints_shm->hyp_pools[SCAN_NR][0];
	unsigned int i;

	for (i = 0; i < pool->count && i < CMP_HYP_PER_SYSCALL; i++) {
		if (pool->entries[i].kind == CMP_HYP_LEN_CORRELATED)
			return &pool->entries[i];
	}
	return NULL;
}

static const struct cmp_field_pool *find_field_pool(void)
{
	unsigned int i;

	for (i = 0; i < CMP_FIELD_POOL_BUCKETS; i++) {
		if (cmp_hints_shm->field_pools[i].key.desc == &scan_desc)
			return &cmp_hints_shm->field_pools[i];
	}
	return NULL;
}

/* scan_buf is tracked and a third of the records match each of its
 * fields, so an enabled scan would resolve it and record. */
static void struct_field_scans_gated_off(void)
{
	const struct kcov_cmp_field_attr *fa;

	run_collect();
	fa = &kcov_shm->cmp_field_attr;

	if (alloc_track_lookups != 0 || desc_lookups != 0)
		BUG("cmp field scan: a gated-off scan resolved struct args");
	check_flushed();

	if (fa->cmp_field_attribution_scanned != 0 ||
	    fa->cmp_field_attribution_found != 0 ||
	    fa->cmp_field_attribution_arg_skipped_short_alloc != 0 ||
	    find_field_pool() != NULL)
		BUG("cmp field scan: a gated-off field attribution recorded");
	if (kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_would_fire != 0 ||
	    kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_bad_desc != 0 ||
	    find_len_correlated() != NULL)
		BUG("cmp field scan: a gated-off length correlation recorded");

	free_shm();
}

void cmp_field_scan_self_check(void);
void cmp_field_scan_self_check(void)
{
	struct_field_scans_gated_off();
}
