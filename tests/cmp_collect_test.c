/*
 * Self-check for cmp_hints_collect(): every KCOV_CMP_CONST record it
 * keeps must reach the hint pool, in trace order, and the RedQueen field
 * scan pins a timespec field only for a call that reads the native
 * layout.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "debug.h"		/* BUG */
#include "kcov.h"
#include "locks.h"
#include "syscall.h"
#include "utils-mem.h"		/* range_readable_user */

/* Owned by cmp_hints.c and kcov/ in production. */
struct cmp_hints_shared *cmp_hints_shm;
struct kcov_shared *kcov_shm;
bool cmp_hints_strip[2][MAX_NR_SYSCALL];

extern struct childdata *fake_this_child;	/* fake_shm.c */

#define COLLECT_NR	7U
#define COLLECT_RECORDS	24U
/* KCOV_CMP_CONST with a 4-byte operand (size index 2 in bits 1..2). */
#define COLLECT_CMP_TYPE	((2UL << 1) | 1UL)

static unsigned long trace_buf[1 + COLLECT_RECORDS * 4];

static struct cmp_hints_pending flushed[COLLECT_RECORDS];
static unsigned int nr_flushed;

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
	if (n > COLLECT_RECORDS - nr_flushed)
		BUG("cmp collect: more records flushed than collected");
	memcpy(&flushed[nr_flushed], batch, n * sizeof(*batch));
	nr_flushed += n;
	return n;
}

static unsigned long collect_arg1(unsigned int i)
{
	return 0x1000UL + i;
}

static unsigned long collect_ip(unsigned int i)
{
	return 0x10000UL + i * 16UL;
}

/* One cmp_hints_collect() call over COLLECT_RECORDS 4-byte
 * KCOV_CMP_CONST records. */
static void run_collect(void)
{
	struct childdata *child;
	unsigned int i;

	kcov_shm = calloc(1, sizeof(*kcov_shm));
	cmp_hints_shm = calloc(1, sizeof(*cmp_hints_shm));
	child = calloc(1, sizeof(*child));
	if (kcov_shm == NULL || cmp_hints_shm == NULL || child == NULL)
		BUG("cmp collect: calloc failed");

	trace_buf[0] = COLLECT_RECORDS;
	for (i = 0; i < COLLECT_RECORDS; i++) {
		unsigned long *rec = &trace_buf[1 + i * 4];

		rec[0] = COLLECT_CMP_TYPE;
		rec[1] = collect_arg1(i);
		rec[2] = 0xdeadUL;
		rec[3] = collect_ip(i);
	}

	nr_flushed = 0;
	fake_this_child = child;

	cmp_hints_collect(trace_buf, COLLECT_NR, false);

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

/* Every record, in order, went to the hint pool. */
static void check_flushed(void)
{
	unsigned int i;

	if (nr_flushed != COLLECT_RECORDS)
		BUG("cmp collect: the hint pool lost records");
	for (i = 0; i < COLLECT_RECORDS; i++) {
		if (flushed[i].ip != collect_ip(i) ||
		    flushed[i].val != collect_arg1(i) ||
		    flushed[i].size != 4)
			BUG("cmp collect: the hint pool got the wrong records");
	}
}

/* clock_nanosleep on i386 and x86_64. */
#define FIELD_NR_TIME32		267U
#define FIELD_NR_NATIVE		230U
/* KCOV_CMP_CONST with an 8-byte operand, so only the exact scalar pass
 * runs before the field scan. */
#define FIELD_CMP_TYPE		((3UL << 1) | 1UL)

static struct syscallentry field_entry = {
	.name = "field",
	.num_args = 1,
	.argtype = { [0] = ARG_TIMESPEC },
};

static struct timespec field_ts = { .tv_sec = 0, .tv_nsec = 999999999 };

/* The field pins one cmp_hints_collect() call stages for a call whose
 * slot 1 holds field_ts, over one record comparing its tv_nsec with
 * NSEC_PER_SEC. */
static unsigned int field_pins(bool do32bit, unsigned int nr)
{
	struct childdata *child;
	unsigned int pins;

	kcov_shm = calloc(1, sizeof(*kcov_shm));
	cmp_hints_shm = calloc(1, sizeof(*cmp_hints_shm));
	child = calloc(1, sizeof(*child));
	if (kcov_shm == NULL || cmp_hints_shm == NULL || child == NULL)
		BUG("cmp collect: calloc failed");

	child->redqueen_enabled = true;
	child->syscall.entry = &field_entry;
	child->syscall.do32bit = do32bit;
	child->syscall.nr = nr;
	child->syscall.dispatch_args[0] = (unsigned long) &field_ts;
	child->syscall.dispatch_args_valid = true;

	trace_buf[0] = 1;
	trace_buf[1] = FIELD_CMP_TYPE;
	trace_buf[2] = 1000000000UL;
	trace_buf[3] = (unsigned long) field_ts.tv_nsec;
	trace_buf[4] = collect_ip(0);

	nr_flushed = 0;
	fake_this_child = child;

	cmp_hints_collect(trace_buf, nr, do32bit);

	fake_this_child = NULL;
	pins = child->reexec_pending_count;
	free(child);
	free_shm();
	return pins;
}

void cmp_collect_self_check(void);
void cmp_collect_self_check(void)
{
	run_collect();
	check_flushed();
	free_shm();

	if (field_pins(false, FIELD_NR_NATIVE) != 1)
		BUG("cmp collect: a native call's tv_nsec compare staged no field pin");
	/* A time32 call reads the buffer as 32-bit fields, which the scan's
	 * native read and the pin's native write would both misplace. */
	if (field_pins(true, FIELD_NR_TIME32) != 0)
		BUG("cmp collect: a time32 call's timespec took a native field pin");
}
