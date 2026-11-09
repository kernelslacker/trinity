/*
 * Self-check for lsm_list_modules' sanitiser and re-call oracle.  A compat
 * call reads each pointer slot as its low 32 bits, so the ids buffer and
 * the size word it hands the kernel come from the low pool for one,
 * whatever value-result shape it drew: HUGE's 4 MiB is a heap buffer no
 * pool can stand in for, which malloc() maps past 4 GiB until a free
 * raises its threshold.  A successful call returns the number of LSMs it
 * listed, which the oracle has to judge.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"		/* page_size */
#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "deferred-free.h"	/* deferred_free_flush */
#include "kernel/lsm.h"		/* LSM_ID_CAPABILITY, ... */
#include "kernel/unistd.h"	/* SYS_lsm_list_modules */
#include "sanitise.h"		/* starts_in_call_pools */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_lsm_list_modules */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct childdata *fake_this_child;	/* fake_shm.c */
extern bool (*fake_syscall)(long number, const unsigned long a[6],
			    long *ret);		/* landlock_test.c */

/* lsm_list_modules on i386. */
#define NR_LSM_LIST_MODULES_I386	461

/* Calls to judge by: HUGE is about one value-result shape in 32, drawn on
 * four calls in five, so these draw it some 25 times. */
#define CALLS	1024

static void compat_buffer_cases(void)
{
	static struct childdata compat;
	struct syscallrecord *rec = &compat.syscall;
	unsigned int i;

	/* A sanitiser builds the call in this_child()'s record, whose being
	 * compat sends its buffers to the low pool. */
	fake_this_child = &compat;
	for (i = 0; i < CALLS; i++) {
		memset(rec, 0, sizeof(*rec));
		rec->do32bit = true;
		rec->nr = NR_LSM_LIST_MODULES_I386;
		syscall_lsm_list_modules.sanitise(rec);
		if (rec->a1 > UINT32_MAX || rec->a2 > UINT32_MAX)
			BUG("lsm_list_modules: a compat call's buffer lies past 4 GiB");
		if ((rec->a1 != 0 && !starts_in_call_pools(rec->a1)) ||
		    (rec->a2 != 0 && !starts_in_call_pools(rec->a2)))
			BUG("lsm_list_modules: a compat call's buffer is not the call's pool");

		/* A failed call: the post handler only gives the snapshot back. */
		rec->retval = (unsigned long) -1L;
		rec->errno_post = EFAULT;
		syscall_lsm_list_modules.post(rec);
	}
	fake_this_child = NULL;
}

#if defined(SYS_lsm_list_modules)
/* The LSMs a kernel runs, and a stack that differs in its second. */
static const uint64_t lsms[] = { LSM_ID_CAPABILITY, LSM_ID_LANDLOCK };
static const uint64_t other_lsms[] = { LSM_ID_CAPABILITY, LSM_ID_BPF };

/* What lsm_list_modules() answers into @ids and @size on a kernel running
 * the LSMs @stack lists: the size word whatever it held, then the ids if
 * it holds them all, and the number of them, or -errno. */
static long list_modules(const uint64_t *stack, uint64_t *ids, uint32_t *size)
{
	uint32_t total = ARRAY_SIZE(lsms) * sizeof(*ids);
	uint32_t usize;

	if (size == NULL)
		return -EFAULT;
	usize = *size;
	*size = total;
	if (usize < total)
		return -E2BIG;
	if (ids == NULL)
		return -EFAULT;
	memcpy(ids, stack, total);
	return ARRAY_SIZE(lsms);
}

/* The stack the oracle's re-call meets. */
static const uint64_t *recall_stack;

static bool fake_lsm_list_modules(long number, const unsigned long a[6],
				  long *ret)
{
	if (number != SYS_lsm_list_modules)
		return false;
	*ret = a[2] != 0 ? -EINVAL :
		list_modules(recall_stack, (uint64_t *) a[0], (uint32_t *) a[1]);
	return true;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

/* Calls answered by a kernel running lsms[], whose re-calls meet
 * @recalled; the anomalies the oracle reports. */
static unsigned long recall_anomalies(const uint64_t *recalled)
{
	unsigned long before = shm->stats.oracle.lsm_list_modules_oracle_anomalies;
	struct syscallrecord rec;
	unsigned int i;
	long ret;

	recall_stack = recalled;
	fake_syscall = fake_lsm_list_modules;
	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		syscall_lsm_list_modules.sanitise(&rec);
		ret = list_modules(lsms, (uint64_t *) rec.a1, (uint32_t *) rec.a2);
		rec.retval = ret < 0 ? (unsigned long) -1L : (unsigned long) ret;
		rec.errno_post = ret < 0 ? (int) -ret : 0;
		syscall_lsm_list_modules.post(&rec);

		/* Each call sends two value-result buffers to deferred
		 * free, whose ring and arena hold some 2000 and leak what
		 * they evict, and nothing ticks it here: drain it as the
		 * calls go. */
		if (i % 512 == 511)
			deferred_free_flush();
	}
	fake_syscall = NULL;
	return shm->stats.oracle.lsm_list_modules_oracle_anomalies - before;
}

static void recall_cases(void)
{
	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(page_size) == NULL)
		writable_pool_init();

	if (recall_anomalies(lsms) != 0)
		BUG("lsm_list_modules: a re-call listing the same LSMs was reported");
	if (recall_anomalies(other_lsms) == 0)
		BUG("lsm_list_modules: a re-call listing other LSMs was not reported");
}
#endif

void lsm_list_modules_self_check(void);
void lsm_list_modules_self_check(void)
{
	/* The value-result buffers go to deferred free: drained after each
	 * run of calls for ASAN to find. */
	compat_buffer_cases();
	deferred_free_flush();
#if defined(SYS_lsm_list_modules)
	recall_cases();
	deferred_free_flush();
#endif
}
