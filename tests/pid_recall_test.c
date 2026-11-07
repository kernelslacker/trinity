/*
 * Self-check for the re-call oracles that judge a call on the calling task
 * by a re-call of their own: each runs its sanitiser and post handler as
 * shipped, handed the answer a call gave, and counts the anomalies its
 * sampled re-call reports.  Only a call on this task is compared, and the
 * task is the one the kernel was handed, which chain substitution can
 * rewrite after the sanitiser drew its own, as it, or a RedQueen pin, can
 * sched_getattr's size and flags.  A time32 call answers in the 32-bit
 * layout, which the oracle widens before it compares.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "kernel/compat.h"	/* struct old_timespec32 */
#include "kernel/unistd.h"	/* SYS_get_robust_list, SYS_sched_getattr */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_get_robust_list, syscall_sched_getattr */
#include "utils.h"		/* ARRAY_SIZE */

void pid_recall_self_check(void);

static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "pid recall: %s\n", what);
	failed++;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

/* The shadow __do_syscall() takes of what the kernel was handed, @ran
 * being the pid it ran on and the rest of the record the other slots. */
static void ran_on(struct syscallrecord *rec, const struct syscallentry *entry,
		   pid_t ran)
{
	unsigned long *slots[] = { &rec->a1, &rec->a2, &rec->a3,
				   &rec->a4, &rec->a5, &rec->a6 };
	unsigned int k;

	rec->a1 = (unsigned long) ran;
	for (k = 0; k < ARRAY_SIZE(slots); k++)
		rec->arg_shadow[k] = *slots[k];
	rec->arg_snapshot_mask = entry->arg_snapshot_mask;
}

#ifdef SYS_get_robust_list
/* get_robust_list calls the sanitiser built on pid @built, which the
 * kernel ran on pid @ran, each answering @head and @len; the anomalies
 * the re-call reports. */
static unsigned long robust_list_anomalies(pid_t built, pid_t ran,
					   void *head, size_t len)
{
	unsigned long before = shm->stats.oracle.get_robust_list_oracle_anomalies;
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) built;
		rec.a2 = (unsigned long) get_writable_address(sizeof(void *));
		rec.a3 = (unsigned long) get_writable_address(sizeof(size_t));
		syscall_get_robust_list.sanitise(&rec);

		*(void **) rec.a2 = head;
		*(size_t *) rec.a3 = len;
		ran_on(&rec, &syscall_get_robust_list, ran);
		rec.retval = 0;
		syscall_get_robust_list.post(&rec);
	}
	return shm->stats.oracle.get_robust_list_oracle_anomalies - before;
}

static void robust_list_cases(void)
{
	pid_t other = gettid() + 1;
	void *head;
	size_t len;

	if (syscall(SYS_get_robust_list, 0, &head, &len) != 0)
		BUG("pid recall: cannot read this task's robust list");

	check("get_robust_list: a call answering this task's head was reported",
	      robust_list_anomalies(0, 0, head, len) == 0);
	check("get_robust_list: a call run on another task was compared with this one",
	      robust_list_anomalies(0, other, (char *) head + 64, len) == 0);
	check("get_robust_list: a call run on this task answering another head was not reported",
	      robust_list_anomalies(other, 0, (char *) head + 64, len) > 0);
}
#endif

#ifdef SYS_sched_getattr
/* What sched_getattr() wrote into a buffer this long. */
#define ATTR_BYTES	256

/* sched_getattr calls the sanitiser built on pid @built, which the kernel
 * ran on pid @ran with a size of @ran_size and flags of @ran_flags, each
 * answering the ATTR_BYTES at @answer; the anomalies the re-call reports. */
static unsigned long sched_attr_anomalies(pid_t built, pid_t ran,
					  unsigned long ran_size,
					  unsigned long ran_flags,
					  const unsigned char *answer)
{
	unsigned long before = shm->stats.oracle.sched_getattr_oracle_anomalies;
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) built;
		rec.a2 = (unsigned long) get_writable_address(page_size);
		syscall_sched_getattr.sanitise(&rec);

		memcpy((void *) rec.a2, answer, ATTR_BYTES);
		rec.a3 = ran_size;
		rec.a4 = ran_flags;
		ran_on(&rec, &syscall_sched_getattr, ran);
		rec.retval = 0;
		syscall_sched_getattr.post(&rec);
	}
	return shm->stats.oracle.sched_getattr_oracle_anomalies - before;
}

/* The smallest size sched_getattr() takes, SCHED_ATTR_SIZE_VER0, which is
 * what a RedQueen pin hands it from that check. */
#define ATTR_SIZE_VER0	48

/* SCHED_GETATTR_FLAG_DL_DYNAMIC, which has a deadline task answer its
 * remaining runtime, at offsetof(sched_runtime), and current deadline. */
#define DL_DYNAMIC	0x01
#define RUNTIME_OFFSET	24

static void sched_attr_cases(void)
{
	static unsigned char own[ATTR_BYTES], others[ATTR_BYTES];
	static unsigned char own_v0[ATTR_BYTES], dl_moved[ATTR_BYTES];
	pid_t other = gettid() + 1;
	uint32_t v0 = ATTR_SIZE_VER0;

	if (syscall(SYS_sched_getattr, 0, own, ATTR_BYTES, 0) != 0)
		BUG("pid recall: cannot read this task's scheduling attributes");
	/* Another task's: a nice value one off, at offsetof(sched_nice). */
	memcpy(others, own, ATTR_BYTES);
	others[16] ^= 1;
	/* What a call handed SCHED_ATTR_SIZE_VER0 gets: that much of the
	 * struct, and that size in its leading size word. */
	memcpy(own_v0, own, ATTR_SIZE_VER0);
	memcpy(own_v0, &v0, sizeof(v0));
	/* A deadline task's dynamic runtime, which moved since the call. */
	memcpy(dl_moved, own, ATTR_BYTES);
	dl_moved[RUNTIME_OFFSET] ^= 1;

	check("sched_getattr: a call answering this task's attributes was reported",
	      sched_attr_anomalies(0, 0, ATTR_BYTES, 0, own) == 0);
	check("sched_getattr: a call run on another task was compared with this one",
	      sched_attr_anomalies(0, other, ATTR_BYTES, 0, others) == 0);
	check("sched_getattr: a call run on this task answering another's attributes was not reported",
	      sched_attr_anomalies(other, 0, ATTR_BYTES, 0, others) > 0);
	check("sched_getattr: a call handed the smallest size was judged on the whole struct",
	      sched_attr_anomalies(0, 0, ATTR_SIZE_VER0, 0, own_v0) == 0);
	check("sched_getattr: a call handed the smallest size answering a larger size word was not reported",
	      sched_attr_anomalies(0, 0, ATTR_SIZE_VER0, 0, own) > 0);
	check("sched_getattr: a DL_DYNAMIC call was compared with a re-call without the flag",
	      sched_attr_anomalies(0, 0, ATTR_BYTES, DL_DYNAMIC, dl_moved) == 0);
	check("sched_getattr: a call without DL_DYNAMIC answering a moved runtime was not reported",
	      sched_attr_anomalies(0, 0, ATTR_BYTES, 0, dl_moved) > 0);
}
#endif

#ifdef SYS_sched_rr_get_interval
/* sched_rr_get_interval calls on this task, under compat number @nr or
 * natively for 0, each answering the @len bytes at @answer; the
 * anomalies the re-call reports. */
static unsigned long rr_interval_anomalies(unsigned int nr,
					   const void *answer, size_t len)
{
	unsigned long before =
		shm->stats.oracle.sched_rr_get_interval_oracle_anomalies;
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a2 = (unsigned long) get_writable_address(sizeof(struct timespec));
		syscall_sched_rr_get_interval.sanitise(&rec);

		memcpy((void *) rec.a2, answer, len);
		if (nr != 0) {
			rec.do32bit = true;
			rec.nr = nr;
		}
		ran_on(&rec, &syscall_sched_rr_get_interval, 0);
		rec.retval = 0;
		syscall_sched_rr_get_interval.post(&rec);
	}
	return shm->stats.oracle.sched_rr_get_interval_oracle_anomalies - before;
}

static void rr_interval_cases(void)
{
	struct timespec own;
	struct old_timespec32 own32;

	if (syscall(SYS_sched_rr_get_interval, 0, &own) != 0)
		BUG("pid recall: cannot read this task's round-robin interval");
	own32.tv_sec = (int32_t) own.tv_sec;
	own32.tv_nsec = (int32_t) own.tv_nsec;

	check("sched_rr_get_interval: a call answering this task's interval was reported",
	      rr_interval_anomalies(0, &own, sizeof(own)) == 0);
	/* 161 on i386, which writes an old_timespec32 and leaves the
	 * poison past it. */
	check("sched_rr_get_interval: a time32 call's interval was read at native offsets",
	      rr_interval_anomalies(161, &own32, sizeof(own32)) == 0);
}
#endif

void pid_recall_self_check(void)
{
	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(sizeof(void *)) == NULL)
		writable_pool_init();

#ifdef SYS_get_robust_list
	robust_list_cases();
#else
	printf("(no get_robust_list) ");
#endif
#ifdef SYS_sched_getattr
	sched_attr_cases();
#else
	printf("(no sched_getattr) ");
#endif
#ifdef SYS_sched_rr_get_interval
	rr_interval_cases();
#else
	printf("(no sched_rr_get_interval) ");
#endif

	if (failed != 0)
		BUG("a pid-gated re-call judged a call the kernel did not run");
}
