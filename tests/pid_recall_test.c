/*
 * Self-check for the re-call oracles that judge a call on the calling task
 * by a re-call of their own: each runs its sanitiser and post handler as
 * shipped, handed the answer a call gave, and counts the anomalies its
 * sampled re-call reports.  Only a call on this task is compared, and the
 * task is the one the kernel was handed, which chain substitution can
 * rewrite after the sanitiser drew its own.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "kernel/unistd.h"	/* SYS_get_robust_list */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_get_robust_list */
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
 * being the pid it ran on. */
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

	if (failed != 0)
		BUG("a pid-gated re-call judged a call the kernel did not run");
}
