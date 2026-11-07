/*
 * Self-check for the re-call oracles keyed on a selector, a clock, a
 * resource or a filesystem index: each runs its sanitiser and post
 * handler as shipped, handed the answer the kernel gave for the selector
 * it was handed, and counts the anomalies its sampled re-call reports.
 * Chain substitution or a RedQueen pin can change the selector after the
 * sanitiser drew it, or the length of the answer, and the re-call has to
 * ask about the one the kernel answered.
 */

#include <errno.h>
#include <linux/mempolicy.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "kernel/compat.h"	/* struct old_timespec32 */
#include "kernel/lsm.h"		/* LSM_ATTR_CURRENT, LSM_ATTR_EXEC */
#include "kernel/unistd.h"	/* SYS_sysfs, SYS_lsm_get_self_attr */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_clock_getres, ... */
#include "utils.h"		/* waitpid_eintr */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern bool fake_pid_draws;			/* dup_pool_test.c */
extern bool (*fake_syscall)(long number, const unsigned long a[6],
			    long *ret);		/* landlock_test.c */

static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "selector recall: %s\n", what);
	failed++;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

/* Tries for a sanitiser to draw the selector a case builds on. */
#define DRAW_TRIES	100000

static struct syscallrecord rec;

/* The compat number a case runs its calls under, or 0 for a native
 * call.  The sanitiser draws as for a native call either way. */
static unsigned int compat_nr;

/* The slots the kernel was handed, as __do_syscall() shadows them. */
static void shadow_slots(const struct syscallentry *entry)
{
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int k;

	for (k = 0; k < ARRAY_SIZE(slots); k++)
		rec.arg_shadow[k] = *slots[k];
	rec.arg_snapshot_mask = entry->arg_snapshot_mask;
}

/* An oracle that takes its selector in a1 and the buffer the kernel
 * answers into in a2, and the counter it bumps. */
struct selector_oracle {
	struct syscallentry *entry;
	unsigned long *anomalies;
};

/* @o's calls the sanitiser drew on selector @built, which the kernel ran
 * on @ran, each answering the @len bytes at @answer; the anomalies the
 * re-call reports. */
static unsigned long selector_anomalies(const struct selector_oracle *o,
					unsigned long built, unsigned long ran,
					const void *answer, size_t len)
{
	unsigned long before = *o->anomalies;
	unsigned int i, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		for (tries = 0; tries < DRAW_TRIES; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a1 = built;
			rec.a2 = (unsigned long) get_writable_address(len);
			o->entry->sanitise(&rec);
			if (rec.a1 == built)
				break;
			free((void *) rec.post_state);
		}
		if (tries == DRAW_TRIES)
			BUG("a sanitiser never drew the selector");

		memcpy((void *) rec.a2, answer, len);
		rec.a1 = ran;
		if (compat_nr != 0) {
			rec.do32bit = true;
			rec.nr = compat_nr;
		}
		shadow_slots(o->entry);
		rec.retval = 0;
		o->entry->post(&rec);
	}
	return *o->anomalies - before;
}

/* A high-resolution clock and a coarse one, whose resolutions differ. */
static void clock_getres_cases(void)
{
	const struct selector_oracle o = {
		&syscall_clock_getres, &shm->stats.oracle.clock_getres_oracle_anomalies,
	};
	struct timespec fine, coarse;
	struct old_timespec32 fine32;

	if (clock_getres(CLOCK_MONOTONIC, &fine) != 0 ||
	    clock_getres(CLOCK_MONOTONIC_COARSE, &coarse) != 0)
		BUG("selector recall: no clock resolutions to compare");
	if (fine.tv_sec == coarse.tv_sec && fine.tv_nsec == coarse.tv_nsec) {
		printf("(clock resolutions alike) ");
		return;
	}

	check("clock_getres: a call rewritten onto another clock was re-called on the first",
	      selector_anomalies(&o, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC,
				 &fine, sizeof(fine)) == 0);
	check("clock_getres: a rewritten call answering the first clock's resolution was not reported",
	      selector_anomalies(&o, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE,
				 &fine, sizeof(fine)) > 0);

	/* clock_getres at 266 on i386 writes the resolution as a struct
	 * old_timespec32, leaving the poison past it. */
	fine32.tv_sec = (int32_t) fine.tv_sec;
	fine32.tv_nsec = (int32_t) fine.tv_nsec;
	compat_nr = 266;
	check("clock_getres: a time32 call's resolution was read at native offsets",
	      selector_anomalies(&o, CLOCK_MONOTONIC, CLOCK_MONOTONIC,
				 &fine32, sizeof(fine32)) == 0);
	compat_nr = 0;
}

#if defined(SYS_getrlimit) || defined(__NR_getrlimit)
/* Two resources whose limits differ. */
static void getrlimit_cases(void)
{
	const struct selector_oracle o = {
		&syscall_getrlimit, &shm->stats.oracle.getrlimit_oracle_anomalies,
	};
	struct rlimit files, stack;

	if (getrlimit(RLIMIT_NOFILE, &files) != 0 ||
	    getrlimit(RLIMIT_STACK, &stack) != 0)
		BUG("selector recall: no resource limits to compare");
	if (files.rlim_cur == stack.rlim_cur && files.rlim_max == stack.rlim_max) {
		printf("(resource limits alike) ");
		return;
	}

	check("getrlimit: a call rewritten onto another resource was re-called on the first",
	      selector_anomalies(&o, RLIMIT_STACK, RLIMIT_NOFILE,
				 &files, sizeof(files)) == 0);
	check("getrlimit: a rewritten call answering the first resource's limits was not reported",
	      selector_anomalies(&o, RLIMIT_NOFILE, RLIMIT_STACK,
				 &files, sizeof(files)) > 0);
}
#endif

/* RUSAGE_SELF against RUSAGE_CHILDREN, in a fresh child that has reaped
 * none: a re-call on the other who sees its page faults go back to 0. */
static void getrusage_cases(void)
{
	const struct selector_oracle o = {
		&syscall_getrusage, &shm->stats.oracle.getrusage_oracle_anomalies,
	};
	struct rusage self;
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		BUG("selector recall: cannot fork for getrusage");
	if (pid == 0) {
		if (getrusage(RUSAGE_SELF, &self) != 0 || self.ru_minflt == 0)
			BUG("selector recall: a fresh child with no usage to compare");
		check("getrusage: a call rewritten onto another who was re-called on the first",
		      selector_anomalies(&o, (unsigned long) RUSAGE_CHILDREN,
					 RUSAGE_SELF, &self, sizeof(self)) == 0);
		check("getrusage: a rewritten call answering the first who's usage was not reported",
		      selector_anomalies(&o, RUSAGE_SELF,
					 (unsigned long) RUSAGE_CHILDREN,
					 &self, sizeof(self)) > 0);
		_exit(failed != 0);
	}
	if (waitpid_eintr(pid, &status, 0) != pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		failed++;
}

#if defined(SYS_prlimit64) || defined(__NR_prlimit64)
/* prlimit64() calls the sanitiser built on this task and resource @built,
 * which the kernel ran on resource @ran, as a pure read when @read_only
 * (new_rlim cleared, as a RedQueen pin can), each answering @answer in
 * old_rlim; the anomalies the re-call reports. */
static unsigned long prlimit64_anomalies(unsigned long built, unsigned long ran,
					 bool read_only,
					 const struct rlimit64 *answer)
{
	unsigned long before = shm->stats.oracle.prlimit64_oracle_anomalies;
	unsigned int i, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		for (tries = 0; tries < DRAW_TRIES; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a2 = built;
			rec.a4 = (unsigned long) get_writable_address(sizeof(*answer));
			syscall_prlimit64.sanitise(&rec);
			if (rec.a1 == 0 && rec.a2 == built)
				break;
			free((void *) rec.post_state);
		}
		if (tries == DRAW_TRIES)
			BUG("prlimit64's sanitiser never drew the resource");

		memcpy((void *) rec.a4, answer, sizeof(*answer));
		rec.a2 = ran;
		if (read_only)
			rec.a3 = 0;
		shadow_slots(&syscall_prlimit64);
		rec.retval = 0;
		syscall_prlimit64.post(&rec);
	}
	return shm->stats.oracle.prlimit64_oracle_anomalies - before;
}

/* Two resources the sanitiser keeps on this task, whose limits differ.
 * Only a pure read is re-called: a call that set a limit moved it. */
static void prlimit64_cases(void)
{
	struct rlimit64 sigpending, msgqueue;

	if (prlimit64(0, RLIMIT_SIGPENDING, NULL, &sigpending) != 0 ||
	    prlimit64(0, RLIMIT_MSGQUEUE, NULL, &msgqueue) != 0)
		BUG("selector recall: no resource limits to compare");
	if (sigpending.rlim_cur == msgqueue.rlim_cur &&
	    sigpending.rlim_max == msgqueue.rlim_max) {
		printf("(resource limits alike) ");
		return;
	}

	check("prlimit64: a pure read rewritten onto another resource was re-called on the first",
	      prlimit64_anomalies(RLIMIT_SIGPENDING, RLIMIT_MSGQUEUE, true,
				  &msgqueue) == 0);
	check("prlimit64: a rewritten pure read answering the first resource's limits was not reported",
	      prlimit64_anomalies(RLIMIT_MSGQUEUE, RLIMIT_SIGPENDING, true,
				  &msgqueue) > 0);
	check("prlimit64: a call that set a limit was re-called",
	      prlimit64_anomalies(RLIMIT_MSGQUEUE, RLIMIT_SIGPENDING, false,
				  &msgqueue) == 0);
}
#endif

#ifdef SYS_sysfs
/* The filesystem names a fake sysfs() lists, by index: the syscall is
 * configured out of many a kernel. */
static const char *const fake_fs_names[] = { "sysfs", "tmpfs" };

static bool fake_sysfs(long number, const unsigned long a[6], long *ret)
{
	unsigned int idx = (unsigned int) a[1];

	if (number != SYS_sysfs)
		return false;
	*ret = -EINVAL;
	if ((int) a[0] == 2 && idx < ARRAY_SIZE(fake_fs_names)) {
		strcpy((char *) a[2], fake_fs_names[idx]);
		*ret = 0;
	} else if ((int) a[0] == 3) {
		*ret = ARRAY_SIZE(fake_fs_names);
	}
	return true;
}

/* sysfs(2, index, buf) calls the sanitiser built on index @built, which the
 * kernel ran as option @option on index @ran, each leaving @answer in the
 * buffer; the anomalies the re-call reports. */
static unsigned long sysfs_anomalies(unsigned long built, unsigned long option,
				     unsigned long ran, const char *answer)
{
	unsigned long before = shm->stats.oracle.sysfs_oracle_anomalies;
	unsigned int i, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		for (tries = 0; tries < DRAW_TRIES; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a1 = 2;
			syscall_sysfs.sanitise(&rec);
			if (rec.a2 == built)
				break;
			free((void *) rec.post_state);
		}
		if (tries == DRAW_TRIES)
			BUG("sysfs's sanitiser never drew the index");

		strcpy((char *) rec.a3, answer);
		rec.a1 = option;
		rec.a2 = ran;
		shadow_slots(&syscall_sysfs);
		rec.retval = 0;
		syscall_sysfs.post(&rec);
	}
	return shm->stats.oracle.sysfs_oracle_anomalies - before;
}

/* An index rewritten to another filesystem's, and an option rewritten to
 * the count, which leaves the buffer as it was. */
static void sysfs_cases(void)
{
	fake_syscall = fake_sysfs;
	check("sysfs: a call rewritten onto another index was re-called on the first",
	      sysfs_anomalies(0, 2, 1, "tmpfs") == 0);
	check("sysfs: a rewritten call answering the first index's name was not reported",
	      sysfs_anomalies(0, 2, 1, "sysfs") > 0);
	check("sysfs: a call rewritten to count the filesystems was judged by its buffer",
	      sysfs_anomalies(0, 3, 0, "stale") == 0);
	fake_syscall = NULL;
}
#endif

#ifdef SYS_lsm_get_self_attr
/* A fake lsm_get_self_attr() answering each attribute with its own number:
 * what the calling task holds depends on the LSMs a kernel runs.  A single
 * LSM's answer it refuses, as the kernel does for the zeroed lsm_ctx id
 * the re-call hands it. */
static bool fake_lsm_get_self_attr(long number, const unsigned long a[6],
				   long *ret)
{
	if (number != SYS_lsm_get_self_attr)
		return false;
	*ret = -EINVAL;
	if (a[3] == 0) {
		memcpy((void *) a[1], &a[0], sizeof(a[0]));
		*(uint32_t *) a[2] = sizeof(a[0]);
		*ret = 0;
	}
	return true;
}

/* lsm_get_self_attr calls the sanitiser built on attribute @built, which
 * the kernel ran on @ran, each answering as the fake does for @answer;
 * the anomalies the re-call reports. */
static unsigned long lsm_anomalies(unsigned long built, unsigned long ran,
				   unsigned long answer)
{
	unsigned long before = shm->stats.oracle.lsm_get_self_attr_oracle_anomalies;
	unsigned int i;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = built;
		syscall_lsm_get_self_attr.sanitise(&rec);

		/* The sanitiser's arms without a buffer or a size are ones
		 * the post handler passes over. */
		if (rec.a2 != 0 && rec.a3 != 0) {
			memcpy((void *) rec.a2, &answer, sizeof(answer));
			*(uint32_t *) rec.a3 = sizeof(answer);
		}
		rec.a1 = ran;
		shadow_slots(&syscall_lsm_get_self_attr);
		rec.retval = 0;
		syscall_lsm_get_self_attr.post(&rec);
	}
	return shm->stats.oracle.lsm_get_self_attr_oracle_anomalies - before;
}

static void lsm_cases(void)
{
	fake_syscall = fake_lsm_get_self_attr;
	check("lsm_get_self_attr: a call rewritten onto another attribute was re-called on the first",
	      lsm_anomalies(LSM_ATTR_CURRENT, LSM_ATTR_EXEC, LSM_ATTR_EXEC) == 0);
	check("lsm_get_self_attr: a call answering another attribute's context was not reported",
	      lsm_anomalies(LSM_ATTR_CURRENT, LSM_ATTR_CURRENT, LSM_ATTR_EXEC) > 0);
	fake_syscall = NULL;
}
#endif

#ifdef __NR_get_mempolicy
/* A fake get_mempolicy() for a task bound to node 1 of a two-node box,
 * writing as much of the mask as copy_nodes_to_user() does: a task's
 * policy depends on the NUMA setup a kernel runs on.  An address, and a
 * flag other than MPOL_F_MEMS_ALLOWED, it refuses. */
#define FAKE_BOUND_NODES	0x2UL
#define FAKE_ALLOWED_NODES	0x3UL

static bool fake_get_mempolicy(long number, const unsigned long a[6], long *ret)
{
	unsigned long nodes = FAKE_BOUND_NODES;
	int mode = MPOL_BIND;

	if (number != __NR_get_mempolicy)
		return false;
	*ret = -EINVAL;
	if (a[2] < 2 || a[3] != 0 || (a[4] & ~(unsigned long) MPOL_F_MEMS_ALLOWED))
		return true;
	if (a[4] == MPOL_F_MEMS_ALLOWED) {
		mode = MPOL_DEFAULT;
		nodes = FAKE_ALLOWED_NODES;
	}
	*(int *) a[0] = mode;
	/* ALIGN(maxnode - 1, 64) / 8 bytes, the nodes past the box's two
	 * cleared. */
	memset((void *) a[1], 0, (a[2] + 62) / 64 * sizeof(unsigned long));
	memcpy((void *) a[1], &nodes, sizeof(nodes));
	*ret = 0;
	return true;
}

/* The slots of a get_mempolicy() call the cases vary. */
struct mempolicy_call {
	unsigned long maxnode;
	unsigned long flags;
};

/* get_mempolicy calls the sanitiser built as @built, which the kernel ran
 * as @ran, each answering as the fake does for @answer; the anomalies the
 * re-call reports. */
static unsigned long mempolicy_anomalies(const struct mempolicy_call *built,
					 const struct mempolicy_call *ran,
					 const struct mempolicy_call *answer)
{
	unsigned long before = shm->stats.oracle.get_mempolicy_oracle_anomalies;
	unsigned int i;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) get_writable_address(sizeof(int));
		rec.a2 = (unsigned long) get_writable_address(page_size);
		rec.a3 = built->maxnode;
		rec.a5 = built->flags;
		syscall_get_mempolicy.sanitise(&rec);

		if (syscall(__NR_get_mempolicy, rec.a1, rec.a2, answer->maxnode,
			    0UL, answer->flags) != 0)
			BUG("selector recall: get_mempolicy's fake refused an answer");
		rec.a3 = ran->maxnode;
		rec.a5 = ran->flags;
		shadow_slots(&syscall_get_mempolicy);
		rec.retval = 0;
		syscall_get_mempolicy.post(&rec);
	}
	return shm->stats.oracle.get_mempolicy_oracle_anomalies - before;
}

/* The task's own nodes and the ones it may use, and a mask one word
 * shorter, which leaves the sanitiser's poison in the word after it, as
 * does a maxnode one past a multiple of 64: the kernel writes maxnode - 1
 * bits. */
static void mempolicy_cases(void)
{
	static const struct mempolicy_call bound = { 64, 0 };
	static const struct mempolicy_call bound_wide = { 128, 0 };
	static const struct mempolicy_call bound_odd = { 65, 0 };
	static const struct mempolicy_call allowed = { 64, MPOL_F_MEMS_ALLOWED };

	fake_syscall = fake_get_mempolicy;
	check("get_mempolicy: a call rewritten onto another flag was re-called on the first",
	      mempolicy_anomalies(&bound, &allowed, &allowed) == 0);
	check("get_mempolicy: a rewritten call answering the first flag's nodes was not reported",
	      mempolicy_anomalies(&allowed, &bound, &allowed) > 0);
	check("get_mempolicy: a call rewritten onto a shorter mask was compared over the longer",
	      mempolicy_anomalies(&bound_wide, &bound, &bound) == 0);
	check("get_mempolicy: a maxnode one past a multiple of 64 was compared over a word the kernel does not write",
	      mempolicy_anomalies(&bound_odd, &bound_odd, &bound_odd) == 0);
	fake_syscall = NULL;
}
#endif

void selector_recall_self_check(void);
void selector_recall_self_check(void)
{
	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(page_size) == NULL)
		writable_pool_init();

	fake_pid_draws = true;
	clock_getres_cases();
	fake_pid_draws = false;
#if defined(SYS_getrlimit) || defined(__NR_getrlimit)
	getrlimit_cases();
#endif
	getrusage_cases();
#if defined(SYS_prlimit64) || defined(__NR_prlimit64)
	prlimit64_cases();
#endif
#ifdef SYS_sysfs
	sysfs_cases();
#endif
#ifdef SYS_lsm_get_self_attr
	lsm_cases();
#endif
#ifdef __NR_get_mempolicy
	mempolicy_cases();
#endif

	if (failed != 0)
		BUG("a selector re-call asked about the wrong selector");
}
