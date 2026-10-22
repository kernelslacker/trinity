/*
 * Self-check for the values the post oracles accept on a call that
 * worked.  Each case hands a post handler the return a successful call
 * produces and counts the corrupt-pointer bumps it makes: a value the
 * kernel returns must not bump, one it cannot return must.  The handlers
 * run as shipped; the post_state table, post_snapshot_or_skip() and the
 * bump itself are faked here.
 */

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#include "debug.h"		/* BUG */
#include "kernel/prctl.h"	/* PR_THP_DISABLE_EXCEPT_ADVISED */
#include "kernel/sched.h"	/* SCHED_EXT, SCHED_RESET_ON_FORK */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_prctl */
#include "utils.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

static unsigned int bumps;
static unsigned int failed;

void post_handler_corrupt_ptr_bump_site(struct syscallrecord *rec,
					void *caller_pc, const char *site)
{
	(void) rec;
	(void) caller_pc;
	(void) site;
	bumps++;
}

void arg_shadow_stomp_bump(struct syscallrecord *rec, unsigned int argnum,
			   unsigned long shadow, unsigned long current)
{
	(void) rec;
	(void) argnum;
	(void) shadow;
	(void) current;
	BUG("a post oracle read an arg whose shadow no longer matched");
}

/* Copies unless a case says the buffer is not one the real helper would
 * prove readable. */
static bool snapshot_readable = true;

bool post_snapshot_or_skip(void *dst, const void *src, size_t len)
{
	if (!snapshot_readable || src == NULL)
		return false;
	memcpy(dst, src, len);
	return true;
}

bool post_state_is_owned(const void *p)
{
	(void) p;
	return true;
}

void post_state_register(void *p)
{
	(void) p;
}

void post_state_release(struct syscallrecord *rec, void *snap)
{
	if (rec->post_state == (unsigned long) snap)
		rec->post_state = 0;
	free(snap);
}

static void expect(const char *what, unsigned int got, unsigned int want)
{
	if (got == want)
		return;
	fprintf(stderr, "%s: %u bump(s), wanted %u\n", what, got, want);
	failed++;
}

/* The out-param the kernel writes through arg2. */
static unsigned int *out;

/* Run prctl's own sanitiser until it draws @option, so the snapshot the
 * post handler claims is the one the sanitiser built. */
static struct syscallrecord *prctl_rec(int option)
{
	static struct syscallrecord rec;
	unsigned int tries;

	for (tries = 0; tries < 4096; tries++) {
		memset(&rec, 0, sizeof(rec));
		rec.a2 = (unsigned long) out;
		syscall_prctl.sanitise(&rec);
		if (rec.a1 == (unsigned long) option)
			return &rec;
		free((void *) rec.post_state);
	}
	BUG("prctl sanitiser never drew the option");
	return NULL;
}

static unsigned int prctl_get(int option, unsigned long retval,
			      unsigned int out_word)
{
	struct syscallrecord *rec = prctl_rec(option);

	*out = out_word;
	rec->retval = retval;
	rec->errno_post = (retval == (unsigned long) -1L) ? EINVAL : 0;
	bumps = 0;
	syscall_prctl.post(rec);
	return bumps;
}

/* x86 and arm64 return 0 and store the mode through arg2; the other
 * architectures return -EINVAL. */
static void get_tsc(void)
{
	static const struct {
		const char *what;
		unsigned long retval;
		unsigned int out_word;
		bool readable;
		unsigned int bumps;
	} cases[] = {
		{ "PR_GET_TSC, mode ENABLE", 0, PR_TSC_ENABLE, true, 0 },
		{ "PR_GET_TSC, mode SIGSEGV", 0, PR_TSC_SIGSEGV, true, 0 },
		{ "PR_GET_TSC, -EINVAL", (unsigned long) -1L, 0, true, 0 },
		{ "PR_GET_TSC, buffer not provably readable",
		  0, 0, false, 0 },
		{ "PR_GET_TSC, mode 0 in the out-word", 0, 0, true, 1 },
		{ "PR_GET_TSC, mode 3 in the out-word", 0, 3, true, 1 },
		{ "PR_GET_TSC, the mode in the return slot",
		  PR_TSC_ENABLE, PR_TSC_ENABLE, true, 1 },
		{ "PR_GET_TSC, a -errno in the return slot",
		  (unsigned long) -22L, 0, true, 1 },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		snapshot_readable = cases[i].readable;
		expect(cases[i].what,
		       prctl_get(PR_GET_TSC, cases[i].retval,
				 cases[i].out_word),
		       cases[i].bumps);
	}
	snapshot_readable = true;
}

/* 0 when THP is not disabled, 1 when it is disabled completely, and
 * 1 | PR_THP_DISABLE_EXCEPT_ADVISED when disabled except where advised. */
static void get_thp_disable(void)
{
	static const struct {
		const char *what;
		unsigned long retval;
		unsigned int bumps;
	} cases[] = {
		{ "PR_GET_THP_DISABLE, not disabled", 0, 0 },
		{ "PR_GET_THP_DISABLE, disabled", 1, 0 },
		{ "PR_GET_THP_DISABLE, disabled except advised",
		  1UL | PR_THP_DISABLE_EXCEPT_ADVISED, 0 },
		{ "PR_GET_THP_DISABLE, -EINVAL", (unsigned long) -1L, 0 },
		{ "PR_GET_THP_DISABLE, the flag without bit 0",
		  PR_THP_DISABLE_EXCEPT_ADVISED, 1 },
		{ "PR_GET_THP_DISABLE, an unknown flag", 1UL | (1UL << 2), 1 },
		{ "PR_GET_THP_DISABLE, a high bit set",
		  0x80000001UL, 1 },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++)
		expect(cases[i].what,
		       prctl_get(PR_GET_THP_DISABLE, cases[i].retval, 0),
		       cases[i].bumps);
}

/* The policy, with SCHED_RESET_ON_FORK OR'd in while the task has
 * sched_reset_on_fork set.  Only a query for the calling task (pid 0) is
 * judged. */
static void sched_getscheduler_policy(void)
{
	static const struct {
		const char *what;
		unsigned long pid;
		unsigned long retval;
		unsigned int bumps;
	} cases[] = {
		{ "sched_getscheduler, SCHED_OTHER", 0, SCHED_OTHER, 0 },
		{ "sched_getscheduler, SCHED_EXT", 0, SCHED_EXT, 0 },
		{ "sched_getscheduler, SCHED_OTHER with SCHED_RESET_ON_FORK",
		  0, SCHED_OTHER | SCHED_RESET_ON_FORK, 0 },
		{ "sched_getscheduler, SCHED_BATCH with SCHED_RESET_ON_FORK",
		  0, SCHED_BATCH | SCHED_RESET_ON_FORK, 0 },
		{ "sched_getscheduler, -1", 0, (unsigned long) -1L, 0 },
		{ "sched_getscheduler, a policy past SCHED_EXT",
		  0, SCHED_EXT + 1, 1 },
		{ "sched_getscheduler, a policy past SCHED_EXT with the flag",
		  0, (SCHED_EXT + 1) | SCHED_RESET_ON_FORK, 1 },
		{ "sched_getscheduler, a stray high bit",
		  0, 0x20000000UL | SCHED_OTHER, 1 },
		{ "sched_getscheduler, another task's pid is not judged",
		  1, 0x20000000UL, 0 },
	};
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = cases[i].pid;
		rec.arg_snapshot_mask = syscall_sched_getscheduler.arg_snapshot_mask;
		rec.arg_shadow[0] = cases[i].pid;
		rec.retval = cases[i].retval;
		rec.errno_post = ((long) cases[i].retval == -1L) ? EINVAL : 0;
		bumps = 0;
		syscall_sched_getscheduler.post(&rec);
		expect(cases[i].what, bumps, cases[i].bumps);
	}
}

void post_oracle_self_check(void);
void post_oracle_self_check(void)
{
	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(sizeof(*out)) == NULL)
		writable_pool_init();
	out = get_writable_address(sizeof(*out));

	get_tsc();
	get_thp_disable();
	sched_getscheduler_policy();

	if (failed != 0)
		BUG("a post oracle judged a return value wrongly");
}
