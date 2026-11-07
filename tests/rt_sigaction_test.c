/*
 * Self-check for rt_sigaction's sanitiser: the act it builds is the
 * struct the kernel copies in for the call's ABI, not glibc's struct
 * sigaction.  On x86-64 that is handler, sa_flags, sa_restorer and an
 * 8-byte mask, with SA_RESTORER and glibc's restorer set, since the
 * kernel will not deliver to a handler without one.  A compat call
 * reads compat_sigaction's 32-bit fields from a buffer below 4 GiB.
 */

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_rt_sigaction */

extern struct childdata *fake_this_child;	/* fake_shm.c */

/* rt_sigaction on i386. */
#define NR_RT_SIGACTION_32	174

/* The uapi value, which glibc's <signal.h> leaves out. */
#define UAPI_SA_RESTORER	0x04000000UL

/* Runs; each builds an act half the time. */
#define RUNS	64

static void alarm_handler(int sig)
{
	(void) sig;
}

/* What glibc's sigaction() put in the kernel's sa_restorer for SIGALRM. */
static unsigned long installed_restorer(void)
{
	unsigned long kact[4];

	if (syscall(__NR_rt_sigaction, SIGALRM, NULL, kact, 8) != 0)
		BUG("rt_sigaction: could not read SIGALRM's action back");
	return (kact[1] & UAPI_SA_RESTORER) ? kact[2] : 0;
}

static void check_native(void)
{
	struct syscallrecord rec;
	unsigned long restorer = 0;
	unsigned int i, built = 0;

#ifdef __x86_64__
	restorer = installed_restorer();
	if (restorer == 0)
		BUG("rt_sigaction: glibc installed SIGALRM without a restorer");
#endif

	for (i = 0; i < RUNS; i++) {
		const unsigned long *k;

		memset(&rec, 0, sizeof(rec));
		syscall_rt_sigaction.sanitise(&rec);
		if (rec.a4 != 8)
			BUG("rt_sigaction: sigsetsize is not the kernel's 8");
		if (rec.a2 != 0) {
			built++;

			/* handler, sa_flags, then sa_restorer where the arch
			 * has one. */
			k = (const unsigned long *) rec.a2;
			if (k[1] >> 31 >> 1)
				BUG("rt_sigaction: sa_flags holds more than build_sa_flags() makes");
#ifdef __x86_64__
			if (!(k[1] & UAPI_SA_RESTORER) || k[2] != restorer)
				BUG("rt_sigaction: an x86-64 act names no restorer, or not glibc's");
#endif
		}
		/* The dispatcher's post pass on a failed call, which
		 * releases the sanitiser's snapshot. */
		rec.retval = (unsigned long) -1L;
		syscall_rt_sigaction.post(&rec);
	}
	if (built == 0)
		BUG("rt_sigaction: no native run built an act");
}

static void check_compat(void)
{
	static struct childdata compat;
	struct syscallrecord *crec = &compat.syscall;
	unsigned int i, built = 0;

	/* A sanitiser builds the call in this_child()'s record, whose
	 * being compat sends its buffers to the low pool. */
	fake_this_child = &compat;
	for (i = 0; i < RUNS; i++) {
		const uint32_t *c;

		memset(crec, 0, sizeof(*crec));
		crec->do32bit = true;
		crec->nr = NR_RT_SIGACTION_32;
		syscall_rt_sigaction.sanitise(crec);
		if (crec->a2 != 0) {
			built++;

			if (crec->a2 > UINT32_MAX)
				BUG("rt_sigaction: a compat call's act lies past 4 GiB");
			/* handler, sa_flags, sa_restorer, then the two mask
			 * words; nothing a compat call installs names a
			 * restorer. */
			c = (const uint32_t *) crec->a2;
			if (c[2] != 0)
				BUG("rt_sigaction: a compat act's sa_restorer is not empty");
		}
		crec->retval = (unsigned long) -1L;
		syscall_rt_sigaction.post(crec);
	}
	fake_this_child = NULL;
	if (built == 0)
		BUG("rt_sigaction: no compat run built an act");
}

void rt_sigaction_self_check(void);
void rt_sigaction_self_check(void)
{
	struct sigaction sa, old;

	/* What a child has: SIGALRM's flag-setter, installed by glibc. */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = alarm_handler;
	if (sigaction(SIGALRM, &sa, &old) != 0)
		BUG("rt_sigaction: could not install a SIGALRM handler");

	check_native();
	check_compat();

	(void) sigaction(SIGALRM, &old, NULL);
}
