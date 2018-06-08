/*
 * SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, fd_set __user *, outp,
	fd_set __user *, exp, struct timeval __user *, tvp)
 */
#include <sys/time.h>
       #include <stdio.h>
       #include <stdlib.h>
       #include <sys/types.h>
       #include <unistd.h>

#include "random.h"
#include "sanitise.h"
#include "utils.h"

#ifndef __NFDBITS
#define __NFDBITS NFDBITS
#endif

static void sanitise_select(struct syscallrecord *rec)
{
	unsigned int i;

	struct timeval *tv;
	fd_set *rfds, *wfds, *exfds;

	rec->a1 = rand32() % 1024;

	rfds = zmalloc(sizeof(fd_set));
	wfds = zmalloc(sizeof(fd_set));
	exfds = zmalloc(sizeof(fd_set));

	FD_ZERO(rfds);
	FD_ZERO(wfds);
	FD_ZERO(exfds);

	/* set some random fd's. */
	for (i = 0; i < rand32() % 10; i++) {
		FD_SET(rand32() % (__NFDBITS - 1), rfds);
		FD_SET(rand32() % (__NFDBITS - 1), wfds);
		FD_SET(rand32() % (__NFDBITS - 1), exfds);
	}

	rec->a2 = (unsigned long) rfds;
	rec->a3 = (unsigned long) wfds;
	rec->a4 = (unsigned long) exfds;

	/* Set a really short timeout */
	tv = zmalloc(sizeof(struct timeval));
	tv->tv_sec = 0;
	tv->tv_usec = 10;
	rec->a5 = (unsigned long) tv;
}

static void post_select(struct syscallrecord *rec)
{
	freeptr(&rec->a2);
	freeptr(&rec->a3);
	freeptr(&rec->a4);
	freeptr(&rec->a5);
}

struct syscallentry syscall_select = {
	.name = "select",
	.num_args = 5,
	.arg1name = "n",
	.arg2name = "inp",
	.arg3name = "outp",
	.arg4name = "exp",
	.arg5name = "tvp",
	.sanitise = sanitise_select,
	.post = post_select,
};
