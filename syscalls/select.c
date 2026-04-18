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
#include "deferred-free.h"

static void sanitise_select(struct syscallrecord *rec)
{
	unsigned int nfds, i, nset;

	struct timeval *tv;
	fd_set *rfds, *wfds, *exfds;

	nfds = (rand32() % 1023) + 1;
	rec->a1 = nfds;

	rfds = zmalloc(sizeof(fd_set));
	wfds = zmalloc(sizeof(fd_set));
	exfds = zmalloc(sizeof(fd_set));

	FD_ZERO(rfds);
	FD_ZERO(wfds);
	FD_ZERO(exfds);

	nset = rand32() % 10;
	/* set some random fd's. */
	for (i = 0; i < nset; i++) {
		FD_SET(rand32() % nfds, rfds);
		FD_SET(rand32() % nfds, wfds);
		FD_SET(rand32() % nfds, exfds);
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
	deferred_freeptr(&rec->a2);
	deferred_freeptr(&rec->a3);
	deferred_freeptr(&rec->a4);
	deferred_freeptr(&rec->a5);
}

struct syscallentry syscall_select = {
	.name = "select",
	.num_args = 5,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS },
	.argname = { [0] = "n", [1] = "inp", [2] = "outp", [3] = "exp", [4] = "tvp" },
	.sanitise = sanitise_select,
	.post = post_select,
	.group = GROUP_VFS,
	.flags = NEED_ALARM,
};
