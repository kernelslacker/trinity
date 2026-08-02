/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <linux/userfaultfd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "childop-outcome.h"
#include "syscall-gate.h"
#include "maps.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "childops/recipe/internal.h"

#include "kernel/eventfd.h"
#include "kernel/fcntl.h"
#include "kernel/timerfd.h"
#include "kernel/memfd.h"
/*
 * Recipe 7: TCP server lifecycle.
 *
 * socket → setsockopt(SO_REUSEADDR) → bind to 127.0.0.1 with port 0
 * (kernel chooses) → listen → accept (non-blocking, expected EAGAIN
 * since nobody connects) → shutdown → close.  Drives the listening
 * socket through its full state-machine setup and teardown so the
 * tcp_close, sk_state_change, and reqsk-queue cleanup paths run.
 */
bool recipe_tcp_server(bool *unsupported __unused__)
{
	/* Snapshot the recipe-runner childop under which we're executing
	 * so the direct-syscall reporter attributes this invocation's
	 * per-attempt raw kernel entries (socket / bind / listen /
	 * setsockopt / fcntl / accept / shutdown / close) to the parent
	 * op's per-childop tally.  Bounds-check the snapshot — the field
	 * lives in shared memory and can be scribbled by a poisoned-arena
	 * write from a sibling; matches the surrounding valid_op gate in
	 * recipe_runner. */
	struct childdata *child = this_child();
	const enum child_op_type op = child ? child->op_type :
		NR_CHILD_OP_TYPES;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	struct sockaddr_in sin;
	socklen_t slen;
	int s = -1;
	int one = 1;
	int flags;
	bool ok = false;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		goto out;

	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		goto out;

	if (listen(s, 4) < 0)
		goto out;

	flags = fcntl(s, F_GETFL);
	if (flags >= 0)
		(void)fcntl(s, F_SETFL, flags | O_NONBLOCK);

	slen = sizeof(sin);
	{
		int conn = accept(s, (struct sockaddr *)&sin, &slen);
		if (conn >= 0)
			close(conn);
	}

	(void)shutdown(s, SHUT_RDWR);

	ok = true;
out:
	if (s >= 0)
		close(s);
	if (valid_op)
		childop_direct_syscalls_add(op, 1);
	return ok;
}

/*
 * Recipe 13: POSIX message queue lifecycle.
 *
 * mq_open(O_CREAT | O_EXCL) → mq_send → mq_receive → mq_close →
 * mq_unlink.  CONFIG_POSIX_MQUEUE may be off on stripped-down kernels
 * — first failure with ENOSYS or ENOENT (mqueue not mounted) latches
 * the recipe off via *unsupported.
 *
 * The queue name embeds mypid() to keep concurrent recipe runs in
 * sibling children from racing on a shared name; O_EXCL gives us a
 * second layer of safety against name collisions on retry.
 */
bool recipe_mq_open(bool *unsupported)
{
	struct childdata *child = this_child();
	const enum child_op_type op = child ? child->op_type :
		NR_CHILD_OP_TYPES;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	struct mq_attr attr;
	char qname[64];
	mqd_t q = (mqd_t)-1;
	char buf[128];
	bool ok = false;

	snprintf(qname, sizeof(qname), "/trinity-recipe-%d-%u",
		 (int)mypid(), rnd_u32());

	memset(&attr, 0, sizeof(attr));
	attr.mq_maxmsg = 4;
	attr.mq_msgsize = 64;
	q = mq_open(qname, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK,
		    0600, &attr);
	if (q == (mqd_t)-1) {
		if (errno == ENOSYS || errno == ENOENT) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe.unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (mq_send(q, "trinity", 7, 0) < 0)
		goto out;

	if (mq_receive(q, buf, sizeof(buf), NULL) < 0)
		goto out;

	if (mq_close(q) < 0)
		goto out;
	q = (mqd_t)-1;

	if (mq_unlink(qname) < 0)
		goto out;

	ok = true;
out:
	if (q != (mqd_t)-1) {
		(void)mq_close(q);
		(void)mq_unlink(qname);
	}
	if (valid_op)
		childop_direct_syscalls_add(op, 1);
	return ok;
}

