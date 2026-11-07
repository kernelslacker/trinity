/*
 * Self-check for the --writer-watch breakpoint (utils/writer-watch.c): the
 * parent's probe passes the attr only when perf_event_open() would, a child
 * opens it disabled, parked above the picker range where the protected-fd
 * registry names it, and an enable that fails closes it.
 * perf_event_open() goes to a model of the kernel's checks through
 * fake_syscall.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/perf_event.h>

#include "debug.h"		/* BUG */
#include "fd.h"			/* fd_is_protected, PROTECTED_FD_HIGH_BASE */
#include "params.h"		/* writer_watch_addr */
#include "writer-watch.h"

/* Owned by main/params/state.c in production. */
unsigned long writer_watch_addr;

extern bool (*fake_syscall)(long number, const unsigned long a[6],
			    long *ret);	/* landlock_test.c */

static struct perf_event_attr opened;
static unsigned int calls;
static int last_fd = -1;
static bool may_watch_kernel;

/*
 * perf_event_open() as far as this attr goes: perf_copy_attr() refuses
 * sigtrap without remove_on_exec, and remove_on_exec with enable_on_exec,
 * with -EINVAL, and perf_allow_kernel() refuses an attr counting kernel
 * events with -EACCES unless perf_event_paranoid <= 1 or the caller holds
 * CAP_PERFMON (kernel/events/core.c).  What it takes gets an fd of
 * /dev/null, on which the enable fails.
 */
static bool model_perf_event_open(long number, const unsigned long a[6],
				  long *ret)
{
	const struct perf_event_attr *attr = (const void *) a[0];

	if (number != __NR_perf_event_open)
		return false;
	calls++;
	opened = *attr;
	if ((attr->sigtrap && !attr->remove_on_exec) ||
	    (attr->remove_on_exec && attr->enable_on_exec))
		*ret = -EINVAL;
	else if (!attr->exclude_kernel && !may_watch_kernel)
		*ret = -EACCES;
	else
		*ret = last_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return true;
}

void writer_watch_self_check(void);
void writer_watch_self_check(void)
{
	struct rlimit lim;
	bool can_park;
	int held;

	fake_syscall = model_perf_event_open;

	writer_watch_addr = 0x1000;
	may_watch_kernel = true;
	if (!writer_watch_probe())
		BUG("writer-watch: the probe refused a breakpoint the kernel takes");
	if (fcntl(last_fd, F_GETFD) != -1)
		BUG("writer-watch: the probe left its breakpoint open");

	may_watch_kernel = false;
	if (writer_watch_probe())
		BUG("writer-watch: the probe passed a breakpoint the kernel refuses");

	calls = 0;
	writer_watch_addr = 0x1004;
	may_watch_kernel = true;
	if (writer_watch_probe() || calls != 0)
		BUG("writer-watch: the probe sent an unaligned address to the kernel");

	/* Parking needs a soft RLIMIT_NOFILE past the base; under a lower
	 * one the breakpoint keeps its number, which the registry still has
	 * to name. */
	if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
		BUG("writer-watch: getrlimit failed");
	can_park = lim.rlim_cur == RLIM_INFINITY ||
		   lim.rlim_cur > PROTECTED_FD_HIGH_BASE;
	if (!can_park)
		fprintf(stderr, "writer-watch: RLIMIT_NOFILE %lu is not above %u, "
			"breakpoint relocation not checked\n",
			(unsigned long) lim.rlim_cur, PROTECTED_FD_HIGH_BASE);

	writer_watch_addr = 0x1000;
	writer_watch_open_child();
	if (calls != 1 || !opened.disabled)
		BUG("writer-watch: a child's breakpoint was not opened disabled");
	held = writer_watch_child_fd();
	if (held < 0 || !fd_is_protected(held) ||
	    lowest_protected_fd_in_range((unsigned int) held,
					 (unsigned int) held) != held)
		BUG("writer-watch: the protected-fd registry does not name the breakpoint");
	if (can_park && ((unsigned int) held < PROTECTED_FD_HIGH_BASE ||
			 fcntl(last_fd, F_GETFD) != -1))
		BUG("writer-watch: a child kept its breakpoint in the picker range");
	writer_watch_arm_child();
	if (fcntl(held, F_GETFD) != -1)
		BUG("writer-watch: a breakpoint whose enable failed stayed open");
	if (writer_watch_child_fd() != -1 || fd_is_protected(held))
		BUG("writer-watch: a closed breakpoint stayed protected");

	fake_syscall = NULL;
	writer_watch_addr = 0;
}
