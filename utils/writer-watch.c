/*
 * writer-watch.c -- Stage-2 hardware watchpoint for the writer-pinning
 * canary, mate to the Stage-1 --writer-pin-sweep detector.  --writer-watch
 * takes a hex address and arms a perf_event_open() HW write breakpoint on it
 * in every child; a hit raises a synchronous SIGTRAP at the writing
 * instruction, which writer_trap_handler() in health/ reports.
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>		/* close, getpid */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <string.h>

#include "fd.h"			/* fd_relocate_high */
#include "params.h"
#include "syscall-gate.h"	/* trinity_raw_syscall */
#include "trinity.h"		/* outputerr */
#include "utils.h"
#include "writer-watch.h"

#include "kernel/hw_breakpoint.h"
/*
 * Per-child fd for the open perf event, from writer_watch_open_child()
 * until writer_watch_arm_child() enables it; the child then holds it for
 * its lifetime and the kernel cleans it up at exit.  Each child opens its
 * own after fork because perf events do NOT propagate across fork to
 * track the child.  Parked above PROTECTED_FD_HIGH_BASE, out of the
 * numbers the fd pickers and mutated fd args reach.
 */
static int writer_watch_fd = -1;

/* perf_event_open() of the breakpoint on this task, disabled, or -1 with
 * errno set. */
static long writer_watch_open(void)
{
	struct perf_event_attr a;

	/*
	 * memset before partial fill: perf_event_attr is large and grows
	 * across kernel versions; uninitialised tail bytes would be
	 * forwarded to the kernel and rejected (EINVAL) or, worse,
	 * interpreted as a different attribute by a future kernel.
	 */
	memset(&a, 0, sizeof(a));
	a.type           = PERF_TYPE_BREAKPOINT;
	a.size           = sizeof(a);
	a.bp_type        = HW_BREAKPOINT_W;
	a.bp_addr        = (uint64_t)writer_watch_addr;
	a.bp_len         = HW_BREAKPOINT_LEN_8;
	/*
	 * sample_period=1 + sigtrap=1: deliver a sample on every hit, and
	 * route it as a SYNCHRONOUS SIGTRAP via the kernel signal machinery
	 * (TRAP_PERF si_code), NOT via fd async-IO notification.  This is
	 * the path that makes info->si_addr meaningful and puts the
	 * faulting RIP in the ucontext -- the alternative (F_SETSIG on a
	 * SIGIO fd) delivers asynchronously and si_addr is unrelated to
	 * the watched address.  sigtrap=1 was added in Linux 5.13, and
	 * perf_copy_attr() refuses it without remove_on_exec.
	 */
	a.sample_period  = 1;
	a.sigtrap        = 1;
	a.remove_on_exec = 1;
	a.sig_data       = (uint64_t)writer_watch_addr;
	/*
	 * exclude_kernel=0: count writes from kernel context too, so a
	 * value-result copy_to_user landing in the watched address is
	 * caught alongside trinity-userspace scribbles.  This directly
	 * answers the open question of whether the wild writer is trinity-
	 * side or kernel-side.  perf_event_open() takes it only from a
	 * caller with CAP_PERFMON, or with perf_event_paranoid <= 1.
	 */
	a.exclude_kernel = 0;
	a.exclude_hv     = 1;
	/*
	 * disabled=1 at open, ENABLE via ioctl AFTER any post-open setup
	 * completes.  Even though sigtrap=1 removes the fcntl ownership
	 * dance, opening disabled keeps the arm/enable boundary explicit
	 * and matches the cautious perf-breakpoint idiom -- the watchpoint
	 * cannot fire on the parent's address space, on the trinity_raw_
	 * syscall return path, or on anything that runs between open and
	 * the explicit ENABLE.
	 */
	a.disabled       = 1;

	/*
	 * (pid=0, cpu=-1): attach to THIS thread on any CPU.  Trinity
	 * children are single-threaded after fork; "this thread" == "this
	 * process".  group_fd=-1: standalone event.
	 */
	return trinity_raw_syscall(__NR_perf_event_open, &a, 0, -1, -1, 0UL);
}

bool writer_watch_probe(void)
{
	long fd;

	if (writer_watch_addr == 0)
		return true;

	/*
	 * HW_BREAKPOINT_LEN_8 takes only an 8-byte aligned address; say so
	 * rather than pass on the kernel's bare EINVAL.
	 */
	if ((writer_watch_addr & 0x7UL) != 0) {
		outputerr("--writer-watch: addr=0x%lx is not 8-byte aligned"
			  " (HW_BREAKPOINT_LEN_8 requires 8-byte alignment)\n",
			  writer_watch_addr);
		return false;
	}

	fd = writer_watch_open();
	if (fd < 0) {
		outputerr("--writer-watch: perf_event_open(addr=0x%lx) failed: %s%s\n",
			  writer_watch_addr, strerror(errno),
			  errno == EACCES ? " (watching kernel writes needs"
			  " CAP_PERFMON or perf_event_paranoid <= 1)" : "");
		return false;
	}
	(void)close((int)fd);
	return true;
}

void writer_watch_open_child(void)
{
	long fd;

	if (writer_watch_addr == 0)
		return;

	fd = writer_watch_open();
	if (fd < 0) {
		outputerr("writer-watch: perf_event_open(addr=0x%lx) failed: %s\n",
			  writer_watch_addr, strerror(errno));
		return;
	}
	writer_watch_fd = fd_relocate_high((int)fd);
}

void writer_watch_arm_child(void)
{
	if (writer_watch_fd < 0)
		return;

	if (ioctl(writer_watch_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		outputerr("writer-watch: PERF_EVENT_IOC_ENABLE failed: %s\n",
			  strerror(errno));
		(void)close(writer_watch_fd);
		writer_watch_fd = -1;
		return;
	}

	outputerr("writer-watch: armed addr=0x%lx fd=%d pid=%d"
		  " (HW write breakpoint, synchronous SIGTRAP on hit"
		  " via perf_event_attr.sigtrap)\n",
		  writer_watch_addr, writer_watch_fd, getpid());
}

int writer_watch_child_fd(void)
{
	return writer_watch_fd;
}
