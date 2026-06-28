/*
 * writer-watch.c -- Stage-2 hardware watchpoint for the writer-pinning
 * canary.  Mate to the Stage-1 sweep in minicorpus.c / syscall.c.
 *
 * The flag --writer-watch=<hexaddr> arms a perf_event_open() hardware
 * WRITE breakpoint (PERF_TYPE_BREAKPOINT / HW_BREAKPOINT_W) on the
 * passed address in every fuzz child.  A write to that address traps
 * synchronously, in the writing child, at the exact instruction.  The
 * SIGTRAP is delivered via F_SETSIG to writer_trap_handler() in
 * signals.c, which dumps the writer's RIP, syscall nr, childop name,
 * op_nr and pid -- the exact wild writer, with no race.
 *
 * exclude_kernel=0 so kernel-side value-result writes (copy_to_user
 * through a fuzzed pointer that lands in the watched address) trap too.
 *
 * Default-OFF: writer_watch_addr stays 0 unless --writer-watch was
 * passed, and writer_watch_arm_child() short-circuits on 0.  Hardware
 * supports up to four breakpoints (DR0-DR3 on x86); this code arms ONE.
 *
 * Heavyweight debug tool -- default off, only enable for a targeted
 * corruption hunt.  The perf fd costs real resources and the trap
 * handler _exit()s on hit; not appropriate for routine fuzzing.
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>		/* close, getpid */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include "params.h"
#include "syscall-gate.h"	/* trinity_raw_syscall */
#include "trinity.h"		/* outputerr */
#include "utils.h"
#include "writer-watch.h"

/*
 * Per-child fd for the open perf event.  Kept at file scope so a future
 * teardown helper could close it; currently the child holds it for its
 * lifetime and the kernel cleans it up at exit.  Inherited COW from
 * the parent only by accident -- the parent never opens one; each
 * child arms its own after fork because perf events do NOT propagate
 * across fork to track the child.
 */
static int writer_watch_fd = -1;

void writer_watch_arm_child(void)
{
	struct perf_event_attr a;
	long fd;

	if (writer_watch_addr == 0)
		return;

	/*
	 * Validate 8-byte alignment up front.  Most x86 implementations
	 * reject an unaligned HW_BREAKPOINT_LEN_8 with -EINVAL from
	 * perf_event_open(); failing loudly here points the operator at
	 * the real cause instead of a kernel error message.
	 */
	if ((writer_watch_addr & 0x7UL) != 0) {
		outputerr("writer-watch: addr=0x%lx is not 8-byte aligned"
			  " (HW_BREAKPOINT_LEN_8 requires 8-byte alignment)\n",
			  writer_watch_addr);
		return;
	}

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
	 * the watched address.  sigtrap=1 was added in Linux 5.13.
	 */
	a.sample_period  = 1;
	a.sigtrap        = 1;
	a.sig_data       = (uint64_t)writer_watch_addr;
	/*
	 * exclude_kernel=0: count writes from kernel context too, so a
	 * value-result copy_to_user landing in the watched address is
	 * caught alongside trinity-userspace scribbles.  This directly
	 * answers the open question of whether the wild writer is trinity-
	 * side or kernel-side.
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
	fd = trinity_raw_syscall(__NR_perf_event_open, &a, 0, -1, -1, 0UL);
	if (fd < 0) {
		outputerr("writer-watch: perf_event_open(addr=0x%lx) failed: %s\n",
			  writer_watch_addr, strerror(errno));
		return;
	}

	if (ioctl((int)fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		outputerr("writer-watch: PERF_EVENT_IOC_ENABLE failed: %s\n",
			  strerror(errno));
		(void)close((int)fd);
		return;
	}

	writer_watch_fd = (int)fd;
	outputerr("writer-watch: armed addr=0x%lx fd=%d pid=%d"
		  " (HW write breakpoint, synchronous SIGTRAP on hit"
		  " via perf_event_attr.sigtrap)\n",
		  writer_watch_addr, writer_watch_fd, getpid());
}
