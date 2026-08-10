#include <stddef.h>
#include <unistd.h>

#include "child.h"
#include "fd.h"
#include "pids.h"
#include "signals.h"
#include "syscall.h"
#include "taint.h"

/*
 * Protected-fd registry.  Argument generators for the close family
 * (close, dup2, dup3, close_range), the size-changing fd-arg sanitisers
 * (ftruncate / ftruncate64, fallocate, lseek / llseek, write / writev /
 * pwrite64 / pwritev / pwritev2 -- see reroll_protected_fd_arg()), and
 * the random-syscall chain-substitution path consult these predicates
 * to keep diagnostic and coverage fds out of the fuzz picker pool.
 * See the contract in include/fd.h.
 *
 * Four classes of fd live in this registry:
 *
 *   - the calling child's kcov PC fd and cmp fd, opened in
 *     kcov_init_child and re-located above KCOV_FD_HIGH_BASE so the
 *     low-slot ARG_FD pool never naturally hands them out -- but
 *     dup2's RAND_RANGE(rl.rlim_cur+1) and close_range's range walks
 *     can still reach them.  A successful close / dup2 over either
 *     slot silently disables coverage for the rest of the child's
 *     life (next ioctl(KCOV_ENABLE, ...) returns -ENOTTY).
 *
 *   - the calling child's per-childop taint watcher fd
 *     (child->tainted_fd, opened by open_tainted_fd) and, in parent
 *     context, the panic-check cached fd (trinity_tainted_fd_cached).
 *     Both name /proc/sys/kernel/tainted; open_tainted_fd also
 *     F_DUPFD_CLOEXEC-relocates its slot up to TAINTED_FD_HIGH_BASE
 *     for the same defence-in-depth reason kcov does.  A fuzz-induced
 *     rewire onto the taint fd makes the next taint read strtol() an
 *     unrelated file's contents into a fabricated taint bit that
 *     kills the run with EXIT_KERNEL_TAINTED (see health/taint.c and
 *     the block comment above tainted_fd_cached).  Registering both
 *     slots closes the last window where child-side fuzz syscalls
 *     could clobber a live taint fd -- child->tainted_fd stays live
 *     for the child's lifetime, and the parent's cache is registered
 *     for symmetry so parent-side arg gen never hands it out.
 *
 *   - the calling child's per-child fault-injection arm fd
 *     (child->fail_nth_fd, opened by open_fail_nth against
 *     /proc/self/fail-nth).  Written on the hot path by
 *     maybe_inject_fault() with the fault-count digit string that
 *     arms the next allocation-failure injection.  A fuzz-induced
 *     rewire onto this slot is strictly worse than the taint case:
 *     the next arm-write successfully stamps digit bytes into the
 *     victim file (data corruption) AND silently disables fault
 *     injection for the rest of this child's life.  open_fail_nth
 *     F_DUPFD_CLOEXEC-relocates the slot up to FAIL_NTH_FD_HIGH_BASE
 *     for the same defence-in-depth reason kcov / tainted_fd do; the
 *     registry entry here closes the residual window where a dup2 /
 *     dup3 / close_range pick could still land on the slot.
 *
 *   - STDERR_FILENO and the in-memory stderr capture memfd installed
 *     by init_stderr_memfd.  The SIGABRT handler drains the memfd
 *     into the per-pid bug log via read(memfd, ...) + write(fd 2, ...);
 *     if either fd is clobbered by a fuzz close-family syscall before
 *     the handler runs, the buffered glibc malloc_printerr /
 *     __fortify_fail / __stack_chk_fail text is lost and the bug log
 *     bottoms out at the in-handler backtrace + siginfo with no
 *     pre-crash explanation.  The same memfd must also be kept out of
 *     size-changing syscall slots: a fuzz-induced ftruncate / fallocate /
 *     pwrite64 / lseek+write that extends the memfd to a multi-GB
 *     sparse size makes the bug-log drain materialise that range into
 *     the on-disk log on the next abort, swamping the host.
 *
 * Parent context (this_child() == NULL): STDERR_FILENO still matches
 * the constant check, but the parent never opens a kcov_child, a
 * stderr memfd, a per-child tainted_fd, or a per-child fail_nth_fd,
 * so those branches naturally fall through.  The parent's own
 * trinity_tainted_fd_cached() slot is
 * still consulted here; parent-side arg generation is rare but the
 * conservative answer (treat the taint fd as protected) is the right
 * one regardless.
 *
 * The fd < 0 / hi < lo guards mirror the kernel-side validation order
 * the close-family syscalls themselves apply, so a sanitiser that
 * skipped its own bounds checks before consulting this registry would
 * still get a safe answer.
 */
bool fd_is_protected(int fd)
{
	struct childdata *child;
	int memfd;
	int taintfd;

	if (fd < 0)
		return false;
	if (fd == STDERR_FILENO)
		return true;
	memfd = trinity_stderr_memfd();
	if (memfd >= 0 && fd == memfd)
		return true;
	taintfd = trinity_tainted_fd_cached();
	if (taintfd >= 0 && fd == taintfd)
		return true;
	/* Not reached from fork grandchildren; this_child() returns the child's own slot. */
	child = this_child();
	if (child == NULL)
		return false;
	if (child->kcov.fd >= 0 && fd == child->kcov.fd)
		return true;
	if (child->kcov.cmp_fd >= 0 && fd == child->kcov.cmp_fd)
		return true;
	if (child->tainted_fd >= 0 && fd == child->tainted_fd)
		return true;
	if (child->fail_nth_fd >= 0 && fd == child->fail_nth_fd)
		return true;
	return false;
}

/*
 * Bounds typed as unsigned int to mirror the kernel's close_range ABI:
 * the syscall takes (unsigned int first, unsigned int last) and walks
 * the fd table when first <= last as unsigned.  A signed int
 * comparison here treats rec->a2 == (unsigned long)-1 (the gen_arg_fd
 * exhaustion fallback, which surfaces to the kernel as 0xFFFFFFFF) as
 * a negative "hi", makes hi < lo true, and returns -1 -- skipping the
 * truncation that should have stopped the kernel-side walk before it
 * reached the kcov fd at KCOV_FD_HIGH_BASE.  All real protected fds
 * fit in int (STDERR_FILENO is 2; KCOV_FD_HIGH_BASE is 60000; the
 * stderr memfd is well below INT_MAX), so widening the comparison
 * operand to unsigned int doesn't shrink the range we cover.
 */
int lowest_protected_fd_in_range(unsigned int lo, unsigned int hi)
{
	struct childdata *child;
	int memfd;
	int taintfd;
	int lowest = -1;

	if (hi < lo)
		return -1;

	if ((unsigned int) STDERR_FILENO >= lo &&
	    (unsigned int) STDERR_FILENO <= hi)
		lowest = STDERR_FILENO;

	memfd = trinity_stderr_memfd();
	if (memfd >= 0 &&
	    (unsigned int) memfd >= lo && (unsigned int) memfd <= hi)
		if (lowest < 0 || memfd < lowest)
			lowest = memfd;

	taintfd = trinity_tainted_fd_cached();
	if (taintfd >= 0 &&
	    (unsigned int) taintfd >= lo && (unsigned int) taintfd <= hi)
		if (lowest < 0 || taintfd < lowest)
			lowest = taintfd;

	/* Not reached from fork grandchildren; this_child() returns the child's own slot. */
	child = this_child();
	if (child != NULL) {
		if (child->kcov.fd >= 0 &&
		    (unsigned int) child->kcov.fd >= lo &&
		    (unsigned int) child->kcov.fd <= hi)
			if (lowest < 0 || child->kcov.fd < lowest)
				lowest = child->kcov.fd;
		if (child->kcov.cmp_fd >= 0 &&
		    (unsigned int) child->kcov.cmp_fd >= lo &&
		    (unsigned int) child->kcov.cmp_fd <= hi)
			if (lowest < 0 || child->kcov.cmp_fd < lowest)
				lowest = child->kcov.cmp_fd;
		if (child->tainted_fd >= 0 &&
		    (unsigned int) child->tainted_fd >= lo &&
		    (unsigned int) child->tainted_fd <= hi)
			if (lowest < 0 || child->tainted_fd < lowest)
				lowest = child->tainted_fd;
		if (child->fail_nth_fd >= 0 &&
		    (unsigned int) child->fail_nth_fd >= lo &&
		    (unsigned int) child->fail_nth_fd <= hi)
			if (lowest < 0 || child->fail_nth_fd < lowest)
				lowest = child->fail_nth_fd;
	}

	return lowest;
}

/*
 * Belt-and-suspenders gate for size-changing fd-arg syscalls
 * (ftruncate / ftruncate64, fallocate, lseek / llseek, write / writev /
 * pwrite64 / pwritev / pwritev2).  gen_arg_fd() already filters
 * fd_is_protected() picks out of the ARG_FD pool, but its bounded
 * reroll falls back to the last (possibly protected) draw on pool
 * exhaustion, and the per-syscall RAND_RANGE / typed-fd-pool buckets in
 * the size-changing sanitisers can independently land on a protected
 * slot.  Per-syscall sanitisers feed rec->a1 through this gate after
 * their own rewrites and before any snap->fd capture: if the slot
 * names a protected fd, reroll up to FAILED_FD_REROLL_LIMIT times via
 * get_random_fd(); on exhaustion stamp the slot with (unsigned long)-1
 * so the kernel returns EBADF and the call cannot extend the stderr
 * capture memfd (or any other trinity-internal fd) into a multi-GB
 * sparse file that the SIGABRT-handler bug-log drain would then
 * materialise into the on-disk log.  Refusing is correct -- these fds
 * are never legitimate fuzz targets.
 */
void reroll_protected_fd_arg(unsigned long *slot)
{
	int fd;
	unsigned int tries;

	if (slot == NULL)
		return;
	if (!fd_is_protected((int) *slot))
		return;

	for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
		fd = get_random_fd();
		if (!fd_is_protected(fd)) {
			*slot = (unsigned long) fd;
			return;
		}
	}
	*slot = (unsigned long) -1;
}
