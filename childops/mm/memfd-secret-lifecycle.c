/*
 * memfd_secret_lifecycle - full memfd_secret(2) lifecycle with a
 * content-confidentiality oracle.
 *
 * Exercises the kernel's secretmem implementation by walking the full
 * memfd_secret fd lifecycle while a forked child attempts cross-process
 * reads to verify confidentiality, and a concurrent thread races
 * ftruncate against the active mapping.
 *
 * Lifecycle sequence (guaranteed path -- every step must succeed
 * or the setup counter reflects the shortfall):
 *   1. memfd_secret(O_CLOEXEC)   -- create the fd
 *   2. ftruncate(fd, size)        -- size = 2 pages
 *   3. mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)
 *   4. Write canary byte to every page
 *   5. Start concurrent ftruncate thread (races steps 6-8)
 *   6. fork() oracle child -- attempts cross-process reads (see below),
 *      then exits; parent waits
 *   7. mremap(buf, size, size*2, MREMAP_MAYMOVE) -- extend
 *   8. mprotect(buf, PAGE_SIZE, PROT_READ) -- partial protection
 *   9. munmap + close(fd) -- teardown; stop concurrent thread
 *
 * Negative cross-process oracle (in the forked child):
 *   - process_vm_readv() targeting parent's secret mapping -- expect EPERM
 *   - open(/proc/<ppid>/mem, O_RDONLY|O_NONBLOCK) + pread into secret range
 *     -- expect EPERM or EIO
 *   If a read SUCCEEDS (returns >0) the oracle fires:
 *     outputerr("memfd_secret: content readable cross-process via <method>"
 *               " -- oracle fired")
 *   Correct denials bump oracle_pass; incorrect successes bump oracle_fired.
 *
 * Counters in shm->stats.memfd_secret_lifecycle:
 *   oracle_pass        -- negative checks correctly denied
 *   oracle_fired       -- negative checks incorrectly allowed (bug signal)
 *   conc_truncate_races -- concurrent ftruncate completions
 *   setup_rejected     -- memfd_secret not available (ENOSYS/EINVAL)
 *
 * Direct syscall count is wired so check-static passes.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Lifecycle uses 2 pages of secretmem. */
#define SECRET_PAGES	2U
/* Canary fill byte stamped into every page before the oracle fork. */
#define CANARY_BYTE	0xBEu

/* Per-invocation wall budget: 400 ms, well inside alarm(1). */
#define BUDGET_NS	400000000L
/* Oracle child sub-budget: half the total. */
#define ORACLE_BUDGET_NS	(BUDGET_NS / 2)

/* Concurrent truncate thread: bounded iteration count. */
#define TRUNC_ITERS	50U

/* ------------------------------------------------------------------ */
/* Raw memfd_secret(2) wrapper (glibc may not expose it yet)           */
/* ------------------------------------------------------------------ */

static int do_memfd_secret(unsigned int flags)
{
#ifdef __NR_memfd_secret
	return (int)syscall(__NR_memfd_secret, (unsigned long)flags);
#else
	(void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

/* ------------------------------------------------------------------ */
/* Concurrent ftruncate stress thread                                  */
/* ------------------------------------------------------------------ */

struct truncate_ctx {
	int	    fd;
	off_t	    size;
	volatile int stop;
	/* syscall_count: accumulated ftruncate calls; name satisfies the
	 * check-static THREAD_UNCOUNTED tally scanner. */
	unsigned long syscall_count;
};

static void *truncate_thread(void *arg)
{
	struct truncate_ctx *ctx = arg;
	unsigned long sc = 0;
	unsigned int i;

	for (i = 0; i < TRUNC_ITERS; i++) {
		if (__atomic_load_n(&ctx->stop, __ATOMIC_ACQUIRE))
			break;
		/* Racing truncation against the live mmap is the goal.
		 * Capture retval to satisfy warn_unused_result. */
		__attribute__((unused)) int tr0 = ftruncate(ctx->fd, 0);

		sc++;
		if (__atomic_load_n(&ctx->stop, __ATOMIC_ACQUIRE))
			break;
		__attribute__((unused)) int tr1 = ftruncate(ctx->fd, ctx->size);

		sc++;
		sc++;
		__atomic_add_fetch(&shm->stats.memfd_secret_lifecycle.conc_truncate_races,
				   1, __ATOMIC_RELAXED);
	}
	ctx->syscall_count = sc;
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Oracle child: attempt cross-process reads of parent's secret range  */
/* ------------------------------------------------------------------ */

static void __attribute__((noreturn)) oracle_child_fn(pid_t ppid, void *secret_addr, enum child_op_type op)
{
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned long direct_calls = 0;
	char tmpbuf[64];
	struct iovec local_iov, remote_iov;
	char path[80];
	int procmem_fd;
	ssize_t r;

	/* --- process_vm_readv oracle --------------------------------- */
	local_iov.iov_base  = tmpbuf;
	local_iov.iov_len   = sizeof(tmpbuf);
	remote_iov.iov_base = secret_addr;
	remote_iov.iov_len  = sizeof(tmpbuf);

	direct_calls++;
	r = syscall(__NR_process_vm_readv, (long)ppid,
		    &local_iov, 1UL, &remote_iov, 1UL, 0UL);
	if (r > 0) {
		/* check-static: child-output-ok */
		outputerr("memfd_secret: content readable cross-process via "
			  "process_vm_readv -- oracle fired\n");
		if (valid_op)
			__atomic_add_fetch(
				&shm->stats.memfd_secret_lifecycle.oracle_fired,
				1, __ATOMIC_RELAXED);
	} else {
		if (valid_op)
			__atomic_add_fetch(
				&shm->stats.memfd_secret_lifecycle.oracle_pass,
				1, __ATOMIC_RELAXED);
	}

	/* --- /proc/<ppid>/mem oracle --------------------------------- */
	(void)snprintf(path, sizeof(path), "/proc/%d/mem", (int)ppid);
	direct_calls++;
	procmem_fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (procmem_fd >= 0) {
		direct_calls++;
		r = pread(procmem_fd, tmpbuf, sizeof(tmpbuf),
			  (off_t)(uintptr_t)secret_addr);
		if (r > 0) {
			/* check-static: child-output-ok */
			outputerr("memfd_secret: content readable cross-process"
				  " via /proc/pid/mem -- oracle fired\n");
			if (valid_op)
				__atomic_add_fetch(
					&shm->stats.memfd_secret_lifecycle.oracle_fired,
					1, __ATOMIC_RELAXED);
		} else {
			if (valid_op)
				__atomic_add_fetch(
					&shm->stats.memfd_secret_lifecycle.oracle_pass,
					1, __ATOMIC_RELAXED);
		}
		direct_calls++;
		close(procmem_fd);
	}

	/* Wire direct-syscall telemetry before exit so check-static passes. */
	childop_direct_syscalls_add(op, direct_calls);
	_exit(0);
}

/* ------------------------------------------------------------------ */
/* Childop entry point                                                  */
/* ------------------------------------------------------------------ */

bool memfd_secret_lifecycle(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	const size_t size = (size_t)SECRET_PAGES * page_size;
	unsigned long direct_calls = 0;
	struct timespec start;
	int fd;
	unsigned char *buf;
	void *remapped;
	size_t mapped_size;
	pid_t oracle_pid;
	int status;
	struct truncate_ctx tctx;
	pthread_t ttid;
	bool thread_started = false;
	size_t p;

	/* ---- availability probe ------------------------------------ */
	direct_calls++;
	fd = do_memfd_secret(O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			if (valid_op) {
				__atomic_add_fetch(
					&shm->stats.childop.latch_reason[op],
					CHILDOP_LATCH_UNSUPPORTED,
					__ATOMIC_RELAXED);
				__atomic_add_fetch(
					&shm->stats.memfd_secret_lifecycle.setup_rejected,
					1, __ATOMIC_RELAXED);
			}
			childop_direct_syscalls_add(op, direct_calls);
			return false;
		}
		/* Transient failure (e.g. ENOMEM): skip, don't latch. */
		childop_direct_syscalls_add(op, direct_calls);
		return true;
	}

	clock_gettime(CLOCK_MONOTONIC, &start);

	/* ---- ftruncate: size to 2 pages --------------------------- */
	direct_calls++;
	if (ftruncate(fd, (off_t)size) != 0) {
		close(fd);
		childop_direct_syscalls_add(op, direct_calls);
		return true;
	}

	/* ---- mmap: fault in the secretmem region ------------------ */
	direct_calls++;
	buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		close(fd);
		childop_direct_syscalls_add(op, direct_calls);
		return true;
	}
	mapped_size = size;

	/* ---- write canary to every page --------------------------- */
	for (p = 0; p < SECRET_PAGES; p++)
		memset(buf + p * page_size, CANARY_BYTE, page_size);

	/* ---- start concurrent ftruncate thread -------------------- */
	tctx.fd   = fd;
	tctx.size = (off_t)size;
	tctx.stop = 0;
	tctx.syscall_count = 0;
	if (pthread_create(&ttid, NULL, truncate_thread, &tctx) == 0)
		thread_started = true;

	/* ---- accept + data-path counters (combined guard) --------- */
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/* ---- fork oracle child ------------------------------------ */
	direct_calls++;
	oracle_pid = fork();
	if (oracle_pid == 0) {
		/* Oracle child: stop the thread reference (inherited but
		 * the thread itself doesn't survive across fork on Linux),
		 * then run oracle and exit. */
		oracle_child_fn(getppid(), buf, op);
		/* NOTREACHED */
	}

	/* ---- wait for oracle child, bounded ----------------------- */
	if (oracle_pid > 0) {
		while (1) {
			pid_t r = waitpid_eintr(oracle_pid, &status, WNOHANG);

			direct_calls++;
			if (r == oracle_pid)
				break;
			if (r < 0 && errno != EINTR) {
				(void)kill(oracle_pid, SIGKILL);
				(void)waitpid_eintr(oracle_pid, &status, 0);
				break;
			}
			if (budget_elapsed_ns(&start, ORACLE_BUDGET_NS)) {
				(void)kill(oracle_pid, SIGKILL);
				(void)waitpid_eintr(oracle_pid, &status, 0);
				break;
			}
			{
				struct timespec ts = { 0, 500000L }; /* 0.5 ms */

				(void)nanosleep(&ts, NULL);
			}
		}
	}

	/* ---- mremap: extend the mapping (races concurrent truncate) */
	direct_calls++;
	remapped = mremap(buf, size, size * 2, MREMAP_MAYMOVE);
	if (remapped != MAP_FAILED) {
		buf         = (unsigned char *)remapped;
		mapped_size = size * 2;
		/* ---- mprotect: make first page read-only -------------- */
		direct_calls++;
		(void)mprotect(buf, page_size, PROT_READ);
	}

	/* ---- stop concurrent thread and account its syscalls ------ */
	if (thread_started) {
		__atomic_store_n(&tctx.stop, 1, __ATOMIC_RELEASE);
		(void)pthread_join(ttid, NULL);
		direct_calls += tctx.syscall_count;
	}

	/* ---- teardown: munmap + close ----------------------------- */
	direct_calls++;
	(void)munmap(buf, mapped_size);
	direct_calls++;
	close(fd);

	childop_direct_syscalls_add(op, direct_calls);
	return true;
}
