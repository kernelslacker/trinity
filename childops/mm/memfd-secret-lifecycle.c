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
 *   6. fork() oracle child -- creates its own secret + anon mappings,
 *      sets PR_SET_DUMPABLE so the parent can ptrace-read it, sends
 *      both addresses back to the parent via a pipe, then sleeps;
 *      parent attempts cross-process reads and waits for the child
 *   7. mremap(buf, size, size*2, MREMAP_MAYMOVE) -- extend
 *   8. mprotect(buf, PAGE_SIZE, PROT_READ) -- partial protection
 *   9. munmap + close(fd) -- teardown; stop concurrent thread
 *
 * Cross-process confidentiality oracle (run by the PARENT):
 *
 *   The oracle child creates a secretmem mapping and a plain anon
 *   mapping in its own address space, marks itself dumpable, then
 *   delivers both addresses to the parent via a pipe.  The parent
 *   attempts cross-process reads via two independent paths:
 *
 *     Path A: process_vm_readv(oracle_pid, ...)
 *     Path B: open(/proc/<oracle_pid>/mem) + pread
 *
 *   For each path a mandatory positive control is run first: the same
 *   read is attempted against the plain anon mapping.  If the control
 *   read fails the environment -- not secretmem -- is doing the
 *   denying, and the result is counted as oracle_inconclusive.  Only
 *   when the control read succeeds is the secretmem read meaningful:
 *   success => oracle_fired (kernel bug); denial => oracle_pass.
 *
 * Counters in shm->stats.memfd_secret_lifecycle:
 *   oracle_pass           -- secretmem reads correctly denied
 *   oracle_fired          -- secretmem reads incorrectly succeeded (bug)
 *   oracle_inconclusive   -- positive-control or setup prevented oracle
 *   conc_truncate_races   -- concurrent ftruncate completions
 *   setup_rejected        -- memfd_secret not available (ENOSYS/EINVAL)
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
#include <sys/prctl.h>
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

/* Size of the secretmem probe region created by the oracle child. */
#define ORACLE_PROBE_SIZE	64U

/* ------------------------------------------------------------------ */
/* Process-local latch: set once on ENOSYS/EINVAL; stops re-probing.  */
/* ------------------------------------------------------------------ */

static bool secret_unsupported;

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
		__atomic_add_fetch(&shm->stats.memfd_secret_lifecycle.conc_truncate_races,
				   1, __ATOMIC_RELAXED);
	}
	ctx->syscall_count = sc;
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Oracle message: child delivers its mapping addresses to the parent  */
/* ------------------------------------------------------------------ */

struct oracle_msg {
	void *secret_addr;	/* secretmem mmap, or NULL on setup failure */
	void *anon_addr;	/* plain anon mmap (positive-control target) */
};

/* ------------------------------------------------------------------ */
/* Oracle child: create secret + anon mappings, hand addresses to      */
/* parent for cross-process read attempts, then sleep.                 */
/* ------------------------------------------------------------------ */

static void __attribute__((noreturn))
oracle_child_fn(int pipefd_wr, enum child_op_type op)
{
	struct oracle_msg msg = { NULL, NULL };
	unsigned long direct_calls = 0;
	int sfd;

	/* Create a secretmem mapping owned by this child process. */
	direct_calls++;
	sfd = do_memfd_secret(O_CLOEXEC);
	if (sfd >= 0) {
		direct_calls++;
		if (ftruncate(sfd, (off_t)ORACLE_PROBE_SIZE) == 0) {
			void *sm;

			direct_calls++;
			sm = mmap(NULL, ORACLE_PROBE_SIZE,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED, sfd, 0);
			if (sm != MAP_FAILED) {
				memset(sm, CANARY_BYTE, ORACLE_PROBE_SIZE);
				msg.secret_addr = sm;
			}
		}
		close(sfd);
	}

	/* Create a plain anon mapping as the positive-control target. */
	{
		void *am;

		direct_calls++;
		am = mmap(NULL, ORACLE_PROBE_SIZE,
			  PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (am != MAP_FAILED) {
			memset(am, (unsigned char)(CANARY_BYTE ^ 0x55u),
			       ORACLE_PROBE_SIZE);
			msg.anon_addr = am;
		}
	}

	/* Allow the parent to ptrace-read this process for the check.
	 * The trinity harness has already called PR_SET_DUMPABLE(false)
	 * on the parent; the child inherits that but overrides it here so
	 * parent->child process_vm_readv / /proc/pid/mem can succeed. */
	direct_calls++;
	(void)prctl(PR_SET_DUMPABLE, 1);

	/* Deliver both mapping addresses; keep them alive for the
	 * duration of the parent's oracle reads. */
	{
		__attribute__((unused)) ssize_t wr =
			write(pipefd_wr, &msg, sizeof(msg));
	}
	close(pipefd_wr);

	{
		struct timespec ts = { 0, (long)ORACLE_BUDGET_NS };

		(void)nanosleep(&ts, NULL);
	}

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

	/* ---- fast exit if already latched as unsupported ----------- */
	if (secret_unsupported)
		return false;

	/* ---- availability probe ------------------------------------ */
	direct_calls++;
	fd = do_memfd_secret(O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			secret_unsupported = true;
			if (valid_op) {
				__atomic_store_n(
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

	direct_calls++;
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
	{
		int pipefds[2];
		struct oracle_msg omsg = { NULL, NULL };
		struct timespec pipe_start;
		bool got_msg = false;

		if (pipe2(pipefds, O_CLOEXEC) < 0)
			pipefds[0] = pipefds[1] = -1;

		direct_calls++;
		oracle_pid = fork();
		if (oracle_pid == 0) {
			/* Oracle child: close read end and hand off. */
			if (pipefds[0] >= 0)
				close(pipefds[0]);
			oracle_child_fn(pipefds[1] >= 0 ? pipefds[1] : -1,
					op);
			/* NOTREACHED */
		}

		/* Parent: close write end, read address message. */
		if (pipefds[1] >= 0)
			close(pipefds[1]);

		if (oracle_pid > 0 && pipefds[0] >= 0) {
			ssize_t nr;

			clock_gettime(CLOCK_MONOTONIC, &pipe_start);
			fcntl(pipefds[0], F_SETFL, O_NONBLOCK);
			do {
				nr = read(pipefds[0], &omsg, sizeof(omsg));
			} while (nr < 0 && errno == EAGAIN &&
				 !budget_elapsed_ns(&pipe_start,
						    ORACLE_BUDGET_NS / 4));
			if (nr == (ssize_t)sizeof(omsg))
				got_msg = true;
		}
		if (pipefds[0] >= 0)
			close(pipefds[0]);

		/* ---- positive-control + confidentiality oracle -------- */
		if (oracle_pid > 0) {
			if (!got_msg || !omsg.anon_addr || !omsg.secret_addr) {
				/* Setup failed in child; cannot run oracle. */
				if (valid_op)
					__atomic_add_fetch(
						&shm->stats.memfd_secret_lifecycle.oracle_inconclusive,
						1, __ATOMIC_RELAXED);
			} else {
				char tbuf[ORACLE_PROBE_SIZE];
				struct iovec liov, riov;
				ssize_t r;

				/* -- process_vm_readv arm -------------------- */
				liov.iov_base = tbuf;
				liov.iov_len  = sizeof(tbuf);

				/* Positive control: anon page must be readable
				 * before the secretmem result is meaningful. */
				riov.iov_base = omsg.anon_addr;
				riov.iov_len  = sizeof(tbuf);
				direct_calls++;
				r = syscall(__NR_process_vm_readv,
					    (long)oracle_pid,
					    &liov, 1UL, &riov, 1UL, 0UL);
				if (r <= 0) {
					/* Anon read denied: attribute to
					 * ambient policy, not secretmem. */
					if (valid_op)
						__atomic_add_fetch(
							&shm->stats.memfd_secret_lifecycle.oracle_inconclusive,
							1, __ATOMIC_RELAXED);
				} else {
					/* Control passed: now probe secretmem. */
					riov.iov_base = omsg.secret_addr;
					riov.iov_len  = sizeof(tbuf);
					direct_calls++;
					r = syscall(__NR_process_vm_readv,
						    (long)oracle_pid,
						    &liov, 1UL,
						    &riov, 1UL, 0UL);
					if (r > 0) {
						/* check-static: child-output-ok */
						outputerr("memfd_secret: content"
							  " readable cross-process"
							  " via process_vm_readv"
							  " -- oracle fired\n");
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
				}

				/* -- /proc/<pid>/mem arm --------------------- */
				{
					char path[80];
					int pmfd;

					(void)snprintf(path, sizeof(path),
						       "/proc/%d/mem",
						       (int)oracle_pid);
					direct_calls++;
					pmfd = open(path,
						    O_RDONLY | O_NONBLOCK |
						    O_CLOEXEC);
					if (pmfd >= 0) {
						/* Positive control: anon page. */
						direct_calls++;
						r = pread(pmfd, tbuf,
							  sizeof(tbuf),
							  (off_t)(uintptr_t)omsg.anon_addr);
						if (r <= 0) {
							/* Anon denied: inconclusive. */
							if (valid_op)
								__atomic_add_fetch(
									&shm->stats.memfd_secret_lifecycle.oracle_inconclusive,
									1, __ATOMIC_RELAXED);
						} else {
							/* Control passed: probe secretmem. */
							direct_calls++;
							r = pread(pmfd, tbuf,
								  sizeof(tbuf),
								  (off_t)(uintptr_t)omsg.secret_addr);
							if (r > 0) {
								/* check-static: child-output-ok */
								outputerr("memfd_secret: content"
									  " readable cross-process"
									  " via /proc/pid/mem"
									  " -- oracle fired\n");
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
						}
						direct_calls++;
						close(pmfd);
					} else {
						/* /proc/pid/mem open failed:
						 * cannot attribute to secretmem. */
						if (valid_op)
							__atomic_add_fetch(
								&shm->stats.memfd_secret_lifecycle.oracle_inconclusive,
								1, __ATOMIC_RELAXED);
					}
				}
			}

			/* ---- wait for oracle child, bounded ----------- */
			while (1) {
				pid_t wr = waitpid_eintr(oracle_pid,
							 &status, WNOHANG);

				direct_calls++;
				if (wr == oracle_pid)
					break;
				if (wr < 0 && errno != EINTR) {
					(void)kill(oracle_pid, SIGKILL);
					(void)waitpid_eintr(oracle_pid,
							    &status, 0);
					break;
				}
				if (budget_elapsed_ns(&start,
						      ORACLE_BUDGET_NS)) {
					(void)kill(oracle_pid, SIGKILL);
					(void)waitpid_eintr(oracle_pid,
							    &status, 0);
					break;
				}
				{
					struct timespec ts = { 0, 500000L };

					(void)nanosleep(&ts, NULL);
				}
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
