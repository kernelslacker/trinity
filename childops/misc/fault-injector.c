/*
 * fault_injector - arm /proc/self/fail-nth to inject an allocation failure
 * at a random depth inside a single allocation-heavy syscall.
 *
 * Each invocation picks a random N in [1, 32], writes it to fail-nth (so the
 * Nth slab/page allocation inside the next syscall returns -ENOMEM), issues
 * one syscall from a curated set of allocation-heavy targets, then disarms
 * fail-nth by writing 0.  This exercises error-unwind paths that are
 * otherwise unreachable under normal memory conditions.
 *
 * Requires CONFIG_FAULT_INJECTION (and CONFIG_FAILSLAB or
 * CONFIG_FAIL_PAGE_ALLOC) in the running kernel.  The fail_nth_fd is opened
 * once per child by open_fail_nth() in child.c; if it is -1 this op is a
 * no-op so the childop runs safely on kernels without fault injection support.
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/eventfd.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <fcntl.h>
#include <unistd.h>

#include "child.h"
#include "childop-outcome.h"
#include "syscall-gate.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"

static void arm_fail_nth(int fd, unsigned int n)
{
	char buf[16];
	int len;
	ssize_t r __attribute__((unused));

	len = snprintf(buf, sizeof(buf), "%u\n", n);
	r = write(fd, buf, (size_t)len);
}

static void disarm_fail_nth(int fd)
{
	ssize_t r __attribute__((unused));

	r = write(fd, "0\n", 2);
}

/*
 * Issue one allocation-heavy syscall.  Returns the raw return value so the
 * caller can check whether the injected fault actually triggered (-ENOMEM).
 * Any fds or mappings created by a successful syscall are closed/unmapped
 * immediately; the point is to exercise the allocation path, not to hold
 * resources.
 *
 * *syscalls is incremented by the number of real syscalls this dispatch
 * issued -- 1 for the alloc attempt itself, plus 1 per teardown call
 * (close/munmap/msgctl/semctl/shmctl) that actually fired.  The caller
 * aggregates this across arm/disarm into a single childop_direct_syscalls_add.
 */
static long do_alloc_syscall(unsigned long *syscalls)
{
	static const unsigned int nr_targets = 10;
	int fds[2];
	long ret;
	void *p;

	switch (rnd_modulo_u32(nr_targets)) {
	case 0:
		/* open: dentry + inode allocation */
		ret = open("/dev/null", O_RDONLY);
		*syscalls += 1;
		if (ret >= 0) {
			close((int)ret);
			*syscalls += 1;
		}
		break;
	case 1:
		/* mmap anonymous: vm_area_struct + page table allocation */
		p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		*syscalls += 1;
		ret = (p == MAP_FAILED) ? -1L : 0L;
		if (p != MAP_FAILED) {
			munmap(p, 4096);
			*syscalls += 1;
		}
		break;
	case 2:
		/* socket: sock + sk allocation */
		ret = socket(AF_INET, SOCK_STREAM, 0);
		*syscalls += 1;
		if (ret >= 0) {
			close((int)ret);
			*syscalls += 1;
		}
		break;
	case 3:
		/* pipe: two file structs + pipe_inode_info */
		ret = pipe(fds);
		*syscalls += 1;
		if (ret == 0) {
			close(fds[0]);
			close(fds[1]);
			*syscalls += 2;
		}
		break;
	case 4:
		/* eventfd: file + eventfd_ctx allocation */
		ret = eventfd(0, (int)RAND_NEGATIVE_OR(0));
		*syscalls += 1;
		if (ret >= 0) {
			close((int)ret);
			*syscalls += 1;
		}
		break;
	case 5:
		/* timerfd_create: file + timerfd_ctx allocation */
		ret = timerfd_create(CLOCK_MONOTONIC, 0);
		*syscalls += 1;
		if (ret >= 0) {
			close((int)ret);
			*syscalls += 1;
		}
		break;
	case 6:
		/* memfd_create: tmpfs inode + file allocation */
		ret = (long)trinity_raw_syscall(__NR_memfd_create, "t", 0U);
		*syscalls += 1;
		if (ret >= 0) {
			close((int)ret);
			*syscalls += 1;
		}
		break;
	case 7:
		/* msgget: msg_queue allocation */
		ret = msgget(IPC_PRIVATE, 0600);
		*syscalls += 1;
		if (ret >= 0) {
			msgctl((int)ret, IPC_RMID, NULL);
			*syscalls += 1;
		}
		break;
	case 8:
		/* semget: sem_array allocation */
		ret = semget(IPC_PRIVATE, 1, 0600);
		*syscalls += 1;
		if (ret >= 0) {
			semctl((int)ret, 0, IPC_RMID);
			*syscalls += 1;
		}
		break;
	case 9:
		/* shmget: shmem inode + shm_info allocation */
		ret = shmget(IPC_PRIVATE, 4096, 0600);
		*syscalls += 1;
		if (ret >= 0) {
			shmctl((int)ret, IPC_RMID, NULL);
			*syscalls += 1;
		}
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

bool fault_injector(struct childdata *child)
{
	unsigned int n;
	long ret;
	/* Local direct-syscall tally.  Bumped by arm_fail_nth (1 write),
	 * do_alloc_syscall (1 alloc attempt + teardown fds/mappings), and
	 * disarm_fail_nth (1 write); published once at op-exit via
	 * childop_direct_syscalls_add() so the hot path pays one atomic
	 * add per invocation instead of per syscall.  The fail_nth_fd == -1
	 * early return path issues no real syscalls and therefore is not
	 * credited.  Mirrors the pipe-thrash reporter pattern. */
	unsigned long direct_calls = 0;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (child->fail_nth_fd == -1)
		return true;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* N=0 disables fail-nth; pick from [1, 32]. */
	n = 1 + rnd_modulo_u32(32);

	arm_fail_nth(child->fail_nth_fd, n);
	direct_calls += 1;

	stats_ring_enqueue(child->stats_ring, STATS_FIELD_FAULT_INJECTED, 0, 1);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	ret = do_alloc_syscall(&direct_calls);
	int saved_errno = errno;

	disarm_fail_nth(child->fail_nth_fd);
	direct_calls += 1;

	if (ret == -1 && saved_errno == ENOMEM)
		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_FAULT_CONSUMED, 0, 1);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
