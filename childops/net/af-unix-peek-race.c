/*
 * af_unix_peek_race - drive the AF_UNIX SOCK_STREAM SO_PEEK_OFF +
 * concurrent MSG_PEEK / plain-recv / shutdown race that reaches the
 * freed-tail path inside net/unix/af_unix.c:unix_stream_read_generic.
 *
 * Bug class: two tasks sharing an fd table contend on one unix_sock
 * receive queue -- a SO_PEEK_OFF/MSG_PEEK walker against a plain-recv
 * dequeuer + shutdown driver, so the peek walk can land on a tail skb
 * a concurrent recv() has just started freeing.  Existing af-unix
 * coverage exercises SCM_RIGHTS + unix_gc but never this triple.
 *
 * Per iteration: socketpair(SOCK_STREAM), SO_PEEK_OFF in
 * [0, UNIX_PEEK_OFF_MAX), pre-fill sv[1], clone(CLONE_FILES) a sibling
 * that tight-loops MSG_PEEK / plain recv on sv[0] while the parent
 * tight-loops send + occasional shutdown(SHUT_WR) on sv[1].  On EPIPE
 * the pair is re-created.
 *
 * Brick-safety: AF_UNIX local-only -- no modules, no sysfs, no
 * namespaces, per-process state only.  Recv sockets carry
 * SO_RCVTIMEO=1s so no recv outlives child.c's SIGALRM(1s).
 *
 * Latch: first invocation probes socketpair(AF_UNIX, SOCK_STREAM); on
 * -EAFNOSUPPORT/-ESOCKTNOSUPPORT the op stays disabled for this
 * child's life.  SO_PEEK_OFF rejection bumps setup_failed without
 * latching (a later iter may land on a supporting kernel).  Header-
 * gated by __has_include on <sys/socket.h>/<sys/un.h> with a fallback
 * stub for paranoid sysroots.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "errno-classify.h"
#include "syscall-gate.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<sys/un.h>)

#include <linux/futex.h>
#include <linux/sched.h>	/* struct clone_args */
#include <sched.h>		/* CLONE_FILES */
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "childops-util.h"	/* waitpid_eintr */
#include "jitter.h"
#include "random.h"

#include "kernel/socket.h"
/* Per-process latched gate: AF_UNIX SOCK_STREAM probe failed.  Once set,
 * every subsequent invocation just bumps setup_failed and returns. */
static bool ns_unsupported_af_unix_peek_race;

/* Per-process probe-once latch: false until the first invocation has
 * confirmed (or rejected) AF_UNIX SOCK_STREAM availability. */
static bool af_unix_peek_race_probed;

/* Per-process latch: clone3() returned ENOSYS once, so don't try again.
 * Pre-5.3-ish kernels lack clone3; further attempts would just burn
 * syscall entries.  Sibling-less single-task race burst is the fallback. */
static bool af_unix_peek_race_clone3_unavailable;

#define UNIX_PEEK_LOOP_BUDGET		8U
#define UNIX_PEEK_LOOP_ITERS_BASE	2U
#define UNIX_PEEK_RACE_BUDGET		32U
#define UNIX_PEEK_RACE_ITERS_BASE	8U
#define UNIX_PEEK_RECV_TIMEO_S		1
#define UNIX_PEEK_PAYLOAD_BYTES		16U
#define UNIX_PEEK_OFF_MAX		8U
#define UNIX_PEEK_REBUILD_BUDGET	4U	/* max socketpair() rebuilds per parent burst */

/*
 * Set SO_RCVTIMEO=1s on a recv-side fd so a recv that races a partial
 * shutdown cannot block past child.c's SIGALRM(1s).
 */
static void set_recv_timeo(int fd)
{
	struct timeval tv;

	tv.tv_sec  = UNIX_PEEK_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/*
 * Open one socketpair(AF_UNIX, SOCK_STREAM, 0) into sv[2] with
 * SOCK_CLOEXEC + SO_RCVTIMEO on both halves, then arm SO_PEEK_OFF=off
 * on the reader half (sv[0]) and pre-fill it with a small payload sent
 * from sv[1].  Returns 0 on success, -1 on failure (sv[] left at -1).
 *
 * The peek-off arming is the whole point of this childop: without it
 * the kernel's unix_stream_read_generic() takes the conventional
 * MSG_PEEK path without consulting sk_peek_off.  ENOPROTOOPT here on
 * pre-stream-peek-off kernels is not a hard fail -- we still want the
 * concurrent MSG_PEEK / plain-recv / shutdown shape -- but we bump
 * setup_failed so the fleet view shows the kernel did not honour the
 * setsockopt.
 */
static int unix_stream_pair_open(int sv[2], int peek_off)
{
	char payload[UNIX_PEEK_PAYLOAD_BYTES] = { 0 };
	int off = peek_off;
	ssize_t s;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
		sv[0] = -1;
		sv[1] = -1;
		return -1;
	}
	set_recv_timeo(sv[0]);
	set_recv_timeo(sv[1]);

	if (setsockopt(sv[0], SOL_SOCKET, SO_PEEK_OFF, &off, sizeof(off)) < 0) {
		__atomic_add_fetch(&shm->stats.af_unix_peek_race.peek_off_rejected,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.af_unix_peek_race.peek_off_armed,
				   1, __ATOMIC_RELAXED);
	}

	s = send(sv[1], payload, sizeof(payload), MSG_DONTWAIT);
	if (s < 0)
		return 0;	/* pair opened, prefill optional */
	return 0;
}

/*
 * Shared state between the parent childop task and the clone(CLONE_FILES)
 * sibling race-producer.  Lives in a MAP_SHARED MAP_ANONYMOUS page so
 * writes from either side are immediately visible to the other -- the
 * sibling is cloned without CLONE_VM, so without MAP_SHARED its COW'd
 * page would diverge on first write.
 *
 * fd numbers cross the clone boundary unmodified because the two tasks
 * share the fd table (CLONE_FILES); a numeric fd in either task refers
 * to the same kernel struct file.  read_fd is a generation-tagged slot:
 * the parent stores -1 before close()/socketpair() and a fresh non-
 * negative fd after; sibling samples it each iteration via __ATOMIC_ACQUIRE
 * so a re-built pair after EPIPE is picked up without a futex hop.
 *
 * `go` is a futex word: parent flips it to 1 and FUTEX_WAKEs after
 * publishing fds/budget; sibling FUTEX_WAITs on it before entering its
 * loop.  `stop` is also atomic-ACQUIRE checked by the sibling each
 * iteration so the parent can ask it to exit cleanly before the
 * budgeted iteration count is exhausted.
 */
struct af_unix_peek_race_shared {
	int		read_fd;	/* sv[0]; -1 while parent is rebuilding */
	uint32_t	race_budget;	/* iterations sibling should run */
	uint32_t	go;		/* futex word: 0 = wait, 1 = start */
	uint32_t	stop;		/* 1 = sibling should break early */
	uint32_t	done;		/* sibling sets 1 on exit */
};

static long raw_futex_wait(uint32_t *uaddr, uint32_t val)
{
	return trinity_raw_syscall(__NR_futex, uaddr, FUTEX_WAIT, val, NULL, NULL, 0);
}

static long raw_futex_wake(uint32_t *uaddr, int n)
{
	return trinity_raw_syscall(__NR_futex, uaddr, FUTEX_WAKE, n, NULL, NULL, 0);
}

/*
 * Sibling task body.  Runs inside a clone(CLONE_FILES | SIGCHLD) child:
 *   - shares the parent's fd table (CLONE_FILES)
 *   - has its own COW'd VM (no CLONE_VM)
 *   - has its own sighand (no CLONE_SIGHAND)
 *   - has its own TGID / pid (no CLONE_THREAD)
 *
 * That isolation matters: the race target is the unix_stream_read_generic
 * freed-tail path under SO_PEEK_OFF, and we want two distinct task_structs
 * contending on the same struct unix_sock receive queue.  Sharing only
 * the fd table -- nothing else -- gives the kernel the most surface to
 * fault on without entangling libc heap, signal handlers, or address
 * space with the parent.
 *
 * By design the sibling NEVER enters trinity dispatch, never calls
 * trinity helpers, never includes shm.h, never bumps stats.  All work
 * is raw syscall(__NR_*).  Defences:
 *
 *   - PR_SET_PDEATHSIG SIGKILL: if the parent crashes, the kernel
 *     kills the orphaned sibling so it cannot spin its race loop
 *     against an unattended fd table forever.
 *   - alarm(2): self-bound watchdog.  Independent of the parent's
 *     per-syscall alarm(1) (no CLONE_SIGHAND, so the parent's SIGALRM
 *     never reaches us).  Belt-and-braces against a kernel bug that
 *     swallows MSG_DONTWAIT and SO_RCVTIMEO=1s simultaneously.
 *   - getppid()==1 re-check post-PDEATHSIG: covers the race where the
 *     parent died between clone return and prctl arming.
 *
 * Each iteration alternates one MSG_PEEK recv and one plain recv on
 * the current read_fd snapshot.  Both use MSG_DONTWAIT and -1 means
 * "parent is rebuilding"; we yield via sched_yield() and retry next
 * iter rather than burning a futex op.
 */
__attribute__((noreturn))
static void af_unix_peek_sibling_main(struct af_unix_peek_race_shared *rs)
{
	uint32_t budget;
	uint32_t i;

	(void)trinity_raw_syscall(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL);
	(void)alarm(2);

	if (trinity_raw_syscall(__NR_getppid) == 1)
		(void)syscall(__NR_exit, 0);

	while (__atomic_load_n(&rs->go, __ATOMIC_ACQUIRE) == 0U)
		(void)raw_futex_wait(&rs->go, 0U);

	budget = rs->race_budget;
	for (i = 0; i < budget; i++) {
		char buf[UNIX_PEEK_PAYLOAD_BYTES];
		int read_fd;
		long r;

		if (__atomic_load_n(&rs->stop, __ATOMIC_ACQUIRE) != 0U)
			break;

		read_fd = __atomic_load_n(&rs->read_fd, __ATOMIC_ACQUIRE);
		if (read_fd < 0) {
			(void)trinity_raw_syscall(__NR_sched_yield);
			continue;
		}

		r = trinity_raw_syscall(__NR_recvfrom, (long)read_fd, (long)buf,
			    (long)sizeof(buf), (long)(MSG_PEEK | MSG_DONTWAIT),
			    0L, 0L);
		(void)r;

		read_fd = __atomic_load_n(&rs->read_fd, __ATOMIC_ACQUIRE);
		if (read_fd < 0)
			continue;

		r = trinity_raw_syscall(__NR_recvfrom, (long)read_fd, (long)buf,
			    (long)sizeof(buf), (long)MSG_DONTWAIT,
			    0L, 0L);
		(void)r;
	}

	__atomic_store_n(&rs->done, 1U, __ATOMIC_RELEASE);
	(void)raw_futex_wake(&rs->done, 1);

	syscall(__NR_exit, 0);
	__builtin_unreachable();
}

/*
 * Allocate the shared-state page.  MAP_SHARED MAP_ANONYMOUS is the
 * cheapest cross-task primitive that survives a clone-without-CLONE_VM.
 * The page is freed by the caller via munmap().
 */
static struct af_unix_peek_race_shared *race_shared_alloc(void)
{
	struct af_unix_peek_race_shared *rs;

	rs = mmap(NULL, sizeof(*rs), PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (rs == MAP_FAILED)
		return NULL;

	rs->read_fd     = -1;
	rs->race_budget = 0;
	rs->go          = 0;
	rs->stop        = 0;
	rs->done        = 0;
	return rs;
}

/*
 * Spawn the race-producer sibling via clone3(CLONE_FILES | SIGCHLD).
 * Returns the sibling pid on success, -1 on failure (caller falls back
 * to the single-task race burst).  Uses clone3 exclusively for ABI
 * portability across architectures; pre-5.3 kernels without clone3
 * latch ENOSYS once and never retry.
 */
static pid_t spawn_race_sibling(struct af_unix_peek_race_shared *rs)
{
	struct clone_args args;
	long ret;

	if (af_unix_peek_race_clone3_unavailable)
		return -1;

	memset(&args, 0, sizeof(args));
	args.flags       = CLONE_FILES;
	args.exit_signal = SIGCHLD;

	ret = trinity_raw_syscall(__NR_clone3, &args, sizeof(args));
	if (ret < 0) {
		if (errno == ENOSYS)
			af_unix_peek_race_clone3_unavailable = true;
		return -1;
	}
	if (ret == 0)
		af_unix_peek_sibling_main(rs);	/* noreturn */
	return (pid_t)ret;
}

/*
 * Reap the sibling.  Try non-blocking first so a sibling that completed
 * its budget early is reaped cheaply; if still alive, ask it to stop
 * via the shared flag, then SIGKILL + blocking waitpid.  SIGKILL is
 * unblockable and we hold no shared sighand, so the sibling cannot
 * defer or mask it.
 */
static void reap_race_sibling(pid_t sibling, struct af_unix_peek_race_shared *rs)
{
	int status = 0;
	pid_t rc;

	__atomic_store_n(&rs->stop, 1U, __ATOMIC_RELEASE);

	rc = waitpid_eintr(sibling, &status, WNOHANG);
	if (rc == 0) {
		(void)kill(sibling, SIGKILL);
		rc = waitpid_eintr(sibling, &status, 0);
	}
	if (rc <= 0)
		return;

	if (WIFEXITED(status)) {
		__atomic_add_fetch(&shm->stats.af_unix_peek_race.sibling_reaped_ok,
				   1, __ATOMIC_RELAXED);
	} else if (WIFSIGNALED(status)) {
		__atomic_add_fetch(&shm->stats.af_unix_peek_race.sibling_crashed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Single-task race burst: alternating peek + drain + send + occasional
 * shutdown.  Used when sibling spawn fails (clone3 unavailable, EAGAIN
 * under cgroup-MAX, etc.) -- preserves the SO_PEEK_OFF shape so a
 * failed sibling spawn does not turn into a wasted iter.
 */
static void run_race_burst_solo(int sv[2], unsigned int races, int peek_off)
{
	unsigned int r;
	unsigned int rebuilds = 0;

	for (r = 0; r < races; r++) {
		char buf[UNIX_PEEK_PAYLOAD_BYTES];
		char tx[UNIX_PEEK_PAYLOAD_BYTES] = { 0 };
		ssize_t s;

		if (sv[0] < 0 || sv[1] < 0)
			break;

		(void)recv(sv[0], buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
		(void)recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);

		s = send(sv[1], tx, sizeof(tx), MSG_DONTWAIT);
		if (s < 0 && errno == EPIPE) {
			if (rebuilds >= UNIX_PEEK_REBUILD_BUDGET)
				break;
			(void)close(sv[0]);
			(void)close(sv[1]);
			sv[0] = -1;
			sv[1] = -1;
			if (unix_stream_pair_open(sv, peek_off) < 0)
				break;
			rebuilds++;
			continue;
		}

		if (ONE_IN(4))
			(void)shutdown(sv[1], SHUT_WR);
	}

	__atomic_add_fetch(&shm->stats.af_unix_peek_race.pair_rebuilds,
			   rebuilds, __ATOMIC_RELAXED);
}

/*
 * Parent's half of the cross-task race: tight-loop send() on sv[1] with
 * occasional shutdown(SHUT_WR), rebuilding the pair on EPIPE (bounded
 * by UNIX_PEEK_REBUILD_BUDGET).  Sibling concurrently runs MSG_PEEK +
 * plain recv on sv[0] via the shared fd table; updates to rs->read_fd
 * are RELEASE-published so the sibling's ACQUIRE-load picks up the
 * fresh fd after a rebuild without needing a futex hop.
 */
static void run_race_burst_parent_half(int sv[2],
				       struct af_unix_peek_race_shared *rs,
				       unsigned int races, int peek_off)
{
	unsigned int r;
	unsigned int rebuilds = 0;

	for (r = 0; r < races; r++) {
		char tx[UNIX_PEEK_PAYLOAD_BYTES] = { 0 };
		ssize_t s;

		if (sv[0] < 0 || sv[1] < 0)
			break;

		s = send(sv[1], tx, sizeof(tx), MSG_DONTWAIT);
		if (s >= 0) {
			__atomic_add_fetch(&shm->stats.af_unix_peek_race.send_ok,
					   1, __ATOMIC_RELAXED);
		} else if (errno == EPIPE) {
			if (rebuilds >= UNIX_PEEK_REBUILD_BUDGET)
				break;
			__atomic_store_n(&rs->read_fd, -1, __ATOMIC_RELEASE);
			(void)close(sv[0]);
			(void)close(sv[1]);
			sv[0] = -1;
			sv[1] = -1;
			if (unix_stream_pair_open(sv, peek_off) < 0)
				break;
			__atomic_store_n(&rs->read_fd, sv[0], __ATOMIC_RELEASE);
			rebuilds++;
			continue;
		}

		if (ONE_IN(4)) {
			if (shutdown(sv[1], SHUT_WR) == 0) {
				__atomic_add_fetch(&shm->stats.af_unix_peek_race.shutdown_ok,
						   1, __ATOMIC_RELAXED);
			}
		}
	}

	__atomic_add_fetch(&shm->stats.af_unix_peek_race.pair_rebuilds,
			   rebuilds, __ATOMIC_RELAXED);
}

/*
 * One outer iteration: open a SOCK_STREAM pair, arm SO_PEEK_OFF, run a
 * small race burst (sibling-task if clone3 lands, single-task fallback
 * otherwise), then tear down.
 *
 * The teardown path closes every fd that is still >= 0, so helpers
 * signal "ownership transferred / fd closed" simply by writing -1 back
 * into the slot.
 */
static void iter_one(struct childdata *child)
{
	int sv[2] = { -1, -1 };
	int peek_off;
	struct af_unix_peek_race_shared *rs = NULL;
	pid_t sibling = -1;
	unsigned int races;

	peek_off = (int)rnd_modulo_u32(UNIX_PEEK_OFF_MAX);

	if (unix_stream_pair_open(sv, peek_off) < 0) {
		__atomic_add_fetch(&shm->stats.af_unix_peek_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.af_unix_peek_race.pair_open_ok,
			   1, __ATOMIC_RELAXED);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	races = BUDGETED(CHILD_OP_AF_UNIX_PEEK_RACE,
			 UNIX_PEEK_RACE_ITERS_BASE);
	if (races > UNIX_PEEK_RACE_BUDGET)
		races = UNIX_PEEK_RACE_BUDGET;
	if (races == 0U)
		races = 1U;

	rs = race_shared_alloc();
	if (rs != NULL) {
		rs->read_fd     = sv[0];
		rs->race_budget = races;
		sibling = spawn_race_sibling(rs);
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	if (sibling < 0) {
		__atomic_add_fetch(&shm->stats.af_unix_peek_race.sibling_spawn_failed,
				   1, __ATOMIC_RELAXED);
		run_race_burst_solo(sv, races, peek_off);
	} else {
		__atomic_add_fetch(&shm->stats.af_unix_peek_race.sibling_spawn_ok,
				   1, __ATOMIC_RELAXED);
		__atomic_store_n(&rs->go, 1U, __ATOMIC_RELEASE);
		(void)raw_futex_wake(&rs->go, 1);

		run_race_burst_parent_half(sv, rs, races, peek_off);

		reap_race_sibling(sibling, rs);
	}

out:
	if (rs != NULL)
		(void)munmap(rs, sizeof(*rs));
	if (sv[0] >= 0) (void)close(sv[0]);
	if (sv[1] >= 0) (void)close(sv[1]);
}

/*
 * One-time AF_UNIX SOCK_STREAM probe.  socketpair() is the cheapest
 * way to verify both AF_UNIX presence and SOCK_STREAM support without
 * leaving any kernel state behind.  Latches ns_unsupported on
 * EAFNOSUPPORT/EPROTONOSUPPORT/ESOCKTNOSUPPORT.
 */
static void probe_af_unix_stream(void)
{
	int sv[2];

	af_unix_peek_race_probed = true;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
		if (is_proto_family_unsupported(errno))
			ns_unsupported_af_unix_peek_race = true;
		return;
	}
	(void)close(sv[0]);
	(void)close(sv[1]);
}

bool af_unix_peek_race(struct childdata *child)
{
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.af_unix_peek_race.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_af_unix_peek_race) {
		__atomic_add_fetch(&shm->stats.af_unix_peek_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!af_unix_peek_race_probed) {
		probe_af_unix_stream();
		if (ns_unsupported_af_unix_peek_race) {
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
			__atomic_add_fetch(&shm->stats.af_unix_peek_race.setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	outer_iters = BUDGETED(CHILD_OP_AF_UNIX_PEEK_RACE,
			       JITTER_RANGE(UNIX_PEEK_LOOP_ITERS_BASE));
	if (outer_iters > UNIX_PEEK_LOOP_BUDGET)
		outer_iters = UNIX_PEEK_LOOP_BUDGET;
	if (outer_iters == 0U)
		outer_iters = 1U;

	for (i = 0; i < outer_iters; i++)
		iter_one(child);

	return true;
}

#else  /* !__has_include(<sys/un.h>) */

bool af_unix_peek_race(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.af_unix_peek_race.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.af_unix_peek_race.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<sys/un.h>) */
