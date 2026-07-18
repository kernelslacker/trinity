/*
 * af_unix_scm_rights_gc_churn - build a closed cycle in the AF_UNIX
 * SCM_RIGHTS reference graph, drop all userspace references, then race
 * net/unix/garbage.c:unix_gc against concurrent recvmsg() draining of
 * the queued SCM_RIGHTS messages.
 *
 * Bug class: AF_UNIX fd-graph + unix_gc race.  SCM_RIGHTS lets one
 * unix sock queue fds referring to other unix socks; userspace can
 * build a closed cycle sk1->sk2->sk3->sk1 whose only remaining refs
 * come from the SCM_RIGHTS msgs queued on cycle peers.  Once the
 * userspace fds are closed, only unix_gc can reclaim -- walking
 * unix_socket_table under unix_gc_lock and folding inflight refcounts.
 * The interesting failures land in the gc walk vs concurrent activity:
 * gc snapshots inflight then a recvmsg drains an SCM_RIGHTS msg
 * before gc finishes the traversal (a decade-defining UAF), listener
 * accept-queue socks torn down under gc, unix_attach_fds double-drop
 * error paths, and io_uring registered-files SCM_RIGHTS extending
 * the graph multi-hop into the gc walk.
 *
 * Per iteration: open three socketpair(SOCK_DGRAM) sv1/sv2/sv3, cycle
 * via sendmsg SCM_RIGHTS=[sv1[0]] on sv2[1], =[sv2[0]] on sv3[1],
 * =[sv3[0]] on sv1[1]; close the original [0] fds so the cycle is
 * unreachable; kick gc (extra SCM_RIGHTS send + usleep(0)); race
 * burst alternates recvmsg(sv2[1]) drains against unix_attach_fds
 * calls carrying a held /dev/null fd (opened once, /dev/null never
 * threads the cycle walk).  Low-probability variant swaps one cycle
 * fd for an io_uring fd with a registered files table (multi-hop
 * graph extension).
 *
 * Brick-safety: AF_UNIX local-only, no modules/sysfs/namespaces, no
 * persistent fs writes.  sendmsg MSG_DONTWAIT; recv sockets carry
 * SO_RCVTIMEO=1s so a stuck recv can't pin past child.c's SIGALRM(1s).
 *
 * Latch: first invocation probes socketpair(AF_UNIX, SOCK_DGRAM); on
 * -EAFNOSUPPORT/-ESOCKTNOSUPPORT (AF_UNIX disabled) the op stays off
 * for this child's life.  Header-gated by __has_include on
 * <sys/socket.h>/<sys/un.h> with a fallback stub for paranoid sysroots.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
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

#if __has_include(<linux/io_uring.h>)
#include <linux/io_uring.h>
#include "kernel/fcntl.h"
#include "kernel/socket.h"
#define HAVE_IOURING_VARIANT	1
#else
#define HAVE_IOURING_VARIANT	0
#endif

/* Per-process latched gate: AF_UNIX SOCK_DGRAM probe failed.  Once set,
 * every subsequent invocation just bumps setup_failed and returns. */
static bool ns_unsupported_af_unix_scm_rights_gc;

/* Per-process probe-once latch: false until the first invocation has
 * confirmed (or rejected) AF_UNIX availability. */
static bool af_unix_scm_rights_gc_probed;

#define UNIX_SCM_LOOP_BUDGET		8U
#define UNIX_SCM_LOOP_ITERS_BASE	2U
#define UNIX_SCM_RACE_BUDGET		8U
#define UNIX_SCM_RACE_ITERS_BASE	2U
#define UNIX_SCM_RECV_TIMEO_S		1
#define UNIX_SCM_PAYLOAD_BYTES		8U
#define UNIX_SCM_IOURING_RING_ENTRIES	4U

/*
 * Set SO_RCVTIMEO=1s on a recv-side fd so a recvmsg that races gc and
 * drains an empty queue cannot block past child.c's SIGALRM(1s).
 */
static void set_recv_timeo(int fd)
{
	struct timeval tv;

	tv.tv_sec  = UNIX_SCM_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/*
 * Open one socketpair(AF_UNIX, SOCK_DGRAM, 0) into sv[2].  Both ends
 * receive SO_RCVTIMEO and SOCK_CLOEXEC; SOCK_CLOEXEC matters because
 * sibling child processes can fork between our setup and teardown.
 * Returns 0 on success, -1 on failure (sv[] left untouched).
 */
static int unix_pair_open(int sv[2])
{
	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) < 0)
		return -1;
	set_recv_timeo(sv[0]);
	set_recv_timeo(sv[1]);
	return 0;
}

/*
 * Send a one-byte payload on send_fd with a single SCM_RIGHTS cmsg
 * carrying scm_fd.  Returns the sendmsg() return value (or -errno
 * folded onto a negative ssize_t for the caller's sign test).
 *
 * The kernel's unix_attach_fds() runs inside this send: it allocates
 * a unix_skb_parms slot with the attached scm fd refs, bumps
 * struct file refcount, and accounts the inflight ref against the
 * receiving sock.  This is the path that historically miscounted on
 * partial-failure (CVE-2024-43892).
 */
static ssize_t send_scm_fd(int send_fd, int scm_fd)
{
	char payload[UNIX_SCM_PAYLOAD_BYTES] = { 0 };
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov;
	struct msghdr mh;
	struct cmsghdr *cmsg;
	ssize_t r;

	iov.iov_base = payload;
	iov.iov_len  = sizeof(payload);

	memset(&mh, 0, sizeof(mh));
	memset(cbuf, 0, sizeof(cbuf));
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&mh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type  = SCM_RIGHTS;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &scm_fd, sizeof(scm_fd));

	r = sendmsg(send_fd, &mh, MSG_DONTWAIT);
	if (r < 0)
		return -errno;
	return r;
}

/*
 * Drain one message from recv_fd.  We don't care what we get back -- the
 * point is to exercise unix_recv()'s SCM_RIGHTS path (skb_unlink +
 * scm_detach_fds + the fd install into our table) concurrently with
 * unix_gc walking the same sock's queue.  Any installed fds are closed
 * immediately so we don't leak.
 *
 * Returns 0 on a recv that completed (success or recoverable error such
 * as EAGAIN/ETIMEDOUT), -1 on hard failure.
 */
static int recv_drain_scm(int recv_fd)
{
	char payload[UNIX_SCM_PAYLOAD_BYTES];
	char cbuf[CMSG_SPACE(sizeof(int) * 8)];
	struct iovec iov;
	struct msghdr mh;
	struct cmsghdr *cmsg;
	ssize_t r;

	iov.iov_base = payload;
	iov.iov_len  = sizeof(payload);

	memset(&mh, 0, sizeof(mh));
	memset(cbuf, 0, sizeof(cbuf));
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);

	r = recvmsg(recv_fd, &mh, MSG_DONTWAIT);
	if (r < 0) {
		/* EAGAIN == EWOULDBLOCK on Linux; -Wlogical-op rejects
		 * naming both, so just check the canonical EAGAIN. */
		if (errno == EAGAIN || errno == EINTR || errno == ETIMEDOUT)
			return 0;
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		if (cmsg->cmsg_len < CMSG_LEN(sizeof(int)))
			continue;
		{
			size_t n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			int *fds = (int *)CMSG_DATA(cmsg);
			size_t i;

			for (i = 0; i < n; i++) {
				if (fds[i] >= 0)
					(void)close(fds[i]);
			}
		}
	}
	return 0;
}

/*
 * Peek one message from recv_fd with MSG_PEEK | MSG_DONTWAIT.  This is
 * the only userspace path that reaches unix_peek_fpl(): the kernel dups
 * each SCM_RIGHTS file (fpl) and installs a fresh fd in our table while
 * leaving the original skb on the queue.  Running this concurrently
 * with unix_gc exercises the gc_in_progress observation that the
 * upstream fix (commit d82ba05263c6 "af_unix: Set gc_in_progress to
 * true in unix_gc()") protects against -- a peeker's dup'd file racing
 * a live gc walk that has not yet snapshotted gc_in_progress.
 *
 * The peeked SCM_RIGHTS payload stays queued (next drain will hit it
 * again); we just close the freshly installed fds to avoid leaks.
 *
 * Returns 0 on a peek that completed (success or EAGAIN/ETIMEDOUT/
 * EINTR), -1 on hard failure.
 */
static int recv_peek_scm(int recv_fd)
{
	char payload[UNIX_SCM_PAYLOAD_BYTES];
	char cbuf[CMSG_SPACE(sizeof(int) * 8)];
	struct iovec iov;
	struct msghdr mh;
	struct cmsghdr *cmsg;
	ssize_t r;

	iov.iov_base = payload;
	iov.iov_len  = sizeof(payload);

	memset(&mh, 0, sizeof(mh));
	memset(cbuf, 0, sizeof(cbuf));
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);

	r = recvmsg(recv_fd, &mh, MSG_PEEK | MSG_DONTWAIT);
	if (r < 0) {
		if (errno == EAGAIN || errno == EINTR || errno == ETIMEDOUT)
			return 0;
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		if (cmsg->cmsg_len < CMSG_LEN(sizeof(int)))
			continue;
		{
			size_t n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			int *fds = (int *)CMSG_DATA(cmsg);
			size_t i;

			for (i = 0; i < n; i++) {
				if (fds[i] >= 0)
					(void)close(fds[i]);
			}
		}
	}
	return 0;
}

#if HAVE_IOURING_VARIANT
/*
 * Best-effort io_uring setup.  Returns the ring fd on success, -1 on
 * failure.  We don't need the ring to be functional -- the gc path
 * cares about the struct file backing the ring fd, not whether SQE
 * submission works.  Older kernels without IORING_SETUP_SQPOLL or
 * with io_uring disabled (CONFIG_IO_URING=n) just fall back to -1
 * and the variant is skipped that iteration.
 */
static int iouring_open(void)
{
	struct io_uring_params p;
	long fd;

	memset(&p, 0, sizeof(p));
	fd = trinity_raw_syscall(SYS_io_uring_setup, UNIX_SCM_IOURING_RING_ENTRIES, &p);
	if (fd < 0)
		return -1;
	return (int)fd;
}
#else
static int iouring_open(void)
{
	return -1;
}
#endif

/*
 * Per-process latch: clone3() returned ENOSYS once, so don't try again.
 * Pre-5.3-ish kernels lack clone3; further attempts would just burn
 * syscall entries.  Sibling-less single-task race burst is the fallback.
 */
static bool af_unix_scm_clone3_unavailable;

/*
 * Shared state between the parent childop task and the clone(CLONE_FILES)
 * sibling race producer.  Lives in a MAP_SHARED MAP_ANONYMOUS page so
 * writes from either side are immediately visible to the other -- the
 * sibling is cloned without CLONE_VM, so without MAP_SHARED its COW'd
 * page would diverge on first write.
 *
 * fd numbers cross the clone boundary unmodified because the two tasks
 * share the fd table (CLONE_FILES); a numeric fd in either task refers
 * to the same kernel struct file.  No fd-passing dance required.
 *
 * The two atomic words form a futex handshake: parent flips `go` to 1
 * and FUTEX_WAKEs after publishing fd/budget; sibling FUTEX_WAITs on it
 * before entering its loop.  `done` is informational: parent reaps via
 * waitpid() rather than polling `done`.
 */
struct af_unix_race_shared {
	int		sv2_recv_fd;	/* cycle endpoint -- target of MSG_PEEK */
	uint32_t	race_budget;	/* iterations sibling should run */
	uint32_t	go;		/* futex word: 0 = wait, 1 = start */
	uint32_t	done;		/* futex word: sibling sets 1 on exit */
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
 * That isolation matters.  The race target is the AF_UNIX SCM_RIGHTS
 * graph + unix_gc walk: we want concurrent MSG_PEEK on the same struct
 * file (shared via fd-table) racing the parent's drain + fresh SCM_RIGHTS
 * attach, exercising unix_peek_fpl()/unix_gc_lock under contention from
 * two distinct task_structs.  Sharing only the fd table -- nothing else
 * -- gives the kernel the most surface to fault on without entangling
 * libc heap, signal handlers, or address space with the parent.
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
 *
 * Peeked SCM_RIGHTS install fresh fds into the shared fd table; we
 * close them inline via raw __NR_close so they don't accumulate across
 * iterations.  The cycle endpoint fds (sv1[0]/sv2[0]/sv3[0]) were
 * already dropped from userspace by the parent before the race phase,
 * so no fd we close here can collide with one the parent still cares
 * about.
 */
__attribute__((noreturn))
static void af_unix_sibling_main(struct af_unix_race_shared *rs)
{
	uint32_t budget;
	uint32_t i;

	(void)trinity_raw_syscall(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL);
	(void)alarm(2);

	/*
	 * Re-check getppid() after arming PDEATHSIG.  If the parent
	 * died in the window between clone3 returning here and the
	 * prctl above, PDEATHSIG was set too late to fire and
	 * getppid()==1 is the only signal we get.  Without this we'd
	 * block forever in raw_futex_wait below on a 'go' flag no
	 * one will ever set, permanently leaking the sibling.
	 */
	if (trinity_raw_syscall(__NR_getppid) == 1)
		(void)syscall(__NR_exit, 0);

	while (__atomic_load_n(&rs->go, __ATOMIC_ACQUIRE) == 0U)
		(void)raw_futex_wait(&rs->go, 0U);

	budget = rs->race_budget;
	for (i = 0; i < budget; i++) {
		char payload[UNIX_SCM_PAYLOAD_BYTES];
		char cbuf[CMSG_SPACE(sizeof(int) * 8)];
		struct iovec iov;
		struct msghdr mh;
		struct cmsghdr *cmsg;
		int recv_fd;
		long r;

		recv_fd = rs->sv2_recv_fd;
		if (recv_fd < 0)
			break;

		iov.iov_base = payload;
		iov.iov_len  = sizeof(payload);

		memset(&mh, 0, sizeof(mh));
		memset(cbuf, 0, sizeof(cbuf));
		mh.msg_iov     = &iov;
		mh.msg_iovlen  = 1;
		mh.msg_control = cbuf;
		mh.msg_controllen = sizeof(cbuf);

		r = trinity_raw_syscall(__NR_recvmsg, (long)recv_fd, (long)&mh,
			    (long)(MSG_PEEK | MSG_DONTWAIT));
		if (r < 0)
			continue;

		for (cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL;
		     cmsg = CMSG_NXTHDR(&mh, cmsg)) {
			size_t n, j;
			int *fds;

			if (cmsg->cmsg_level != SOL_SOCKET ||
			    cmsg->cmsg_type  != SCM_RIGHTS)
				continue;
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(int)))
				continue;
			n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			fds = (int *)CMSG_DATA(cmsg);
			for (j = 0; j < n; j++) {
				if (fds[j] >= 0)
					(void)trinity_raw_syscall(__NR_close, (long)fds[j]);
			}
		}
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
static struct af_unix_race_shared *race_shared_alloc(void)
{
	struct af_unix_race_shared *rs;

	rs = mmap(NULL, sizeof(*rs), PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (rs == MAP_FAILED)
		return NULL;

	rs->sv2_recv_fd = -1;
	rs->race_budget = 0;
	rs->go   = 0;
	rs->done = 0;
	return rs;
}

/*
 * Spawn the race-producer sibling via clone3(CLONE_FILES | SIGCHLD).
 * Returns the sibling pid on success, -1 on failure (caller falls back
 * to the single-task race burst).  Uses clone3 exclusively for ABI
 * portability across architectures -- legacy clone()'s argument order
 * varies (x86_64 vs s390 vs sparc), and we have nothing to gain from
 * fighting that on the producer path.  Pre-5.3 kernels without clone3
 * latch ENOSYS once and never retry.
 *
 * No CLONE_VM, no CLONE_SIGHAND, no CLONE_THREAD: the sibling is a
 * sibling task in the conventional Linux sense (separate TGID,
 * separate sighand, COW'd VM), differing from a plain fork() only in
 * the shared fd table.
 */
static pid_t spawn_race_sibling(struct af_unix_race_shared *rs)
{
	struct clone_args args;
	long ret;

	if (af_unix_scm_clone3_unavailable)
		return -1;

	memset(&args, 0, sizeof(args));
	args.flags       = CLONE_FILES;
	args.exit_signal = SIGCHLD;

	ret = trinity_raw_syscall(__NR_clone3, &args, sizeof(args));
	if (ret < 0) {
		if (errno == ENOSYS)
			af_unix_scm_clone3_unavailable = true;
		return -1;
	}
	if (ret == 0)
		af_unix_sibling_main(rs);	/* noreturn */
	return (pid_t)ret;
}

/*
 * Reap the sibling.  Try non-blocking first so a sibling that completed
 * its budget early is reaped cheaply; if still alive, SIGKILL + blocking
 * waitpid.  SIGKILL is unblockable and we hold no shared sighand, so
 * the sibling cannot defer or mask it.
 *
 * Bumps reaped_ok vs crashed depending on exit shape so a long-running
 * fleet can flag sibling-side instability without trinity having to
 * inspect every iteration.
 */
static void reap_race_sibling(pid_t sibling)
{
	int status = 0;
	pid_t rc;

	rc = waitpid_eintr(sibling, &status, WNOHANG);
	if (rc == 0) {
		(void)kill(sibling, SIGKILL);
		rc = waitpid_eintr(sibling, &status, 0);
	}
	if (rc <= 0)
		return;

	if (WIFEXITED(status)) {
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.sibling_reaped_ok,
				   1, __ATOMIC_RELAXED);
	} else if (WIFSIGNALED(status)) {
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.sibling_crashed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Single-task race burst: alternating peek + drain on sv2[1] and repeated
 * SCM_RIGHTS attach on sv4.  The /dev/null fd carried by the sv4 attach is
 * opened once before the loop and reused across iters: gc sees the same
 * per-iter SCM_RIGHTS skb queued on sv4_recv and the same unix_attach_fds()
 * call regardless of whether fd identity rotates, and /dev/null is not a
 * unix sock so it never participates in gc's cycle walk.  Dropping the
 * per-iter open()/close() pair tightens the contention window against
 * unix_gc.  Used when sibling spawn fails (clone3 unavailable, EAGAIN
 * under cgroup-MAX, etc.) -- preserves the Phase 1 coverage so a failed
 * sibling spawn does not turn into a wasted iter.
 */
static void run_race_burst_solo(int sv2_recv, int sv4_recv, unsigned int races)
{
	unsigned int r;
	int extra_fd = -1;

	if (sv4_recv >= 0)
		extra_fd = open("/dev/null", O_RDWR | O_CLOEXEC);

	for (r = 0; r < races; r++) {
		if (sv2_recv >= 0) {
			if (recv_peek_scm(sv2_recv) == 0) {
				__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.peek_ok,
						   1, __ATOMIC_RELAXED);
			}
			if (recv_drain_scm(sv2_recv) == 0) {
				__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.recv_ok,
						   1, __ATOMIC_RELAXED);
			}
		}

		if (extra_fd >= 0)
			(void)send_scm_fd(sv4_recv, extra_fd);
	}

	if (extra_fd >= 0)
		(void)close(extra_fd);
}

/*
 * Parent's half of the cross-task race: drain sv2[1] (races the sibling's
 * MSG_PEEK on the same queue + races unix_gc's inflight snapshot) and
 * repeated SCM_RIGHTS attach on sv4 (races unix_gc's socket-table walk).
 * The sibling is concurrently running its peek loop against sv2[1] via
 * the shared fd table; the resulting two-task contention on a single
 * struct unix_sock's queue is the race shape Phase 2 buys.
 *
 * The /dev/null fd carried by the sv4 attach is opened once before the
 * loop and reused -- see the run_race_burst_solo comment for why fd
 * identity does not matter to the gc-walk race shape.
 *
 * peek_ok is bumped by the sibling's iterations conceptually, but the
 * sibling does not touch shm; instead the parent's pre-spawn
 * sibling_spawn_ok bump signals that a sibling drove peek for `races`
 * iterations (the sibling's actual completed count is at most
 * race_budget; any shortfall comes from alarm(2) or PDEATHSIG).
 */
static void run_race_burst_parent_half(int sv2_recv, int sv4_recv,
				       unsigned int races)
{
	unsigned int r;
	int extra_fd = -1;

	if (sv4_recv >= 0)
		extra_fd = open("/dev/null", O_RDWR | O_CLOEXEC);

	for (r = 0; r < races; r++) {
		if (sv2_recv >= 0) {
			if (recv_drain_scm(sv2_recv) == 0) {
				__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.recv_ok,
						   1, __ATOMIC_RELAXED);
			}
		}

		if (extra_fd >= 0)
			(void)send_scm_fd(sv4_recv, extra_fd);
	}

	if (extra_fd >= 0)
		(void)close(extra_fd);
}

/*
 * Per-iteration scratchpad shared across the af_unix_scm_rights_gc_<phase>
 * helpers.  Lifetime is exactly one iter_one() invocation; avoids threading
 * three fd pairs plus the io_uring variant flags through every helper.
 *
 * The teardown path in iter_one closes every fd that is still >= 0, so
 * helpers signal "ownership transferred / fd closed" simply by writing
 * -1 back into the field.
 */
struct af_unix_scm_rights_gc_iter_ctx {
	int		sv1[2];
	int		sv2[2];
	int		sv3[2];
	int		sv4[2];
	int		iouring_fd;
	bool		use_iouring;
	bool		cycle_ok;
};

/*
 * Phase 1: open the four AF_UNIX SOCK_DGRAM pairs the cycle needs.
 * sv1..sv3 form the cycle members; sv4 is the spare used by the
 * gc-trigger and race-burst phases.  Returns 0 on success or -1 on the
 * first pair failure; the caller goes to the shared teardown path,
 * which safely no-ops on any pair left at the initial { -1, -1 }.
 */
static int af_unix_scm_rights_gc_setup(struct af_unix_scm_rights_gc_iter_ctx *it)
{
	if (unix_pair_open(it->sv1) < 0)
		return -1;
	if (unix_pair_open(it->sv2) < 0)
		return -1;
	if (unix_pair_open(it->sv3) < 0)
		return -1;
	if (unix_pair_open(it->sv4) < 0)
		return -1;
	return 0;
}

/*
 * Phase 2: build the closed SCM_RIGHTS cycle.  Optionally (~1-in-8)
 * swap sv1[0] for an io_uring fd in the first send so the cycle threads
 * an io_uring rsrc node -- the multi-hop graph extension shape that
 * surfaced the CVE-2025-21712 family.  io_uring open failure silently
 * falls back to the plain three-AF_UNIX-fd cycle.
 *
 *   sv2[1] receives sv1[0] (or the io_uring fd in the variant)
 *   sv3[1] receives sv2[0]
 *   sv1[1] receives sv3[0]
 *
 * Each send transfers a kernel ref on the embedded fd into the receiving
 * sock's queue.  Order matters only insofar as each send transfers a ref;
 * the cycle closure happens at the third send.  Sets it->cycle_ok and
 * bumps cycle_built_ok (+iouring_variant_ok) on full success.
 */
static void af_unix_scm_rights_gc_build_cycle(struct af_unix_scm_rights_gc_iter_ctx *it)
{
	int first_fd;
	ssize_t s1, s2, s3;

	it->use_iouring = HAVE_IOURING_VARIANT && ONE_IN(8);
	if (it->use_iouring) {
		it->iouring_fd = iouring_open();
		if (it->iouring_fd < 0)
			it->use_iouring = false;
	}

	first_fd = it->use_iouring ? it->iouring_fd : it->sv1[0];

	s1 = send_scm_fd(it->sv2[1], first_fd);
	s2 = send_scm_fd(it->sv3[1], it->sv2[0]);
	s3 = send_scm_fd(it->sv1[1], it->sv3[0]);
	if (s1 >= 0 && s2 >= 0 && s3 >= 0) {
		it->cycle_ok = true;
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.cycle_built_ok,
				   1, __ATOMIC_RELAXED);
		if (it->use_iouring) {
			__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.iouring_variant_ok,
					   1, __ATOMIC_RELAXED);
		}
	}
}

/*
 * Phase 3: drop userspace refs to the cycle members.  After this the
 * cycle is reachable only via the queued SCM_RIGHTS messages on the
 * peer ends -- exactly the gc fodder shape.  Each closed fd is
 * immediately written back to -1 so the shared teardown path does not
 * double-close.  No-op if build_cycle did not set cycle_ok.
 */
static void af_unix_scm_rights_gc_drop_refs(struct af_unix_scm_rights_gc_iter_ctx *it)
{
	if (!it->cycle_ok)
		return;

	(void)close(it->sv1[0]); it->sv1[0] = -1;
	(void)close(it->sv2[0]); it->sv2[0] = -1;
	(void)close(it->sv3[0]); it->sv3[0] = -1;
	if (it->use_iouring) {
		(void)close(it->iouring_fd);
		it->iouring_fd = -1;
	}
	__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.close_ok,
			   1, __ATOMIC_RELAXED);
}

/*
 * Phase 4: prod unix_gc into running.  Half the time fire a fresh
 * SCM_RIGHTS attach over the spare sv4 pair -- drives unix_inflight()
 * and the gc-schedule path; the other half just usleep(0) and let the
 * workqueue tick catch up.  extra_fd is opened, used, and closed inside
 * the helper so the caller's teardown stays simple.  Bumps trigger_ok
 * on either branch on best effort.
 */
static void af_unix_scm_rights_gc_trigger_gc(struct af_unix_scm_rights_gc_iter_ctx *it)
{
	int extra_fd;

	if (RAND_BOOL()) {
		extra_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (extra_fd >= 0) {
			ssize_t s = send_scm_fd(it->sv4[1], extra_fd);

			if (s >= 0) {
				__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.trigger_ok,
						   1, __ATOMIC_RELAXED);
			}
			(void)close(extra_fd);
		}
	} else {
		(void)usleep(0);
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.trigger_ok,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase 5: race burst.  Two shapes share the same loop body conceptually:
 *
 *   Shape A (single-task fallback): one task issues peek + drain + attach
 *     in a tight loop.  Lands as Phase 1 already shipped.
 *
 *   Shape B (sibling-task, Phase 2): spawn a clone(CLONE_FILES | SIGCHLD)
 *     sibling that issues raw MSG_PEEK recvmsg() against sv2[1] via the
 *     shared fd table; this task does drain + fresh SCM_RIGHTS attach in
 *     parallel.  Two task_structs contending on the same struct unix_sock
 *     queue, both visible to unix_gc under unix_gc_lock -- the race shape
 *     the gc lockset was historically not hardened against.
 *
 *   Shape B falls back to Shape A on clone3 ENOSYS or EAGAIN so a
 *   transient spawn failure does not turn into a wasted iter.
 */
static void af_unix_scm_rights_gc_race_burst(struct af_unix_scm_rights_gc_iter_ctx *it)
{
	struct af_unix_race_shared *rs;
	pid_t sibling = -1;
	unsigned int races;

	races = BUDGETED(CHILD_OP_AF_UNIX_SCM_RIGHTS_GC,
			 UNIX_SCM_RACE_ITERS_BASE);
	if (races > UNIX_SCM_RACE_BUDGET)
		races = UNIX_SCM_RACE_BUDGET;
	if (races == 0U)
		races = 1U;

	rs = race_shared_alloc();
	if (rs != NULL) {
		rs->sv2_recv_fd = it->sv2[1];
		rs->race_budget = races;
		sibling = spawn_race_sibling(rs);
	}

	if (sibling < 0) {
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.sibling_spawn_failed,
				   1, __ATOMIC_RELAXED);
		run_race_burst_solo(it->sv2[1], it->sv4[1], races);
	} else {
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.sibling_spawn_ok,
				   1, __ATOMIC_RELAXED);
		__atomic_store_n(&rs->go, 1U, __ATOMIC_RELEASE);
		(void)raw_futex_wake(&rs->go, 1);

		run_race_burst_parent_half(it->sv2[1], it->sv4[1], races);

		reap_race_sibling(sibling);
	}

	if (rs != NULL)
		(void)munmap(rs, sizeof(*rs));
}

/*
 * One outer iteration: build a 3-pair SCM_RIGHTS cycle, drop userspace
 * refs to make it gc-only-reachable, run a small race burst.  All
 * counters are best-effort -- iter_one returns void; the per-step bumps
 * carry the success signal.
 */
static void iter_one(struct childdata *child)
{
	struct af_unix_scm_rights_gc_iter_ctx it = {
		.sv1 = { -1, -1 },
		.sv2 = { -1, -1 },
		.sv3 = { -1, -1 },
		.sv4 = { -1, -1 },
		.iouring_fd = -1,
		.use_iouring = false,
		.cycle_ok = false,
	};
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (af_unix_scm_rights_gc_setup(&it) != 0)
		goto out;
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	af_unix_scm_rights_gc_build_cycle(&it);
	af_unix_scm_rights_gc_drop_refs(&it);
	af_unix_scm_rights_gc_trigger_gc(&it);
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	af_unix_scm_rights_gc_race_burst(&it);

out:
	if (it.sv1[0] >= 0) (void)close(it.sv1[0]);
	if (it.sv1[1] >= 0) (void)close(it.sv1[1]);
	if (it.sv2[0] >= 0) (void)close(it.sv2[0]);
	if (it.sv2[1] >= 0) (void)close(it.sv2[1]);
	if (it.sv3[0] >= 0) (void)close(it.sv3[0]);
	if (it.sv3[1] >= 0) (void)close(it.sv3[1]);
	if (it.sv4[0] >= 0) (void)close(it.sv4[0]);
	if (it.sv4[1] >= 0) (void)close(it.sv4[1]);
	if (it.iouring_fd >= 0) (void)close(it.iouring_fd);
}

/*
 * One-time AF_UNIX SOCK_DGRAM probe.  socketpair() is the cheapest
 * way to verify both AF_UNIX presence and SOCK_DGRAM support without
 * leaving any kernel state behind.  Latches ns_unsupported on
 * EAFNOSUPPORT/EPROTONOSUPPORT/ESOCKTNOSUPPORT.
 */
static void probe_af_unix(void)
{
	int sv[2];

	af_unix_scm_rights_gc_probed = true;

	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) < 0) {
		if (is_proto_family_unsupported(errno))
			ns_unsupported_af_unix_scm_rights_gc = true;
		return;
	}
	(void)close(sv[0]);
	(void)close(sv[1]);
}

bool af_unix_scm_rights_gc_churn(struct childdata *child)
{
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_af_unix_scm_rights_gc) {
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!af_unix_scm_rights_gc_probed) {
		probe_af_unix();
		if (ns_unsupported_af_unix_scm_rights_gc) {
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized latch_reason array. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
			__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	outer_iters = BUDGETED(CHILD_OP_AF_UNIX_SCM_RIGHTS_GC,
			       JITTER_RANGE(UNIX_SCM_LOOP_ITERS_BASE));
	if (outer_iters > UNIX_SCM_LOOP_BUDGET)
		outer_iters = UNIX_SCM_LOOP_BUDGET;
	if (outer_iters == 0U)
		outer_iters = 1U;

	for (i = 0; i < outer_iters; i++)
		iter_one(child);

	return true;
}

#else  /* !__has_include(<sys/un.h>) */

bool af_unix_scm_rights_gc_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<sys/un.h>) */
