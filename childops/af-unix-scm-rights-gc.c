/*
 * af_unix_scm_rights_gc_churn - build a closed cycle in the AF_UNIX
 * SCM_RIGHTS reference graph, drop all userspace references, then race
 * the kernel garbage collector (unix_gc) against concurrent recvmsg()
 * draining of the queued SCM_RIGHTS messages.
 *
 * The bug class is the AF_UNIX fd-graph + unix_gc race: SCM_RIGHTS
 * cmsgs let one unix socket queue file descriptors that themselves
 * refer to other unix sockets, building a directed reference graph.
 * Userspace can construct a closed cycle (sk1 -> sk2 -> sk3 -> sk1)
 * such that every cycle member's only remaining ref comes from the
 * SCM_RIGHTS message queued on the previous member.  Once userspace
 * drops its descriptors to all three, the cycle is unreachable from
 * any task fd table -- only unix_gc (net/unix/garbage.c) can reclaim
 * it, by walking unix_socket_table under unix_gc_lock and folding
 * inflight refcounts to detect garbage.
 *
 * The interesting failures land in the gc walk vs concurrent activity:
 *
 *   - CVE-2021-0920: a concurrent recvmsg() drains an SCM_RIGHTS msg
 *     while unix_gc is mid-walk; the recv decrements the inflight
 *     count after gc has snapshotted it but before gc finishes the
 *     graph traversal, leaving a use-after-free on the sock that gc
 *     was about to release.  One of the most severe Linux CVEs of the
 *     decade -- exploited in the wild against Pixel devices.
 *
 *   - CVE-2024-26923: a unix listener socket with queued connections
 *     races unix_gc; the listener's accept queue holds child socks
 *     that gc treats as inflight but the listener can dispose of
 *     under listen->shutdown without coordination.
 *
 *   - CVE-2024-43892: unix scm fd refcount imbalance when sendmsg
 *     fails partway through SCM_RIGHTS attach -- the per-fd ref taken
 *     by unix_attach_fds() was dropped twice on the error path.
 *
 *   - CVE-2025-21712 family: an io_uring fd with a registered files
 *     table can be sent over unix sock; gc walks reach the io_uring
 *     fd, which itself holds further fds (some of which may be unix
 *     socks back into the graph), turning a single SCM_RIGHTS send
 *     into a multi-hop graph extension that gc has to handle without
 *     unbounded recursion.
 *
 * Sequence (per BUDGETED inner-loop iteration):
 *   1.  Open three independent socketpair(AF_UNIX, SOCK_DGRAM, 0) pairs
 *       (sv1, sv2, sv3).  Each pair is two endpoints; we use [0] and
 *       [1] as send/recv halves.
 *   2.  Build the cycle:
 *         sendmsg(sv2[1], SCM_RIGHTS=[sv1[0]])
 *         sendmsg(sv3[1], SCM_RIGHTS=[sv2[0]])
 *         sendmsg(sv1[1], SCM_RIGHTS=[sv3[0]])
 *       Each send transfers a kernel ref on the embedded fd's struct
 *       file into the receiving sock's queue (unix_attach_fds path).
 *   3.  close(sv1[0]); close(sv2[0]); close(sv3[0]); -- the original
 *       userspace refs are gone.  The only remaining refs on the
 *       three socks are the SCM_RIGHTS msgs queued on their peers,
 *       and those refs form a closed cycle: cycle is gc fodder.
 *   4.  Trigger gc via one of:
 *       (a) sendmsg over a fourth sock with another SCM_RIGHTS attach
 *           (drives unix_inflight() which schedules gc).
 *       (b) yield via usleep(0) and rely on the workqueue tick.
 *   5.  Race burst (BUDGETED, alternating):
 *       (a) recvmsg(sv2[1]) to drain the SCM_RIGHTS msg queued on the
 *           sv2 peer that holds sv1[0] -- races unix_gc's snapshot of
 *           inflight counts.
 *       (b) open("/dev/null") and sendmsg the new fd on a remaining
 *           unix sock -- exercises unix_attach_fds() while gc may be
 *           walking the same socket table.
 *   6.  Variant (low probability): replace one of the cycle fds with
 *       an io_uring fd carrying a registered files table.  Drives the
 *       multi-hop graph extension shape from the CVE-2025-21712
 *       family.
 *   7.  close(); the kernel cleans up whatever userspace missed via
 *       unix_destruct_scm() once the last ref drops.
 *
 * Brick-safety: AF_UNIX local-only -- no module load, no sysfs writes,
 * no namespace touches.  All sendmsg use MSG_DONTWAIT.  Recv sockets
 * carry SO_RCVTIMEO=1s so a stuck recv cannot pin past child.c's
 * SIGALRM(1s).  Per-process state only, no persistent fs writes.
 *
 * Cap-gate latch: first invocation per process probes
 * socketpair(AF_UNIX, SOCK_DGRAM, 0).  If -EAFNOSUPPORT or
 * -ESOCKTNOSUPPORT (sysroots / kernels with AF_UNIX disabled, vanishingly
 * rare but possible on heavily-stripped images) the latch fires and
 * every subsequent invocation just bumps setup_failed and returns.
 *
 * Header gating: <sys/socket.h> + <sys/un.h> are standard glibc and
 * always present; the fallback stub remains for the !__has_include
 * case for paranoid sysroots.
 *
 * Failure modes treated as benign coverage:
 *   - sendmsg returning EMSGSIZE / EAGAIN: queue full or msg too big
 *     for the iovec; per-step counter just doesn't bump.
 *   - recvmsg returning EAGAIN / no data: the gc may have raced us
 *     and reclaimed the cycle before the recv fired; the lookup +
 *     lock acquisition path still ran.
 *   - close() returning EBADF: a sibling closed the fd between our
 *     setup and teardown; harmless.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<sys/un.h>)

#include <sys/un.h>

#include "jitter.h"
#include "random.h"

#if __has_include(<linux/io_uring.h>)
#include <linux/io_uring.h>
#include <sys/syscall.h>
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
	fd = syscall(SYS_io_uring_setup, UNIX_SCM_IOURING_RING_ENTRIES, &p);
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
 * One outer iteration: build a 3-pair SCM_RIGHTS cycle, drop userspace
 * refs to make it gc-only-reachable, run a small race burst.  All
 * counters are best-effort -- iter_one returns void; the per-step bumps
 * carry the success signal.
 */
static void iter_one(void)
{
	int sv1[2] = { -1, -1 };
	int sv2[2] = { -1, -1 };
	int sv3[2] = { -1, -1 };
	int sv4[2] = { -1, -1 };
	int iouring_fd = -1;
	int extra_fd = -1;
	bool use_iouring;
	bool cycle_ok = false;
	unsigned int races, r;

	if (unix_pair_open(sv1) < 0)
		return;
	if (unix_pair_open(sv2) < 0)
		goto out;
	if (unix_pair_open(sv3) < 0)
		goto out;
	if (unix_pair_open(sv4) < 0)
		goto out;

	/* Optional io_uring variant: ~1-in-8 iterations swap sv1[0] for an
	 * io_uring fd in the cycle.  Drives the multi-hop graph extension
	 * shape that surfaced the CVE-2025-21712 family.  Falls through
	 * silently if io_uring is unavailable. */
	use_iouring = HAVE_IOURING_VARIANT && ONE_IN(8);
	if (use_iouring) {
		iouring_fd = iouring_open();
		if (iouring_fd < 0)
			use_iouring = false;
	}

	/* 2) Build the cycle: each send transfers a kernel ref on the
	 *    embedded fd into the receiving sock's queue.
	 *
	 *    sv2[1] receives sv1[0] (or the io_uring fd in the variant)
	 *    sv3[1] receives sv2[0]
	 *    sv1[1] receives sv3[0]
	 *
	 *    Order matters only insofar as each send transfers a ref --
	 *    the cycle closure happens at the third send. */
	{
		int first_fd = use_iouring ? iouring_fd : sv1[0];
		ssize_t s1, s2, s3;

		s1 = send_scm_fd(sv2[1], first_fd);
		s2 = send_scm_fd(sv3[1], sv2[0]);
		s3 = send_scm_fd(sv1[1], sv3[0]);
		if (s1 >= 0 && s2 >= 0 && s3 >= 0) {
			cycle_ok = true;
			__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_cycle_built_ok,
					   1, __ATOMIC_RELAXED);
			if (use_iouring) {
				__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_iouring_variant_ok,
						   1, __ATOMIC_RELAXED);
			}
		}
	}

	/* 3) Drop userspace refs to the cycle members.  After this the
	 *    cycle is reachable only via the queued SCM_RIGHTS messages
	 *    on the peer ends -- exactly the gc fodder shape. */
	if (cycle_ok) {
		(void)close(sv1[0]); sv1[0] = -1;
		(void)close(sv2[0]); sv2[0] = -1;
		(void)close(sv3[0]); sv3[0] = -1;
		if (use_iouring) {
			(void)close(iouring_fd);
			iouring_fd = -1;
		}
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_close_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* 4) Trigger gc.  Half the time fire a fresh SCM_RIGHTS attach
	 *    over the spare sv4 pair (drives unix_inflight() and the gc
	 *    schedule path); the other half just yield and let the
	 *    workqueue catch up. */
	if (RAND_BOOL()) {
		extra_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (extra_fd >= 0) {
			ssize_t s = send_scm_fd(sv4[1], extra_fd);

			if (s >= 0) {
				__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_trigger_ok,
						   1, __ATOMIC_RELAXED);
			}
			(void)close(extra_fd);
			extra_fd = -1;
		}
	} else {
		(void)usleep(0);
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_trigger_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* 5) Race burst: alternating recvmsg drain (races gc's inflight
	 *    snapshot) and fresh SCM_RIGHTS attach (races gc's socket-
	 *    table walk).  BUDGETED so heavily-loaded fleets shrink the
	 *    burst automatically. */
	races = BUDGETED(CHILD_OP_AF_UNIX_SCM_RIGHTS_GC,
			 UNIX_SCM_RACE_ITERS_BASE);
	if (races > UNIX_SCM_RACE_BUDGET)
		races = UNIX_SCM_RACE_BUDGET;
	if (races == 0U)
		races = 1U;

	for (r = 0; r < races; r++) {
		/* (a) Drain the queued SCM_RIGHTS message on a peer end
		 *     of the cycle.  recv_drain_scm closes any installed
		 *     fds itself so we don't leak refs across iterations. */
		if (sv2[1] >= 0) {
			if (recv_drain_scm(sv2[1]) == 0) {
				__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_recv_ok,
						   1, __ATOMIC_RELAXED);
			}
		}

		/* (b) Fresh SCM_RIGHTS attach over sv4 with a /dev/null
		 *     fd: keeps unix_inflight() / the gc schedule path
		 *     active during the race window. */
		if (sv4[1] >= 0) {
			extra_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
			if (extra_fd >= 0) {
				(void)send_scm_fd(sv4[1], extra_fd);
				(void)close(extra_fd);
				extra_fd = -1;
			}
		}
	}

out:
	if (sv1[0] >= 0) (void)close(sv1[0]);
	if (sv1[1] >= 0) (void)close(sv1[1]);
	if (sv2[0] >= 0) (void)close(sv2[0]);
	if (sv2[1] >= 0) (void)close(sv2[1]);
	if (sv3[0] >= 0) (void)close(sv3[0]);
	if (sv3[1] >= 0) (void)close(sv3[1]);
	if (sv4[0] >= 0) (void)close(sv4[0]);
	if (sv4[1] >= 0) (void)close(sv4[1]);
	if (iouring_fd >= 0) (void)close(iouring_fd);
	if (extra_fd >= 0) (void)close(extra_fd);
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
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT)
			ns_unsupported_af_unix_scm_rights_gc = true;
		return;
	}
	(void)close(sv[0]);
	(void)close(sv[1]);
}

bool af_unix_scm_rights_gc_churn(struct childdata *child)
{
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_af_unix_scm_rights_gc) {
		__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!af_unix_scm_rights_gc_probed) {
		probe_af_unix();
		if (ns_unsupported_af_unix_scm_rights_gc) {
			__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_setup_failed,
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
		iter_one();

	return true;
}

#else  /* !__has_include(<sys/un.h>) */

bool af_unix_scm_rights_gc_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.af_unix_scm_rights_gc_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<sys/un.h>) */
