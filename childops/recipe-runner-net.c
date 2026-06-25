/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/userfaultfd.h>

#include "arch.h"
#include "syscall-gate.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "childops/recipe-runner-internal.h"

/*
 * Send a single fd over an AF_UNIX socket via SCM_RIGHTS ancillary
 * data.  Helper for recipe_net_unix_gc, which needs to construct a
 * deliberate fd-cycle topology in the unix garbage collector's view.
 *
 * Returns the sendmsg() return value (1 on success — the iov is one
 * filler byte; AF_UNIX sendmsg with empty iov but non-empty cmsg is
 * undefined on some kernels, so we always carry at least one data
 * byte).  Negative on failure with errno set.
 */
static ssize_t scm_send_one_fd(int sock, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char filler = 'g';
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));

	iov.iov_base = &filler;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	return sendmsg(sock, &msg, 0);
}

/*
 * Bound on racer-side blocking syscalls in 2nd-thread recipes.  Long
 * enough that a close() consistently lands while the racer is mid-
 * syscall, short enough that pthread_join() returns in well under one
 * alarm tick.  Mirrors close-racer.c's RACER_TIMEOUT_MS.
 */
#define RECIPE_RACER_TIMEOUT_MS		100

/*
 * Latch threshold: if pthread_create fails this many times back-to-back
 * inside a single recipe invocation, stop trying for the rest of it.
 * Mirrors close-racer.c's THREAD_SPAWN_LATCH.  fork_storm or cgroup_churn
 * can push us into EAGAIN territory on nproc/thread limits, and there is
 * no point hammering a limit that won't lift mid-op.
 */
#define RECIPE_THREAD_SPAWN_LATCH	3

/*
 * Recipe 20: AF_UNIX garbage-collector cycle lifecycle.
 *
 * Build two AF_UNIX socketpairs and use SCM_RIGHTS to wire a reference
 * cycle the kernel can only break via unix_gc():
 *
 *   socketpair() -> sv1[0] <-> sv1[1]
 *   socketpair() -> sv2[0] <-> sv2[1]
 *   sendmsg(sv1[0], SCM_RIGHTS, [sv2[1]])  // sv2[1] queued in sv1[1]
 *   sendmsg(sv2[0], SCM_RIGHTS, [sv1[1]])  // sv1[1] queued in sv2[1]
 *
 * After all four user fds are closed, sv1[1] and sv2[1] are kept alive
 * solely by the in-flight refs in each other's receive queues.  No fd
 * table holds them; each is reachable only via the other.  The unix
 * garbage collector (net/unix/garbage.c) has to walk the in-flight
 * graph, identify the unreachable cycle, and tear both down — the path
 * with the long history of UAFs and refcount mismatches (CVE-2021-0920,
 * CVE-2022-32296, the 2024 unix_gc rework, etc.).
 *
 * Random callers of sendmsg+SCM_RIGHTS in trinity rarely build a cycle
 * — they pass random fds, almost never both ends of a freshly-paired
 * socket — so the GC cycle path stays cold without a deliberate recipe
 * to drive it.
 *
 * Cleanup closes anything still open on every exit path.  In the happy
 * case all four fds are already cleared to -1 before we fall through.
 */
bool recipe_net_unix_gc(bool *unsupported __unused__)
{
	int sv1[2] = { -1, -1 };
	int sv2[2] = { -1, -1 };
	bool ok = false;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) < 0)
		goto out;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) < 0)
		goto out;

	if (scm_send_one_fd(sv1[0], sv2[1]) != 1)
		goto out;

	if (scm_send_one_fd(sv2[0], sv1[1]) != 1)
		goto out;

	/* Drop every user-visible reference.  sv1[1] and sv2[1] now live
	 * only via the SCM_RIGHTS payloads queued in each other — a cycle
	 * unreachable from any fdtable.  Closing in this order forces the
	 * GC to reckon with the cycle on the next teardown pass. */
	close(sv1[0]); sv1[0] = -1;
	close(sv1[1]); sv1[1] = -1;
	close(sv2[0]); sv2[0] = -1;
	close(sv2[1]); sv2[1] = -1;

	ok = true;
out:
	if (sv1[0] >= 0)
		close(sv1[0]);
	if (sv1[1] >= 0)
		close(sv1[1]);
	if (sv2[0] >= 0)
		close(sv2[0]);
	if (sv2[1] >= 0)
		close(sv2[1]);
	return ok;
}

/*
 * Racer thread for recipe_net_tcp.  Blocks in poll() with a bounded
 * timeout, then attempts accept() on the (possibly already-closed)
 * listen fd.  Both calls have hard ceilings: poll's is the timeout
 * argument; accept inherits the fd's O_NONBLOCK so it returns
 * immediately with EAGAIN/EBADF/EINVAL regardless of whether the
 * close raced ahead, mid-syscall, or behind it.
 *
 * EBADF is the fdget-vs-close lookup race we are hunting; EINVAL is
 * the in-flight close caught at the LISTEN-state check; success is
 * the close-after-accept-completed sub-window (no peer ever connects,
 * so accept won't actually return a connection — the path is reached
 * only via a pending SYN that landed under the bind+listen window).
 */
struct tcp_racer_arg {
	int listen_fd;
};

static void *tcp_racer_thread(void *arg)
{
	struct tcp_racer_arg *ra = arg;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	struct pollfd pfd;
	int conn;

	pfd.fd = ra->listen_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	(void)poll(&pfd, 1, RECIPE_RACER_TIMEOUT_MS);

	conn = accept(ra->listen_fd, (struct sockaddr *)&sin, &slen);
	if (conn >= 0)
		close(conn);
	return NULL;
}

/*
 * Recipe 21: TCP listening-socket close-vs-accept race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   socket(AF_INET, SOCK_STREAM) -> setsockopt(SO_REUSEADDR) -> bind to
 *   127.0.0.1:0 (kernel picks port) -> listen -> O_NONBLOCK -> spawn
 *   racer thread blocked in poll(POLLIN, 100ms) + accept() -> usleep
 *   0..100us race-window jitter -> close(s) (the race) -> pthread_join.
 *
 * Targets the kernel paths inet_csk_listen_stop, inet_csk_destroy_sock,
 * tcp_close, and the request-sock-queue teardown that fire when a
 * listening socket is destroyed while another task is mid-accept().
 * Threads share the fdtable, which is the bug class — a sibling
 * process closing the same numeric fd in its own table never races
 * with our fdget.  Distinct from recipe_tcp_server (recipe 7) which
 * runs accept-then-close serially on a single thread; this one drives
 * the *concurrent* accept-vs-close window.
 *
 * Bounded racer syscalls (poll with timeout, accept on O_NONBLOCK fd)
 * mean plain pthread_join always returns within ~100ms.  Sidesteps the
 * wedge problem where pthread_cancel against a thread stuck in an
 * uninterruptible read is unreliable and detached threads leak state.
 *
 * THREAD_SPAWN_LATCH=3 consecutive pthread_create failures bails for
 * the rest of the invocation — under nproc/thread limits the EAGAIN
 * won't lift mid-op while fork_storm or cgroup_churn are competing for
 * the budget.
 *
 * Returns ok=true if any cycle reached close+join.  All-cycles-failed
 * counts as partial.  Per-cycle failures are tolerated mid-loop because
 * one bad cycle (e.g. ephemeral port exhaustion under sibling load)
 * shouldn't penalise the whole recipe.
 */
#define RECIPE_NET_TCP_MAX_CYCLES	4

bool recipe_net_tcp(bool *unsupported __unused__)
{
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;
	bool spawn_latched = false;

	cycles = 1 + rnd_modulo_u32(RECIPE_NET_TCP_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct tcp_racer_arg ra;
		struct sockaddr_in sin;
		pthread_t tid;
		int s = -1;
		int one = 1;
		int flags;
		int rc;

		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0)
			continue;

		(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
				 &one, sizeof(one));

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = 0;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			close(s);
			continue;
		}

		if (listen(s, 4) < 0) {
			close(s);
			continue;
		}

		flags = fcntl(s, F_GETFL);
		if (flags >= 0)
			(void)fcntl(s, F_SETFL, flags | O_NONBLOCK);

		ra.listen_fd = s;
		rc = pthread_create(&tid, NULL, tcp_racer_thread, &ra);
		if (rc != 0) {
			close(s);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH) {
				spawn_latched = true;
				break;
			}
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window — 0..100us picks a random sub-window
		 * of the racer's poll/accept to land the close in. */
		if ((rnd_u32() & 0xff) != 0)
			usleep((useconds_t)rnd_modulo_u32(101));

		(void)close(s);

		(void)pthread_join(tid, NULL);

		completed++;
	}

	/* If every cycle was lost to pthread_create EAGAIN under sibling
	 * thread pressure, that's transient nproc/thread exhaustion — not
	 * a recipe failure.  Skip rather than score a partial, which would
	 * keep the picker re-selecting us against a kernel path we never
	 * actually exercised. */
	if (completed == 0 && spawn_latched)
		return true;

	return completed > 0;
}

/*
 * Recipe 25: userfaultfd write-protect lifecycle.
 *
 * open /dev/userfaultfd (or fall back to the userfaultfd() syscall on
 * older kernels) -> UFFDIO_API to negotiate -> mmap a 2-page private
 * anonymous region -> touch both pages so PTEs are present ->
 * UFFDIO_REGISTER with MISSING|WP -> UFFDIO_WRITEPROTECT(MODE_WP) to
 * apply WP across both pages -> UFFDIO_WRITEPROTECT(mode=DONTWAKE) to
 * clear it again -> UFFDIO_UNREGISTER -> munmap -> close.
 *
 * Distinct from recipe 16 (recipe_userfaultfd) which only exercises
 * the MISSING register-mode path.  The WP path is much newer (5.7+
 * for anon, 5.19+ for shmem) and lives on its own ioctl with its own
 * change_pte_range walker (mwriteprotect_range -> uffd_wp_range ->
 * change_protection_range).  The set + clear sequence drives the WP
 * bit toggle in both directions through the same VMA and the same
 * present-PTE walk -- the path the 2024 madvise-vs-WP race fix and
 * the 5.19 shmem-WP backports addressed.
 *
 * Random callers of ioctl rarely guess UFFDIO_WRITEPROTECT against a
 * uffd that's been registered with MODE_WP, so the WP-toggle path
 * stays cold without a deliberate driver.  Touching the pages before
 * registering is required: UFFDIO_WRITEPROTECT walks present PTEs
 * only; an un-faulted region would no-op the toggle and we wouldn't
 * drive the change_protection path we care about.
 *
 * Latch shape covers every way the feature can be absent:
 *   - /dev/userfaultfd open ENOENT     (no devtmpfs entry, older kernel)
 *   - /dev/userfaultfd open EPERM/EACCES (DAC denial)
 *   - userfaultfd() syscall ENOSYS     (CONFIG_USERFAULTFD off)
 *   - userfaultfd() syscall EPERM      (CAP_SYS_PTRACE missing under
 *                                       unprivileged_userfaultfd=0)
 *   - UFFDIO_REGISTER with MODE_WP returning EINVAL
 *                                      (kernel pre-WP support, or arch
 *                                       lacks pte_uffd_wp)
 *   - UFFDIO_WRITEPROTECT itself returning EINVAL
 *                                      (half-supported backport: WP
 *                                       register flag landed but the
 *                                       toggle ioctl did not)
 *
 * Once latched, the dispatcher stops siblings from re-probing the
 * unsupported feature on every recipe pick.
 */
bool recipe_uffd_wp(bool *unsupported)
{
	struct uffdio_api api;
	struct uffdio_register reg;
	struct uffdio_range range;
	struct uffdio_writeprotect wp;
	void *region = MAP_FAILED;
	size_t len = (size_t)page_size * 2;
	int fd = -1;
	bool registered = false;
	bool ok = false;

	fd = open("/dev/userfaultfd", O_CLOEXEC | O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		int open_errno = errno;

		/* /dev/userfaultfd is missing or denied -- fall back to the
		 * userfaultfd() syscall, which on older kernels is the only
		 * way in (and gates on CAP_SYS_PTRACE under
		 * unprivileged_userfaultfd=0). */
		fd = (int)trinity_raw_syscall(__NR_userfaultfd,
				  O_CLOEXEC | O_NONBLOCK);
		if (fd < 0) {
			if (errno == EPERM || errno == EACCES ||
			    errno == ENOSYS || open_errno == ENOENT) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
			}
			goto out;
		}
	}

	memset(&api, 0, sizeof(api));
	api.api = UFFD_API;
	if (ioctl(fd, UFFDIO_API, &api) < 0)
		goto out;

	region = mmap(NULL, len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		goto out;

	/* Populate PTEs.  UFFDIO_WRITEPROTECT walks present PTEs only;
	 * an un-faulted region would no-op the toggle. */
	((volatile char *)region)[0] = 'a';
	((volatile char *)region)[page_size] = 'b';

	memset(&reg, 0, sizeof(reg));
	reg.range.start = (uintptr_t)region;
	reg.range.len = len;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
	if (ioctl(fd, UFFDIO_REGISTER, &reg) < 0) {
		if (errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}
	registered = true;

	/* Set WP across both pages -- drives mwriteprotect_range ->
	 * uffd_wp_range -> change_protection_range with the WP bit
	 * being applied to present PTEs. */
	memset(&wp, 0, sizeof(wp));
	wp.range.start = (uintptr_t)region;
	wp.range.len = len;
	wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
	if (ioctl(fd, UFFDIO_WRITEPROTECT, &wp) < 0) {
		if (errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	/* Clear WP -- same walker, opposite direction.  DONTWAKE skips
	 * the wake step (we have no waiters), so this drives the toggle
	 * without the wake-side bookkeeping that's already covered by
	 * the MISSING-mode recipe. */
	wp.mode = UFFDIO_WRITEPROTECT_MODE_DONTWAKE;
	if (ioctl(fd, UFFDIO_WRITEPROTECT, &wp) < 0)
		goto out;

	range.start = (uintptr_t)region;
	range.len = len;
	if (ioctl(fd, UFFDIO_UNREGISTER, &range) < 0)
		goto out;
	registered = false;

	ok = true;
out:
	if (registered) {
		range.start = (uintptr_t)region;
		range.len = len;
		(void)ioctl(fd, UFFDIO_UNREGISTER, &range);
	}
	if (region != MAP_FAILED)
		(void)munmap(region, len);
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 24: fsnotify cross-fd watch lifecycle.
 *
 * inotify_init1 (watcher fd) -> open a fresh per-pid file under /tmp
 * (modifier fd, kept distinct from the watcher) -> inotify_add_watch
 * on that path -> write/fchmod/close on the modifier fd to drive
 * three distinct event types (IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE)
 * -> non-blocking read on the watcher to drain the queued events ->
 * unlink the file -> non-blocking read again to catch the
 * IN_DELETE_SELF + automatic mark teardown -> inotify_rm_watch ->
 * close watcher.
 *
 * The cross-fd shape is the point.  Recipe 8 (recipe_inotify) only
 * exercises init / add_watch / read / rm_watch / close on /tmp without
 * driving any modifications from a separate fd, so the notification
 * delivery path (fsnotify_call_mark_by_event_type, the per-mark hlist
 * walk that dispatches into inotify_handle_inode_event, the event-
 * queue alloc inside inotify_handle_event) never runs.  Driving the
 * mod operations from a fd that the watcher does not own forces
 * fsnotify to route an event to a mark whose installer holds a
 * different file struct -- the cross-context lifetime path that has
 * historically leaked under teardown races (the 2024 fsnotify_mark
 * refcount fixes, the inotify event-queue bounds tightening, the
 * recurring IN_DELETE_SELF auto-removal UAFs).
 *
 * Random write/fchmod/close calls in trinity rarely hit a path that
 * is actively being watched, and the standalone inotify_add_watch in
 * recipe 8 never fires events because /tmp is too noisy for any
 * specific event to be attributed to it.  The deterministic
 * watcher + fresh-file + cross-fd-mod sequence makes the notification
 * delivery edge fire on every invocation.
 *
 * ENOSYS on inotify_init1 (extremely unlikely on modern kernels but
 * possible on stripped-down builds without CONFIG_INOTIFY_USER)
 * latches the recipe off.  Per-event read failures and individual
 * mod failures are tolerated -- the recipe cares about driving the
 * dispatch path, not about specific event counts arriving.
 */
bool recipe_fsnotify_xwatch(bool *unsupported)
{
	char path[64];
	char buf[1024];
	int wfd = -1;
	int wd = -1;
	int mod = -1;
	ssize_t r __unused__;
	bool ok = false;

	snprintf(path, sizeof(path), "/tmp/trinity-recipe-fsx-%d-%u",
		 (int)mypid(), rnd_u32());

	wfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (wfd < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	mod = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	if (mod < 0)
		goto out;

	wd = inotify_add_watch(wfd, path,
			       IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
			       IN_DELETE_SELF);
	if (wd < 0)
		goto out;

	/* Drive three notification types from the modifier fd that the
	 * watcher does not own.  Each call routes into fsnotify with a
	 * file struct distinct from the one held by the inotify mark --
	 * the cross-context delivery path. */
	if (write(mod, "x", 1) != 1)
		goto out;
	(void)fchmod(mod, 0644);
	close(mod);
	mod = -1;

	/* Drain queued events.  Best-effort -- the read path is what we
	 * care about, not the byte count.  EAGAIN is acceptable on a
	 * heavily loaded box where the wake hasn't propagated yet. */
	r = read(wfd, buf, sizeof(buf));

	if (unlink(path) < 0)
		goto out;

	/* IN_DELETE_SELF + automatic mark teardown.  The watcher mark
	 * stays armed across the unlink and gets torn down by fsnotify
	 * itself rather than the explicit rm_watch below -- that's the
	 * implicit-teardown path the dispatcher has to walk. */
	r = read(wfd, buf, sizeof(buf));

	if (inotify_rm_watch(wfd, wd) < 0 && errno != EINVAL)
		goto out;
	wd = -1;

	ok = true;
out:
	if (wd >= 0)
		(void)inotify_rm_watch(wfd, wd);
	if (mod >= 0)
		close(mod);
	if (wfd >= 0)
		close(wfd);
	(void)unlink(path);
	return ok;
}

/*
 * Recipe 23: AF_INET raw socket sweep.
 *
 * Walks several proto values through socket(AF_INET, SOCK_RAW, X) ->
 * setsockopt -> bind -> shutdown -> close in one pass.  Drives
 * raw_create, raw_hash_sk / raw_v4_hash, the IP-level setsockopt
 * dispatcher, raw_bind, and raw_close in sequence so the per-proto
 * demuxer state lives across multiple lifecycle stages within a
 * single recipe invocation.
 *
 * Random callers of socket() rarely pick AF_INET + SOCK_RAW + a
 * specific IPPROTO; trinity's standard arg picker hits AF_INET with
 * SOCK_STREAM/SOCK_DGRAM and almost never builds the raw-protocol
 * fanout.  The IP_HDRINCL + IP_PKTINFO + IP_RECVERR option triplet
 * each takes its own slot in the inet_sk option mask, and walking all
 * three on the same socket exercises the option-set ordering the
 * isolated-syscall path almost never reaches.
 *
 * Raw sockets are CAP_NET_RAW gated.  EPERM/EACCES on the first
 * socket() call latches the recipe off so siblings stop probing.
 * Subsequent per-proto failures inside the loop are tolerated --
 * kernels can leave specific ipprotos unimplemented (or restricted via
 * /proc/sys/net/ipv4) without the whole feature being absent.
 */
bool recipe_net_raw(bool *unsupported)
{
	static const int protos[] = {
		IPPROTO_RAW,
		IPPROTO_ICMP,
		IPPROTO_UDP,
		IPPROTO_TCP,
	};
	struct sockaddr_in sin;
	unsigned int i;
	unsigned int completed = 0;

	for (i = 0; i < ARRAY_SIZE(protos); i++) {
		int s;
		int one = 1;

		s = socket(AF_INET, SOCK_RAW, protos[i]);
		if (s < 0) {
			if (i == 0 && (errno == EPERM || errno == EACCES ||
				       errno == ENOSYS)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		/* Walk a few IP-level option entries.  IP_HDRINCL is
		 * implicit on IPPROTO_RAW but setting it explicitly drives
		 * the option path; IP_PKTINFO and IP_RECVERR each take their
		 * own slot in the inet_sk option mask. */
		(void)setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
		(void)setsockopt(s, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
		(void)setsockopt(s, IPPROTO_IP, IP_RECVERR, &one, sizeof(one));

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = 0;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		(void)bind(s, (struct sockaddr *)&sin, sizeof(sin));

		(void)shutdown(s, SHUT_RDWR);
		close(s);
		completed++;
	}

	return completed > 0;
}

/*
 * Recipe 22: AF_UNIX SOCK_STREAM out-of-band data lifecycle.
 *
 *   socketpair(AF_UNIX, SOCK_STREAM)
 *   send 8 inline bytes                    // normal data ahead of OOB
 *   send 1 byte, MSG_OOB                   // splits the receive queue
 *   send 4 more inline bytes               // data after the OOB marker
 *   recv 1 byte, MSG_OOB                   // consume the OOB byte
 *   recv up to 16 bytes, normal            // drain around the gap
 *   shutdown(SHUT_WR)                      // stops further writes
 *   recv (best-effort) any straggler
 *   close
 *
 * Drives unix_stream_sendmsg's MSG_OOB path (the urg skb tagging), the
 * unix_stream_read_generic / unix_stream_recv_urg split-and-rejoin
 * logic, and the receive-queue manipulation that has to keep the OOB
 * gap consistent across a normal recv that straddles it.  Sending data
 * both before and after the OOB byte is the structural minimum for
 * exercising the gap-around path — a single OOB byte alone hits a
 * trivial fast path that elides most of the bookkeeping.
 *
 * AF_UNIX OOB has been a recurring source of bugs since it was added
 * (commit 314001f0bf92, 5.15) — skb-extension lifetime issues, the
 * 2023 unix_stream_recv_urg accounting fixes, the splice-vs-OOB races.
 * Random callers of send/recv almost never set MSG_OOB on a SOCK_STREAM
 * AF_UNIX socket, so the path stays cold without a dedicated recipe.
 *
 * EOPNOTSUPP (CONFIG_AF_UNIX_OOB unset, or building on a kernel
 * predating the OOB support) latches the recipe off via *unsupported.
 * EINVAL on OOB send is the same signal under some kernel
 * configurations and is handled the same way.
 */
bool recipe_net_unix_oob(bool *unsupported)
{
	int sv[2] = { -1, -1 };
	char buf[16];
	char oob;
	ssize_t r __unused__;
	bool ok = false;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		goto out;

	if (send(sv[0], "trinity8", 8, 0) != 8)
		goto out;

	if (send(sv[0], "U", 1, MSG_OOB) != 1) {
		if (errno == EOPNOTSUPP || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (send(sv[0], "tail", 4, 0) != 4)
		goto out;

	/* Pull the OOB byte first.  On AF_UNIX SOCK_STREAM the OOB byte
	 * is held in a side slot until consumed; subsequent normal recv
	 * has to skip the gap it left in the inline stream. */
	if (recv(sv[1], &oob, 1, MSG_OOB) != 1)
		goto out;

	/* Drain the inline data — the kernel must stitch together the
	 * pre-OOB and post-OOB segments into one contiguous read.  Best-
	 * effort: short reads are fine, the path under test is the queue
	 * walk, not the byte count. */
	r = recv(sv[1], buf, sizeof(buf), 0);

	if (shutdown(sv[0], SHUT_WR) < 0)
		goto out;

	/* Final non-blocking drain to flush any straggler skb the
	 * shutdown path may have transitioned in.  EAGAIN/0 are both
	 * acceptable; this read is for path coverage, not correctness. */
	r = recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT);

	ok = true;
out:
	if (sv[0] >= 0)
		close(sv[0]);
	if (sv[1] >= 0)
		close(sv[1]);
	return ok;
}
