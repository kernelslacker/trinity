/*
 * sockmap_cork_race — sockmap sk_msg verdict concurrent cork double-free.
 *
 * Bug class: bpf/sockmap cork identity re-checked only after a lock drop
 * → double-free / UAF in kernel/bpf/sockmap.c.  Oracle: KASAN.
 *
 * TRIGGER PATH
 * ------------
 * When a TCP socket is enrolled in a BPF_MAP_TYPE_SOCKMAP with a
 * BPF_PROG_TYPE_SK_MSG / BPF_SK_MSG_VERDICT verdict program attached,
 * every sendmsg() on that socket is routed through tcp_bpf_sendmsg().
 *
 * With MSG_MORE, tcp_bpf_sendmsg() allocates a cork (sk_msg_alloc) and
 * accumulates data before flushing.  When the accumulated data exhausts
 * SO_SNDBUF, sk_msg_alloc() fails and tcp_bpf_sendmsg_do() calls
 * sk_stream_wait_memory() to block until buffer space is available.
 * sk_stream_wait_memory() releases then re-acquires the socket lock
 * around the wait.  During this lock-drop window:
 *
 *   1. Thread A is in sk_stream_wait_memory(), socket lock dropped, still
 *      holding a cork pointer from before the wait.
 *   2. Thread B acquires the socket lock, enters tcp_bpf_sendmsg_do(),
 *      encounters the same cork, flushes and frees it.
 *   3. Thread A's wait completes, it re-acquires the lock and accesses
 *      the now-freed cork → use-after-free / double-free.
 *
 * STRUCTURE PER INVOCATION
 * ------------------------
 *   1. Establish a loopback TCP pair (listener → cli/srv).
 *   2. Create BPF_MAP_TYPE_SOCKMAP, load a minimal BPF_PROG_TYPE_SK_MSG
 *      verdict program (r0 = 1 = SK_PASS; exit), attach it with
 *      BPF_SK_MSG_VERDICT so that every sendmsg on cli routes through
 *      tcp_bpf_sendmsg().
 *   3. Enroll cli in sockmap slot 0 via BPF_MAP_UPDATE_ELEM.
 *   4. Shrink cli's SO_SNDBUF to SNDBUF_FLOOR so sk_msg_alloc() fails
 *      and sk_stream_wait_memory() is reached on small sends.  Set
 *      SO_SNDTIMEO to cap blocking time so no sender thread gets stuck
 *      past the op's wall-clock budget.
 *   5. Leave srv unread initially — back-pressure on cli keeps the send
 *      buffer full.
 *   6. Spawn NSENDERS sender threads; each calls sendmsg(MSG_MORE)
 *      repeatedly with chunks sized ≥ SNDBUF_FLOOR, driving the
 *      sk_stream_wait_memory path on every call.
 *   7. Spawn a drainer thread that periodically recv()s from srv,
 *      freeing buffer space and waking multiple blocked sender threads
 *      simultaneously — the concurrent wakeup is the race window.
 *   8. Join all threads, tear down all fds.
 *
 * SELF-BOUNDING
 * -------------
 * NROUNDS bounds per-sender-thread syscall count.  BUDGET_NS is a
 * wall-clock ceiling checked in the drainer and sender loops.  All
 * sockets and BPF fds are closed on return.  All threads are joined
 * before return so no fd escapes into a detached thread.
 *
 * SO_SNDTIMEO guarantees that blocking sendmsg() calls return within
 * SNDTIMEO_MS even if no buffer space is freed, bounding the worst-case
 * pthread_join() wait to roughly BUDGET_NS + SNDTIMEO_MS.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>

#include "bpf.h"
#include "bpf-syscall.h"
#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/socket.h"

/* Numeric fallbacks for older UAPI headers. */
#ifndef BPF_PROG_TYPE_SK_MSG
# define BPF_PROG_TYPE_SK_MSG		16
#endif
#ifndef BPF_SK_MSG_VERDICT
# define BPF_SK_MSG_VERDICT		7
#endif
#ifndef BPF_MAP_TYPE_SOCKMAP
# define BPF_MAP_TYPE_SOCKMAP		15
#endif

/* Number of concurrent sender threads.  Four gives enough parallelism to
 * reliably land multiple threads in the sk_stream_wait_memory() lock-drop
 * window simultaneously without swamping the SIGALRM budget. */
#define NSENDERS		4

/* Rounds per sender thread.  Kept small enough that NSENDERS threads
 * finish well within BUDGET_NS even if sk_stream_wait_memory blocks for
 * SNDTIMEO_MS on each call. */
#define NROUNDS			24

/* Chunk size for each sendmsg().  Larger than SNDBUF_FLOOR so that a
 * single call reliably exhausts the send buffer and forces the cork
 * alloc → sk_stream_wait_memory() path. */
#define CHUNK_MAX		8192

/* SO_SNDBUF ceiling requested on the client.  The kernel doubles the
 * value internally and enforces a 2×SOCK_MIN_SNDBUF floor; any value
 * here below 4096 is silently clamped up by the kernel. */
#define SNDBUF_FLOOR		4096

/* SO_SNDTIMEO in milliseconds.  Caps the blocking wait inside
 * sk_stream_wait_memory() so no sender thread wedges the pthread_join. */
#define SNDTIMEO_MS		120

/* Wall-clock ceiling for the race loop.  Matches the band used by other
 * recent thrash ops in this tree. */
#define BUDGET_NS		200000000L	/* 200 ms */

/* License string shared by both BPF prog loads. */
static const char scr_license[] = "GPL";

/* Latch: once BPF_MAP_CREATE(SOCKMAP) or BPF_PROG_LOAD(SK_MSG) fails
 * with an irrecoverable error (ENOSYS / EPERM / EINVAL) for this child,
 * stop trying for the rest of its life. */
static int scr_bpf_off;

/* ------------------------------------------------------------------ */
/*  BPF helpers                                                         */
/* ------------------------------------------------------------------ */

static int create_sockmap(unsigned long *tally)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type    = BPF_MAP_TYPE_SOCKMAP;
	attr.key_size    = sizeof(__u32);
	attr.value_size  = sizeof(int);
	attr.max_entries = 4;

	(*tally)++;
	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

/*
 * Load a minimal BPF_PROG_TYPE_SK_MSG verdict program.
 *
 * The program unconditionally returns SK_PASS (= 1), which is the
 * minimal verifier-passing body for SK_MSG programs: the verifier
 * accepts a constant-return program without requiring context loads or
 * helper calls.  All we need is for the program to be attached so that
 * tcp_bpf_sendmsg() is the active send path for enrolled sockets.
 */
static int load_sk_msg_verdict_prog(unsigned long *tally)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 1),	/* r0 = SK_PASS */
		EBPF_EXIT(),
	};
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type  = BPF_PROG_TYPE_SK_MSG;
	attr.insn_cnt   = ARRAY_SIZE(insns);
	attr.insns      = (__u64)(uintptr_t)insns;
	attr.license    = (__u64)(uintptr_t)scr_license;

	(*tally)++;
	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int attach_sk_msg_verdict(int map_fd, int prog_fd,
				 unsigned long *tally)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.target_fd      = map_fd;
	attr.attach_bpf_fd  = prog_fd;
	attr.attach_type    = BPF_SK_MSG_VERDICT;

	(*tally)++;
	return sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
}

static int sockmap_enroll(int map_fd, __u32 key, int sock_fd,
			  unsigned long *tally)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key    = (__u64)(uintptr_t)&key;
	attr.value  = (__u64)(uintptr_t)&sock_fd;
	attr.flags  = 0;	/* BPF_ANY */

	(*tally)++;
	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int sockmap_evict(int map_fd, __u32 key, unsigned long *tally)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key    = (__u64)(uintptr_t)&key;

	(*tally)++;
	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/* ------------------------------------------------------------------ */
/*  TCP loopback pair                                                   */
/* ------------------------------------------------------------------ */

static int make_loopback_pair(int *cli_out, int *srv_out,
			      unsigned long *tally)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	int listener = -1;
	int c = -1, s = -1;
	int one = 1;

	(*tally)++;
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
		goto fail;

	(*tally)++;
	(void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
			 &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port        = 0;

	(*tally)++;
	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto fail;
	(*tally)++;
	if (listen(listener, 1) < 0)
		goto fail;
	(*tally)++;
	if (getsockname(listener, (struct sockaddr *)&addr, &slen) < 0)
		goto fail;

	(*tally)++;
	c = socket(AF_INET, SOCK_STREAM, 0);
	if (c < 0)
		goto fail;

	(*tally)++;
	if (connect(c, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS)
		goto fail;

	(*tally)++;
	s = accept(listener, NULL, NULL);
	if (s < 0)
		goto fail;

	(*tally)++;
	close(listener);
	*cli_out = c;
	*srv_out = s;
	return 0;

fail:
	if (listener >= 0) { (*tally)++; close(listener); }
	if (c >= 0)        { (*tally)++; close(c); }
	if (s >= 0)        { (*tally)++; close(s); }
	return -1;
}

/* ------------------------------------------------------------------ */
/*  Thread arguments and bodies                                         */
/* ------------------------------------------------------------------ */

struct sender_arg {
	int cli_fd;
	unsigned int rounds;
	volatile int *stop;
};

struct drainer_arg {
	int srv_fd;
	volatile int *stop;
};

/*
 * Sender thread — drives the cork alloc → sk_stream_wait_memory path.
 *
 * Each call to sendmsg(MSG_MORE) with a chunk larger than SNDBUF_FLOOR
 * will attempt to append to the corked sk_msg.  Once the socket send
 * buffer is full, sk_msg_alloc() inside tcp_bpf_sendmsg_do() fails and
 * the thread blocks in sk_stream_wait_memory() with the socket lock
 * released.  When the drainer thread frees buffer space, multiple sender
 * threads wake up concurrently and race to re-acquire the lock and
 * access or free the cork.
 */
static void *sender_thread(void *arg)
{
	struct sender_arg *sa = arg;
	unsigned char buf[CHUNK_MAX];
	struct iovec iov;
	struct msghdr msg;
	unsigned int i;

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0xa5, sizeof(buf));
	iov.iov_base = buf;
	msg.msg_iov  = &iov;
	msg.msg_iovlen = 1;

	for (i = 0; i < sa->rounds && !*sa->stop; i++) {
		size_t n;

		/* Large chunk to rapidly fill the send buffer. */
		n = (size_t)(CHUNK_MAX / 2) +
		    (size_t)(rnd_modulo_u32(CHUNK_MAX / 2) + 1);
		iov.iov_len = n;

		/*
		 * Blocking sendmsg(MSG_MORE): engages the cork path in
		 * tcp_bpf_sendmsg_do(), and blocks in sk_stream_wait_memory
		 * when the send buffer is full.  SO_SNDTIMEO caps the
		 * blocking duration so the thread always returns within
		 * the op's wall-clock budget.
		 */
		(void)sendmsg(sa->cli_fd, &msg, MSG_MORE | MSG_NOSIGNAL);

		/*
		 * Every 4th round flush the cork without MSG_MORE.
		 * This drains the cork at the kernel level, exercises the
		 * cork alloc→free cycle, and gives other sender threads a
		 * chance to race the same cork on the next iteration.
		 */
		if ((i & 3) == 3) {
			iov.iov_len = 1;
			(void)sendmsg(sa->cli_fd, &msg, MSG_NOSIGNAL);
		}
	}
	return NULL;
}

/*
 * Drainer thread — periodically reads from the server side to free send
 * buffer space on the client.  Each recv() wakes all threads currently
 * blocked in sk_stream_wait_memory() on the client socket, allowing
 * multiple senders to concurrently re-acquire the lock and race the cork.
 */
static void *drainer_thread(void *arg)
{
	struct drainer_arg *da = arg;
	unsigned char buf[4096];

	while (!*da->stop) {
		/*
		 * Brief sleep before each drain: gives sender threads time
		 * to block in sk_stream_wait_memory() before we free space,
		 * maximising the number of threads that wake up at once.
		 */
		usleep(1000);	/* 1 ms */
		(void)recv(da->srv_fd, buf, sizeof(buf), MSG_DONTWAIT);
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  Childop entry point                                                 */
/* ------------------------------------------------------------------ */

bool sockmap_cork_race(struct childdata *child)
{
	int cli = -1, srv = -1;
	int map_fd = -1, prog_fd = -1;
	int i;
	bool enrolled = false;
	unsigned long direct_calls = 0;

	pthread_t senders[NSENDERS];
	pthread_t drainer_tid;
	bool sender_live[NSENDERS];
	bool drainer_live = false;

	volatile int stop_flag = 0;

	struct sender_arg sa;
	struct drainer_arg da;

	struct timespec race_start;
	struct timeval sndtimeo;
	int sndbuf = SNDBUF_FLOOR;

	__atomic_add_fetch(&shm->stats.sockmap_cork_race.runs, 1,
			   __ATOMIC_RELAXED);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (__atomic_load_n(&scr_bpf_off, __ATOMIC_RELAXED))
		return true;

	memset(sender_live, 0, sizeof(sender_live));

	/* 1. TCP loopback pair. */
	if (make_loopback_pair(&cli, &srv, &direct_calls) < 0) {
		__atomic_add_fetch(&shm->stats.sockmap_cork_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* 2a. Create sockmap. */
	map_fd = create_sockmap(&direct_calls);
	if (map_fd < 0) {
		if (errno == ENOSYS || errno == EPERM || errno == EINVAL ||
		    errno == ENOENT) {
			__atomic_store_n(&scr_bpf_off, 1, __ATOMIC_RELAXED);
			if (valid_op)
				__atomic_store_n(
					&shm->stats.childop.latch_reason[op],
					CHILDOP_LATCH_UNSUPPORTED,
					__ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.sockmap_cork_race.map_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* 2b. Load sk_msg verdict prog. */
	prog_fd = load_sk_msg_verdict_prog(&direct_calls);
	if (prog_fd < 0) {
		if (errno == ENOSYS || errno == EPERM || errno == EINVAL ||
		    errno == ENOENT) {
			__atomic_store_n(&scr_bpf_off, 1, __ATOMIC_RELAXED);
			if (valid_op)
				__atomic_store_n(
					&shm->stats.childop.latch_reason[op],
					CHILDOP_LATCH_UNSUPPORTED,
					__ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.sockmap_cork_race.prog_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* 2c. Attach verdict prog to sockmap. */
	if (attach_sk_msg_verdict(map_fd, prog_fd, &direct_calls) < 0) {
		__atomic_add_fetch(&shm->stats.sockmap_cork_race.attach_failed,
				   1, __ATOMIC_RELAXED);
		/* Attach failure (e.g. CONFIG_BPF_STREAM_PARSER missing) is
		 * non-fatal for this invocation but we stop here since the
		 * sockmap path won't be active without it. */
		goto out;
	}

	/* 3. Enroll cli in sockmap slot 0. */
	if (sockmap_enroll(map_fd, 0, cli, &direct_calls) < 0) {
		__atomic_add_fetch(&shm->stats.sockmap_cork_race.enroll_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	enrolled = true;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* 4. Shrink cli send buffer and set a send timeout. */
	direct_calls++;
	(void)setsockopt(cli, SOL_SOCKET, SO_SNDBUF,
			 &sndbuf, sizeof(sndbuf));

	sndtimeo.tv_sec  = 0;
	sndtimeo.tv_usec = SNDTIMEO_MS * 1000L;
	direct_calls++;
	(void)setsockopt(cli, SOL_SOCKET, SO_SNDTIMEO,
			 &sndtimeo, sizeof(sndtimeo));

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &race_start);

	/* 6. Spawn sender threads. */
	sa.cli_fd = cli;
	sa.rounds = NROUNDS;
	sa.stop   = &stop_flag;

	for (i = 0; i < NSENDERS; i++) {
		if (pthread_create(&senders[i], NULL, sender_thread, &sa) == 0)
			sender_live[i] = true;
	}

	/* 7. Spawn drainer thread. */
	da.srv_fd = srv;
	da.stop   = &stop_flag;
	if (pthread_create(&drainer_tid, NULL, drainer_thread, &da) == 0)
		drainer_live = true;

	/* Wait for budget or for senders to finish, whichever comes first.
	 * Poll in short sleeps rather than blocking in the parent thread so
	 * we can detect budget expiry without waiting for a long SNDTIMEO. */
	while (!budget_elapsed_ns(&race_start, BUDGET_NS))
		usleep(5000);	/* 5 ms poll interval */

	/* Signal all threads to stop and join them. */
	__atomic_store_n(&stop_flag, 1, __ATOMIC_RELAXED);

	for (i = 0; i < NSENDERS; i++) {
		if (sender_live[i])
			pthread_join(senders[i], NULL);
	}
	if (drainer_live)
		pthread_join(drainer_tid, NULL);

	__atomic_add_fetch(&shm->stats.sockmap_cork_race.races_run, 1,
			   __ATOMIC_RELAXED);

out:
	/* Evict the socket from the sockmap before closing, to give the
	 * kernel a clean removal path rather than a stale-entry teardown. */
	if (enrolled)
		(void)sockmap_evict(map_fd, 0, &direct_calls);

	if (cli >= 0) {
		direct_calls++;
		(void)shutdown(cli, SHUT_RDWR);
		direct_calls++;
		close(cli);
	}
	if (srv >= 0) {
		direct_calls++;
		(void)shutdown(srv, SHUT_RDWR);
		direct_calls++;
		close(srv);
	}
	if (prog_fd >= 0) {
		direct_calls++;
		close(prog_fd);
	}
	if (map_fd >= 0) {
		direct_calls++;
		close(map_fd);
	}

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
