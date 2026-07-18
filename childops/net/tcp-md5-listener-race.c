/*
 * tcp_md5_listener_race - drive the TCP MD5 listener early-RST window
 * upstream commit c8f7244c8ccc fixed.
 *
 * tcp_v4_rcv() / tcp_v6_rcv() can drop the only remaining reference on
 * a child sock through tcp_child_process(); the cousin paths that send
 * a RST in response to a malformed segment then dereference the freed
 * child.  The bug only fires when the listener is MD5-protected, the
 * peer's first segment passes MD5 verification far enough to allocate
 * the child, and the segment's wire shape forces the early-RST exit
 * before the child is grafted back onto the accept queue.  Random
 * setsockopt fuzzing emits TCP_MD5SIG in isolation (net/proto/ip-tcp.c)
 * but never assembles listener + per-peer key + tight zero-linger
 * client RST burst, so the racer's response path is unreached.
 *
 * Sequence:
 *   1. listener TCP socket on 127.0.0.1; bind+listen(64); install
 *      TCP_MD5SIG for peer 127.0.0.1/32 with a random key.
 *   2. BUDGETED outer loop: spawn N=4 client sockets in tight
 *      connect()->SO_LINGER{1,0}->close() bursts.  The zero-linger
 *      close drives the kernel to send RST instead of FIN, hitting
 *      tcp_child_process()'s exit-with-RST path on the listener side.
 *   3. Mid-burst, rotate the listener's MD5 key (TCP_MD5SIG with new
 *      bytes for the same peer), then delete it (TCP_MD5SIG with
 *      tcpm_keylen=0).  Mirrors the install/rotate/delete shape used
 *      by tcp-ao-rotate.c on the related TCP-AO surface.
 *   4. Drain the listen queue with accept(SOCK_NONBLOCK) to advance
 *      state machines without blocking; close accepted fds without
 *      read().
 *
 * Self-bounding: BUDGETED + JITTER_RANGE around base 6 with the outer
 * cap holding wall-time near 200ms; client sockets are O_NONBLOCK so
 * a wedged peer cannot pin us past child.c's SIGALRM(1s) safety net.
 * Loopback only.
 *
 * Failure modes (all expected, none propagated as childop failure):
 *   - EOPNOTSUPP/EINVAL/EPERM on the first listener TCP_MD5SIG:
 *     CONFIG_TCP_MD5SIG=n or no permission.  Latched per-process.
 *   - ECONNRESET / EAGAIN / EINPROGRESS on the client side: the burst
 *     is doing its job.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/tcp.h>
#include <string.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/socket.h"
/* tcp_md5sig and TCP_MD5SIG_MAXKEYLEN already arrive via <linux/tcp.h>
 * and are referenced unconditionally by net/proto/ip-tcp.c, so no
 * private fallback is needed here. */

/* Latched once per child: the listener's first TCP_MD5SIG returned
 * EOPNOTSUPP / EINVAL / EPERM.  None flip during this process's
 * lifetime, so further attempts just burn CPU on identical setup. */
static bool ns_unsupported_tcp_md5;

#define MD5_BURST_CLIENTS	4U
#define MD5_OUTER_BASE		6U

static void fill_md5(struct tcp_md5sig *m, const struct sockaddr_in *peer,
		     uint8_t keylen)
{
	memset(m, 0, sizeof(*m));
	memcpy(&m->tcpm_addr, peer, sizeof(*peer));
	m->tcpm_keylen = keylen;
	if (keylen)
		generate_rand_bytes(m->tcpm_key, keylen);
}

static int open_loopback_listener(struct sockaddr_in *addr)
{
	socklen_t slen = sizeof(*addr);
	int one = 1;
	int s;

	/* Non-blocking listener: the drain loop below relies on accept4()
	 * returning EAGAIN on an empty queue.  SOCK_NONBLOCK passed to
	 * accept4() only sets O_NONBLOCK on the accepted fd, not on the
	 * accept() call itself. */
	s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (s < 0)
		return -1;
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr->sin_port = 0;

	if (bind(s, (struct sockaddr *)addr, sizeof(*addr)) < 0)
		goto fail;
	if (listen(s, 64) < 0)
		goto fail;
	if (getsockname(s, (struct sockaddr *)addr, &slen) < 0)
		goto fail;
	return s;
fail:
	close(s);
	return -1;
}

/* One zero-linger client: drives RST on close().  Returns true if at
 * least the connect() egress hit the wire (succeeded or EINPROGRESS). */
static bool burst_one_client(const struct sockaddr_in *srv)
{
	struct linger lg = { .l_onoff = 1, .l_linger = 0 };
	int c;
	bool sent = false;

	c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (c < 0)
		return false;
	(void)setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	if (connect(c, (const struct sockaddr *)srv, sizeof(*srv)) == 0 ||
	    errno == EINPROGRESS)
		sent = true;
	close(c);
	return sent;
}

bool tcp_md5_listener_race(struct childdata *child)
{
	struct sockaddr_in srv_addr;
	struct tcp_md5sig md5;
	int listener;
	unsigned int iters;
	unsigned int i, j;
	int rc;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_tcp_md5)
		return true;

	listener = open_loopback_listener(&srv_addr);
	if (listener < 0) {
		__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/* Install initial MD5 key for the loopback peer.  This is the
	 * call that hits the support gate. */
	fill_md5(&md5, &srv_addr, 16);
	rc = setsockopt(listener, IPPROTO_TCP, TCP_MD5SIG, &md5, sizeof(md5));
	if (rc < 0) {
		if (errno == EOPNOTSUPP || errno == EINVAL || errno == EPERM) {
			ns_unsupported_tcp_md5 = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_md5_set_failed,
				   1, __ATOMIC_RELAXED);
		close(listener);
		return true;
	}
	__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_md5_set_ok, 1,
			   __ATOMIC_RELAXED);
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	iters = BUDGETED(CHILD_OP_TCP_MD5_LISTENER_RACE,
			 JITTER_RANGE(MD5_OUTER_BASE));
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < iters; i++) {
		/* Burst N zero-linger clients into the listener.  Each
		 * close() drives RST and races tcp_child_process()'s
		 * exit path against the listener's MD5 verify state. */
		for (j = 0; j < MD5_BURST_CLIENTS; j++) {
			if (burst_one_client(&srv_addr)) {
				__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_connect_ok,
						   1, __ATOMIC_RELAXED);
				__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_rst_sent_ok,
						   1, __ATOMIC_RELAXED);
			}
		}

		/* Mid-burst rotate: replace the key bytes for the same
		 * peer.  RCU walkers in the verify path may still hold
		 * the old key node when the rotate retires it. */
		fill_md5(&md5, &srv_addr, 16);
		rc = setsockopt(listener, IPPROTO_TCP, TCP_MD5SIG,
				&md5, sizeof(md5));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_md5_set_ok,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_md5_set_failed,
					   1, __ATOMIC_RELAXED);

		/* Drain the accept queue so the state machine advances
		 * without blocking; we don't read() the accepted fd. */
		for (;;) {
			int a = accept4(listener, NULL, NULL, SOCK_NONBLOCK);

			if (a < 0)
				break;
			close(a);
		}

		/* Delete the MD5 key for this peer (keylen=0).  This is
		 * the targeted delete-vs-verify race window: in-flight
		 * SYNs may still be inside the verify path with the
		 * just-yanked key. */
		fill_md5(&md5, &srv_addr, 0);
		rc = setsockopt(listener, IPPROTO_TCP, TCP_MD5SIG,
				&md5, sizeof(md5));
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_md5_set_ok,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_md5_set_failed,
					   1, __ATOMIC_RELAXED);

		/* Reinstall for the next outer iteration so the rotate
		 * loop has a key to delete again. */
		fill_md5(&md5, &srv_addr, 16);
		(void)setsockopt(listener, IPPROTO_TCP, TCP_MD5SIG,
				 &md5, sizeof(md5));
	}

	close(listener);
	__atomic_add_fetch(&shm->stats.tcp_md5_listener_race_completed_ok, 1,
			   __ATOMIC_RELAXED);
	return true;
}
