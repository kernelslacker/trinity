/*
 * inet_listener_rehash_race - drive the TCP listener lhash2 -> ehash
 * bucket-escape race documented by Trail of Bits / OpenAI Security
 * Research.
 *
 * Background.  The IPv4 and IPv6 TCP listener lookup helpers
 * (__inet_lookup_listener / inet_lhash2_lookup, inet6_lhash2_lookup)
 * walk the lhash2 hlist under RCU using sk_nulls_node.  When a
 * listening socket is unhashed and then rehashed as a connected
 * socket, the same sk_nulls_node is relinked into an ehash slot.  A
 * reader mid-walk on lhash2 follows the node's new next pointer into
 * ehash.  The walker never validates the terminal nulls marker before
 * returning, so the listener lookup can return an ehash entry -- in
 * particular a TIME_WAIT sock -- under the lookup's ownership
 * contract.  tcp_v4_rcv() / tcp_v6_rcv() then treat the returned tw
 * struct as a full sock, producing KASAN UAF / refcount WARN.
 *
 * Random per-syscall fuzz driving TCP setsockopt/connect/bind never
 * assembles the concurrent unhash-vs-rehash-vs-lhash2-lookup shape.
 * grep of childops/ pre-op shows zero references to lhash / lhash2;
 * tcp-md5-listener-race.c pounds on listener MD5 install/rotate but
 * does not drive listener-side unhash/rehash transitions.  This op
 * closes that gap.
 *
 * Shape (all inside a single childop invocation; loopback-only):
 *   1. Pick a fixed target port P.  A small pool [P0..P0+7] keeps
 *      independent invocations from step-locking on one bucket while
 *      still concentrating enough race attempts to hit the window.
 *   2. Seed TIME_WAIT on ehash adjacent to lhash2[P]: fork a short
 *      acceptor helper on P (SO_REUSEADDR), fire N zero-linger
 *      clients into it, close them.  RST-close leaves TIME_WAIT on
 *      one side of every connection.  Acceptor terminates when the
 *      last client closes.
 *   3. Fork worker A: tight loop of v4 listener churn on P.
 *      socket(AF_INET,SOCK_STREAM) + SO_REUSEADDR + SO_REUSEPORT +
 *      bind(127.0.0.1:P) + listen(64) + close().  close() drives
 *      inet_unhash() removing the sk_nulls_node from lhash2.
 *   4. Fork worker B: tight loop of v6 listener churn on P.  Same
 *      shape but AF_INET6 / ::1 -- covers inet6_lhash2_lookup as
 *      well as inet_lhash2_lookup.
 *   5. Fork worker C: tight loop of connect+RST clients at port P
 *      from ephemeral source ports.  Each connect() drives an inbound
 *      SYN whose __inet_lookup_listener walks lhash2 concurrently
 *      with the churn in workers A/B.
 *   6. Fork worker D: tight loop of "rehash" attempts -- open a
 *      SOCK_STREAM, bind to the same port with SO_REUSEADDR, then
 *      connect() to a scratch listener on a different port.  connect()
 *      moves the socket from unhashed straight to ehash while the
 *      other workers' listener sockets on the same P are churning.
 *   7. Workers self-bound on CLOCK_MONOTONIC to WALL_CAP_NS; parent
 *      reaps all four via waitpid_eintr(); WIFSIGNALED bumps
 *      sibling_crashed (the exact bug surface -- one worker crashes
 *      when the kernel dereferences the escaped tw sock).
 *
 * Self-gating.  socket(AF_INET,SOCK_STREAM) EOPNOTSUPP / EAFNOSUPPORT
 * / EACCES latches ns_unsupported for the rest of the process's life
 * so the op is a silent no-op on hosts without TCP.  Same shape as
 * qrtr-bind-race / af-unix-peek-race.
 *
 * Brick-safety.  Loopback only; every fd per-worker, closed on
 * _exit(); no rtnetlink, no module load, no globally-reachable
 * resource.  Hard wall-clock cap (300 ms) inside each worker plus
 * an outer BUDGETED cap around the whole run.  child.c's alarm(1)
 * backstops any wedged worker.
 */

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "jitter.h"
#include "rnd.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"

#include "kernel/membarrier.h"
#include "kernel/socket.h"

#define IRR_PORT_BASE			47100U
#define IRR_PORT_POOL			8U
#define IRR_TWSEED_CLIENTS		12U
#define IRR_WORKER_WALL_CAP_NS		(300L * 1000L * 1000L)
#define IRR_OUTER_BASE			2U
#define IRR_OUTER_CAP			4U
/* Fixed port for the temporary AF_INET acceptor that the ADDRFORM arm
 * connects to in step 2.  Sits outside the [PORT_BASE..PORT_BASE+POOL)
 * range so it never conflicts with the race workers. */
#define IRR_ADDRFORM_HELPER_PORT	(IRR_PORT_BASE + IRR_PORT_POOL + 3U)

/* Latched once per process on EAFNOSUPPORT / EACCES / EPROTONOSUPPORT
 * from the bare socket() probe -- means TCP is unusable in this net
 * namespace and no amount of retry will change it. */
static bool ns_unsupported_inet_listener_rehash;
static bool inet_listener_rehash_probed;

static uint16_t pick_target_port(void)
{
	return (uint16_t)(IRR_PORT_BASE + rnd_modulo_u32(IRR_PORT_POOL));
}

/* Best-effort setsockopt: many of these are optional and rejected by
 * some kernels / seccomp profiles.  We swallow errors -- the op works
 * with or without SO_REUSEADDR/SO_REUSEPORT, just at different fault
 * densities. */
static void set_reuse(int s)
{
	int one = 1;

	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
}

static void addr_v4(struct sockaddr_in *sin, uint16_t port)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin->sin_port = htons(port);
}

static void addr_v6(struct sockaddr_in6 *sin6, uint16_t port)
{
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = in6addr_loopback;
	sin6->sin6_port = htons(port);
}

static void probe_inet(struct childdata *child)
{
	int fd;

	inet_listener_rehash_probed = true;
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ns_unsupported_inet_listener_rehash = true;
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}
	close(fd);
}

/*
 * Twait seeder worker (fork()d): open an acceptor listener on port P,
 * spawn N zero-linger clients that connect and immediately RST-close.
 * The acceptor accept()s and closes each; the RST close leaves the
 * client side of the connection in TIME_WAIT on the ehash slots
 * adjacent to lhash2[P].  Exits when all clients drained.  Runs in
 * the forked child only -- noreturn.
 */
static __attribute__((noreturn)) void twseed_worker(uint16_t port)
{
	struct sockaddr_in sin;
	int listener;
	unsigned int i;
	unsigned long n = 0;

	addr_v4(&sin, port);
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	n++;
	if (listener < 0)
		_exit(0);
	set_reuse(listener);
	n += 2; /* two setsockopt calls in set_reuse() */
	n++; /* bind attempt */
	if (bind(listener, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		goto out;
	n++; /* listen attempt */
	if (listen(listener, 64) < 0)
		goto out;
	__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.twseed_listener_ok,
			   1, __ATOMIC_RELAXED);

	for (i = 0; i < IRR_TWSEED_CLIENTS; i++) {
		struct linger lg = { .l_onoff = 1, .l_linger = 0 };
		int c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
		int a;

		n++;
		if (c < 0)
			continue;
		(void)setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		n++;
		if (connect(c, (struct sockaddr *)&sin, sizeof(sin)) == 0 ||
		    errno == EINPROGRESS)
			__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.twseed_ok,
					   1, __ATOMIC_RELAXED);
		n++; /* connect attempt */

		/* Drain any pending accepts so the RST close on the client
		 * side actually flushes an established sock into TIME_WAIT
		 * instead of dropping the SYN.  Non-blocking, so EAGAIN is
		 * expected on empty. */
		while ((a = accept4(listener, NULL, NULL, SOCK_NONBLOCK)) >= 0) {
			close(a);
			n += 2; /* accept4 + close */
		}
		close(c);
		n++;
	}
out:
	close(listener);
	n++;
	{
		struct childdata *tc = this_child();
		const enum child_op_type op = tc ? tc->op_type : NR_CHILD_OP_TYPES;
		childop_direct_syscalls_add(op, n);
	}
	_exit(0);
}

/*
 * Listener-churn worker (fork()d): open a listener, close it, repeat
 * until wall-clock cap.  The close() drives inet_unhash() which
 * removes the sk_nulls_node from lhash2 -- the moment the race reader
 * is trying to walk past.  `family` picks AF_INET (drives
 * inet_lhash2_lookup) or AF_INET6 (drives inet6_lhash2_lookup).
 */
static __attribute__((noreturn)) void churn_worker(int family, uint16_t port)
{
	struct timespec t0;
	unsigned long cycles = 0;
	unsigned long n = 0;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (!budget_elapsed_ns(&t0, IRR_WORKER_WALL_CAP_NS)) {
		int s = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);

		n++;
		if (s < 0)
			break;
		set_reuse(s);
		n += 2; /* two setsockopt calls in set_reuse() */
		if (family == AF_INET) {
			struct sockaddr_in sin;
			addr_v4(&sin, port);
			if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
				close(s);
				n += 2; /* bind + close */
				continue;
			}
		} else {
			struct sockaddr_in6 sin6;
			addr_v6(&sin6, port);
			if (bind(s, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
				close(s);
				n += 2; /* bind + close */
				continue;
			}
		}
		n++; /* bind succeeded */
		if (listen(s, 64) == 0)
			cycles++;
		n++; /* listen attempt */
		/* close() -> inet_unhash().  The lhash2 removal window is
		 * the RCU walker's dereference target. */
		close(s);
		n++;
	}
	if (family == AF_INET)
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.churn_v4_cycles,
				   cycles, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.churn_v6_cycles,
				   cycles, __ATOMIC_RELAXED);
	{
		struct childdata *tc = this_child();
		const enum child_op_type op = tc ? tc->op_type : NR_CHILD_OP_TYPES;
		childop_direct_syscalls_add(op, n);
	}
	_exit(0);
}

/*
 * SYN-driver worker (fork()d): connect+RST clients aimed at port P
 * from ephemeral source ports.  Each connect() enters
 * __inet_lookup_listener on the target, walking lhash2 concurrently
 * with the churn workers above.  Zero-linger + immediate close ensures
 * we don't tie up state and can churn SYNs fast.
 */
static __attribute__((noreturn)) void syn_worker(uint16_t port)
{
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct timespec t0;
	unsigned long sent = 0;
	unsigned long n = 0;

	addr_v4(&sin, port);
	addr_v6(&sin6, port);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (!budget_elapsed_ns(&t0, IRR_WORKER_WALL_CAP_NS)) {
		struct linger lg = { .l_onoff = 1, .l_linger = 0 };
		int c;
		bool v6 = (rnd_u32() & 1U) != 0;

		c = socket(v6 ? AF_INET6 : AF_INET,
			   SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
		n++;
		if (c < 0)
			continue;
		(void)setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		n++;
		if (v6) {
			if (connect(c, (struct sockaddr *)&sin6, sizeof(sin6)) == 0 ||
			    errno == EINPROGRESS)
				sent++;
		} else {
			if (connect(c, (struct sockaddr *)&sin, sizeof(sin)) == 0 ||
			    errno == EINPROGRESS)
				sent++;
		}
		n++; /* connect attempt */
		close(c);
		n++;
	}
	__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.syn_sent,
			   sent, __ATOMIC_RELAXED);
	{
		struct childdata *tc = this_child();
		const enum child_op_type op = tc ? tc->op_type : NR_CHILD_OP_TYPES;
		childop_direct_syscalls_add(op, n);
	}
	_exit(0);
}

/*
 * Rehash worker (fork()d): drive the unhash->rehash-into-ehash side
 * of the race by having a bound socket transition into a connected
 * (ehash) state while the churn workers pound the same port.  We
 * bind the socket to port P with SO_REUSEADDR, then connect() to a
 * scratch port on loopback (which will refuse -- ECONNREFUSED -- and
 * that's fine, the point is the transition through inet_hash / rehash
 * machinery, not a successful connection).  connect() failing still
 * exercises __inet_hash_connect() which is the rehash path.
 */
static __attribute__((noreturn)) void rehash_worker(uint16_t port)
{
	struct sockaddr_in sin_bind, sin_peer;
	struct timespec t0;
	unsigned long cycles = 0;
	unsigned long n = 0;

	addr_v4(&sin_bind, port);
	/* Scratch peer port: unlikely to be listened on; connect will fail
	 * with ECONNREFUSED after the kernel walks its hash tables. */
	addr_v4(&sin_peer, (uint16_t)(IRR_PORT_BASE + IRR_PORT_POOL + 1U));
	sin_peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (!budget_elapsed_ns(&t0, IRR_WORKER_WALL_CAP_NS)) {
		int s = socket(AF_INET,
			       SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

		n++;
		if (s < 0)
			break;
		set_reuse(s);
		n += 2; /* two setsockopt calls in set_reuse() */
		n++; /* bind attempt */
		if (bind(s, (struct sockaddr *)&sin_bind, sizeof(sin_bind)) == 0) {
			/* Non-blocking connect on refused peer completes
			 * synchronously with ECONNREFUSED; either way the
			 * inet_hash_connect path runs. */
			(void)connect(s, (struct sockaddr *)&sin_peer,
				      sizeof(sin_peer));
			n++; /* connect attempt */
			cycles++;
		}
		close(s);
		n++;
	}
	__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.rehash_cycles,
			   cycles, __ATOMIC_RELAXED);
	{
		struct childdata *tc = this_child();
		const enum child_op_type op = tc ? tc->op_type : NR_CHILD_OP_TYPES;
		childop_direct_syscalls_add(op, n);
	}
	_exit(0);
}

/*
 * IPV6_ADDRFORM sequential arm.
 *
 * Drives the seven-step sequence that exposes the ipv6_pinfo UAF:
 *
 *   1. socket(AF_INET6, SOCK_STREAM) -- no IPV6_V6ONLY
 *   2. connect() to ::ffff:127.0.0.1 via a short-lived AF_INET acceptor,
 *      reaching ESTABLISHED with a v4-mapped sk_v6_daddr
 *   3. setsockopt(IPPROTO_IPV6, IPV6_ADDRFORM, PF_INET) -- counts
 *      addrform_returned_zero on success (the only live-arm signal)
 *   4. connect(AF_UNSPEC) -- TCP_CLOSE / disconnect
 *   5. listen(64) on the same fd
 *   6. one AF_INET client SYN + accept() child
 *   7. close(listener) FIRST, then close(child) -- the ordering IS the bug
 *
 * Oracle: KASAN (inet6_cleanup_sock xchg over freed listener memory).
 * Sequential, not a race; runs in the parent child-process context.
 * Returns the number of syscalls issued so the caller can accumulate
 * them into the direct_calls total.
 */
static unsigned long run_addrform_arm(void)
{
	int helper = -1, addrfd = -1, client = -1, child = -1;
	struct sockaddr_in  helper_sin, client_sin;
	struct sockaddr_in6 mapped_sin6;
	struct sockaddr_storage local_ss;
	socklen_t local_len;
	int pf_inet = PF_INET;
	int one     = 1;
	unsigned long n = 0;

	/* Phase 0: spin up a temporary AF_INET acceptor on the helper port.
	 * The AF_INET6 addrfd will connect to it via ::ffff:127.0.0.1, which
	 * the kernel routes through the IPv4 stack.  SO_REUSEADDR lets
	 * concurrent child processes share the port without EADDRINUSE. */
	addr_v4(&helper_sin, (uint16_t)IRR_ADDRFORM_HELPER_PORT);
	helper = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	n++;
	if (helper < 0) {
		__atomic_add_fetch(
			&shm->stats.inet_listener_rehash_race.addrform_setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}
	(void)setsockopt(helper, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	n++;
	(void)setsockopt(helper, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	n++;
	if (bind(helper, (struct sockaddr *)&helper_sin, sizeof(helper_sin)) < 0) {
		__atomic_add_fetch(
			&shm->stats.inet_listener_rehash_race.addrform_setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}
	n++;
	if (listen(helper, 64) < 0) {
		__atomic_add_fetch(
			&shm->stats.inet_listener_rehash_race.addrform_setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}
	n++;

	/* Step 1: socket(AF_INET6, SOCK_STREAM) -- deliberately no IPV6_V6ONLY
	 * so the socket accepts v4-mapped addresses and the kernel sets
	 * sk_v6_daddr to the v4-mapped form on connect(). */
	addrfd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	n++;
	if (addrfd < 0) {
		__atomic_add_fetch(
			&shm->stats.inet_listener_rehash_race.addrform_setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Step 2: connect() to ::ffff:127.0.0.1:HELPER_PORT.  This reaches
	 * TCP_ESTABLISHED with a v4-mapped sk_v6_daddr, satisfying the
	 * ipv6_only_sock() == false gate inside IPV6_ADDRFORM. */
	memset(&mapped_sin6, 0, sizeof(mapped_sin6));
	mapped_sin6.sin6_family = AF_INET6;
	mapped_sin6.sin6_port   = htons((uint16_t)IRR_ADDRFORM_HELPER_PORT);
	/* ::ffff:127.0.0.1 -- bytes 10-11 are 0xff, then the v4 address */
	mapped_sin6.sin6_addr.s6_addr[10] = 0xff;
	mapped_sin6.sin6_addr.s6_addr[11] = 0xff;
	mapped_sin6.sin6_addr.s6_addr[12] = 127;
	mapped_sin6.sin6_addr.s6_addr[15] = 1;
	if (connect(addrfd, (struct sockaddr *)&mapped_sin6,
		    sizeof(mapped_sin6)) < 0) {
		__atomic_add_fetch(
			&shm->stats.inet_listener_rehash_race.addrform_setup_failed,
			1, __ATOMIC_RELAXED);
		goto out;
	}
	n++;

	/* Step 3: setsockopt(IPPROTO_IPV6, IPV6_ADDRFORM, PF_INET).
	 * On success (ret == 0) the socket is converted to AF_INET and
	 * ipv6_pinfo is detached.  addrform_returned_zero is the only way
	 * to confirm the arm is live -- all four kernel gates fail silently
	 * with a plain errno on mismatch, so counting zero-returns is the
	 * sole liveness signal. */
	if (setsockopt(addrfd, IPPROTO_IPV6, IPV6_ADDRFORM,
		       &pf_inet, sizeof(pf_inet)) == 0)
		__atomic_add_fetch(
			&shm->stats.inet_listener_rehash_race.addrform_returned_zero,
			1, __ATOMIC_RELAXED);
	n++;

	/* Step 4: connect(AF_UNSPEC) -- TCP_CLOSE / disconnect.  After this
	 * the socket is TCP_CLOSE with its local port still assigned. */
	{
		struct sockaddr sa_unspec;
		memset(&sa_unspec, 0, sizeof(sa_unspec));
		sa_unspec.sa_family = AF_UNSPEC;
		(void)connect(addrfd, &sa_unspec, sizeof(sa_unspec));
		n++;
	}

	/* Step 5: listen(64) on the same fd.  The socket is TCP_CLOSE and
	 * still bound to the ephemeral local port assigned during connect();
	 * after ADDRFORM it is now AF_INET.  listen() drives
	 * tcp_v4_syn_recv_sock()'s opt_child_init == NULL branch. */
	if (listen(addrfd, 64) < 0)
		goto out;
	n++;

	/* Step 6: discover the listening port via getsockname(), then
	 * drive one SYN from an AF_INET client and accept() the child
	 * socket.  The child inherits any ipv6_pinfo pointer that
	 * ADDRFORM left dangling on the listener. */
	local_len = sizeof(local_ss);
	if (getsockname(addrfd, (struct sockaddr *)&local_ss, &local_len) < 0)
		goto out;
	n++;

	{
		uint16_t listen_port = 0;

		if (local_ss.ss_family == AF_INET)
			listen_port =
				((struct sockaddr_in *)&local_ss)->sin_port;
		else if (local_ss.ss_family == AF_INET6)
			listen_port =
				((struct sockaddr_in6 *)&local_ss)->sin6_port;
		if (listen_port == 0)
			goto out;

		addr_v4(&client_sin, ntohs(listen_port));
		client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		n++;
		if (client < 0)
			goto out;
		if (connect(client, (struct sockaddr *)&client_sin,
			    sizeof(client_sin)) < 0)
			goto out;
		n++;
	}

	child = accept4(addrfd, NULL, NULL, SOCK_CLOEXEC);
	n++;
	if (child < 0)
		goto out;

	__atomic_add_fetch(
		&shm->stats.inet_listener_rehash_race.addrform_child_accepted,
		1, __ATOMIC_RELAXED);

	/* Step 7: close(listener) FIRST, force an RCU grace period via
	 * membarrier(MEMBARRIER_CMD_GLOBAL), then close(child).
	 *
	 * The listener socket is SOCK_RCU_FREE: its memory is reclaimed
	 * via call_rcu, so close(addrfd) only schedules the callback --
	 * the ipv6_pinfo region is still live.  Without a grace period
	 * the child's inet6_cleanup_sock() runs microseconds after
	 * close(addrfd), long before the RCU callback fires, so the
	 * oracle-triggering write lands on a still-live object every
	 * time and KASAN is silent.
	 *
	 * membarrier(MEMBARRIER_CMD_GLOBAL, 0, 0) is synchronize_rcu()
	 * from userspace (kernel/sched/membarrier.c): it issues a
	 * scheduler IPI to every CPU, waiting until each has passed
	 * through a quiescent point.  After it returns the listener's
	 * RCU callback has fired and the ipv6_pinfo region is freed.
	 * close(child) then runs inet6_cleanup_sock() on the freed
	 * memory, which is the write the oracle needs to catch.
	 *
	 * Only a 0 return is counted -- a non-zero return means the
	 * grace period was not guaranteed and the oracle cannot fire. */
	close(addrfd);
	addrfd = -1;
	n++;
	{
		long mb_ret = syscall(__NR_membarrier,
				      MEMBARRIER_CMD_GLOBAL, 0, 0);

		n++;
		if (mb_ret == 0)
			__atomic_add_fetch(
				&shm->stats.inet_listener_rehash_race.addrform_grace_forced,
				1, __ATOMIC_RELAXED);
	}
	close(child);
	child = -1;
	n++;

out:
	if (child  >= 0) { close(child);  n++; }
	if (addrfd >= 0) { close(addrfd); n++; }
	if (client >= 0) { close(client); n++; }
	if (helper >= 0) { close(helper); n++; }
	return n;
}

static void reap_worker(pid_t pid)
{
	int status;

	if (pid <= 0)
		return;
	if (waitpid_eintr(pid, &status, 0) != pid)
		return;
	if (WIFSIGNALED(status))
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.sibling_crashed,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.sibling_reaped_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Run one full race round: TIME_WAIT seed -> four concurrent workers
 * (v4 churn, v6 churn, SYN driver, rehash driver) -> reap all.
 * Returns the number of parent-side syscalls issued so the caller can
 * publish them via childop_direct_syscalls_add() once at op-exit.
 */
static unsigned long run_one_round(void)
{
	uint16_t port = pick_target_port();
	pid_t p_seed, p_v4, p_v6, p_syn, p_rehash;
	unsigned long calls = 0;

	__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.iter,
			   1, __ATOMIC_RELAXED);

	/* Phase 1: TIME_WAIT seed.  Runs to completion before the race
	 * workers spawn so the ehash slot is populated when the churn
	 * begins.  A failed fork() is not fatal -- the race can still
	 * fire, just with lower payoff density. */
	p_seed = fork();
	calls++;
	if (p_seed == 0)
		twseed_worker(port);
	if (p_seed > 0) {
		reap_worker(p_seed);
		calls++;
	} else {
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.fork_failed,
				   1, __ATOMIC_RELAXED);
	}

	/* Phase 2: launch four race workers concurrently. */
	p_v4 = fork();
	calls++;
	if (p_v4 == 0)
		churn_worker(AF_INET, port);
	if (p_v4 < 0)
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.fork_failed,
				   1, __ATOMIC_RELAXED);

	p_v6 = fork();
	calls++;
	if (p_v6 == 0)
		churn_worker(AF_INET6, port);
	if (p_v6 < 0)
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.fork_failed,
				   1, __ATOMIC_RELAXED);

	p_syn = fork();
	calls++;
	if (p_syn == 0)
		syn_worker(port);
	if (p_syn < 0)
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.fork_failed,
				   1, __ATOMIC_RELAXED);

	p_rehash = fork();
	calls++;
	if (p_rehash == 0)
		rehash_worker(port);
	if (p_rehash < 0)
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.fork_failed,
				   1, __ATOMIC_RELAXED);

	if (p_v4 > 0 && p_v6 > 0 && p_syn > 0 && p_rehash > 0)
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.spawn_quad_ok,
				   1, __ATOMIC_RELAXED);

	/* Reap all four in whatever order they finish.  Each is
	 * self-bounded on CLOCK_MONOTONIC (IRR_WORKER_WALL_CAP_NS) so
	 * the outer waitpid can't hang. */
	reap_worker(p_v4);
	if (p_v4 > 0) calls++;
	reap_worker(p_v6);
	if (p_v6 > 0) calls++;
	reap_worker(p_syn);
	if (p_syn > 0) calls++;
	reap_worker(p_rehash);
	if (p_rehash > 0) calls++;

	/* Sequential ADDRFORM arm: runs after the race workers have been
	 * reaped so it does not share ports or timing with the race itself.
	 * Contributes its own syscall count directly to this round's total. */
	calls += run_addrform_arm();

	return calls;
}

bool inet_listener_rehash_race(struct childdata *child)
{
	unsigned int outer_iters, i;
	unsigned long direct_calls = 0;

	__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_inet_listener_rehash) {
		__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!inet_listener_rehash_probed) {
		probe_inet(child);
		if (ns_unsupported_inet_listener_rehash) {
			__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  Matches the guard shape used by every
	 * other childop in this cluster; op_type lives in shm and can be
	 * scribbled by a poisoned-arena sibling write. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	outer_iters = BUDGETED(CHILD_OP_INET_LISTENER_REHASH_RACE,
			       JITTER_RANGE(IRR_OUTER_BASE));
	if (outer_iters == 0U)
		outer_iters = 1U;
	if (outer_iters > IRR_OUTER_CAP)
		outer_iters = IRR_OUTER_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < outer_iters; i++)
		direct_calls += run_one_round();

	__atomic_add_fetch(&shm->stats.inet_listener_rehash_race.completed_ok,
			   1, __ATOMIC_RELAXED);
	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return true;
}
