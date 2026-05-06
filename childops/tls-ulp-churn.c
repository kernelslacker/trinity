/*
 * tls_ulp_churn - kTLS ULP install + key rotate + splice over a single
 * loopback socket.
 *
 * The companion tls_rotate childop drives the install / rekey lifecycle
 * across a *pair* of TLS-armed sockets, which exercises tls_sw_sendmsg
 * + tls_sw_recvmsg cleanly but leaves splice_eof / strparser-on-rekey
 * mostly untouched.  This childop opens a single loopback peer instead
 * and folds three drivers into one short sequence:
 *
 *   1. socket -> connect to a one-shot loopback acceptor
 *   2. setsockopt(TCP_ULP, "tls")
 *   3. setsockopt(TLS_TX, &cinfo) with a urandom-keyed
 *      tls12_crypto_info_aes_gcm_128
 *   4. setsockopt(TLS_RX, &cinfo) matching, so the strparser path is
 *      armed on the receive side
 *   5. send() to drive tls_sw_sendmsg
 *   6. splice() from a regular-file fd into the TLS socket — drives
 *      tls_sw_splice_eof, the bug-rich edge that flat fuzzing never
 *      reaches because it requires the whole TLS lifecycle plus a
 *      splice_to-capable source fd
 *   7. setsockopt(TLS_TX, &cinfo) AGAIN with a fresh urandom key —
 *      mid-stream rekey, the canonical race window covered by the kTLS
 *      UAF / OOB family in net/tls/tls_strp.c and net/tls/tls_sw.c
 *   8. send() / recv() through the rotated key
 *   9. shutdown / close
 *
 * Three runtime latches keep the per-iteration cost on configurations
 * that can't reach the path:
 *   - ns_unsupported_tls_ulp:  TCP_ULP "tls" returns ENOPROTOOPT/EPERM
 *     (no CONFIG_TLS, no CAP_NET_ADMIN required for ULP install but
 *     module gating still applies).
 *   - ns_unsupported_tls_tx:   TLS_TX returns ENOPROTOOPT/EINVAL/
 *     EOPNOTSUPP — TLS framework present but TX install path refuses.
 *   - ns_unsupported_aes_gcm_128: TLS_TX returns EINVAL specifically
 *     against the AES-GCM-128 cinfo (alg gated by CONFIG_TLS or by the
 *     crypto layer not registering aes-gcm).
 *
 * Self-bounding: BUDGETED + JITTER_RANGE around a small base (3 ±50%)
 * caps the inner loop, every send/recv/splice uses MSG_DONTWAIT or
 * SPLICE_F_NONBLOCK, and the loopback acceptor is torn down at the end
 * of the call.  The acceptor is a forked subprocess that just accept()s
 * once and exits — it can't outlive the iteration.  Loopback-only;
 * splice source is /etc/passwd O_RDONLY so we read a small,
 * predictable, regular file.
 *
 * Header gating: the install structs come from <linux/tls.h>; we
 * already ship a private include/tls.h with the cipher constants and a
 * minimal tls_crypto_info, so the only header we have to gate is the
 * full tls12_crypto_info_aes_gcm_128 struct definition.  __has_include
 * picks up <linux/tls.h> when present and we emit a minimal local
 * fallback otherwise so the source compiles on stripped sysroots.
 * TLS_TX / TLS_RX optnames are already in include/tls.h, no fallback
 * needed for those.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "compat.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "tls.h"
#include "trinity.h"

/* tls12_crypto_info_aes_gcm_128 and TLS_CIPHER_AES_GCM_128 / TLS_TX /
 * TLS_RX optnames are all provided by include/tls.h above, which
 * shadows the toolchain's <linux/tls.h> intentionally so trinity
 * builds the same way against stripped sysroots.  Don't pull
 * <linux/tls.h> in here — it would redefine the same structs and the
 * build fails. */

/* Latched per-child gates.  None of these flip during a child's
 * lifetime (kernel config / module presence / crypto registration are
 * all static), so once we've paid the EFAIL we stop probing and just
 * bump the runs+setup_failed pair on subsequent invocations. */
static bool ns_unsupported_tls_ulp;
static bool ns_unsupported_tls_tx;
static bool ns_unsupported_aes_gcm_128;

/* Inner-loop iter base for the rekey burst.  Real value gets ±50%
 * jitter via JITTER_RANGE() and per-op multiplier scaling via
 * BUDGETED() so productive runs grow the burst on their own. */
#define ULP_CHURN_ITERS_BASE	3U

/* Wall-clock cap on the whole iteration.  Mirrors the storm-style
 * ops: any single invocation that overruns this gets cut short rather
 * than spinning to the SIGALRM(1s) boundary inherited from child.c. */
#define STORM_BUDGET_NS		200000000L	/* 200 ms */

/* Splice source.  Regular file, world-readable, supports splice_to
 * via generic_file_splice_read on every filesystem we care about.
 * The procfs and sysfs alternatives don't implement splice cleanly. */
#define SPLICE_SRC_PATH		"/etc/passwd"

/* Cap the per-splice byte count so a wedged loopback peer never makes
 * us fill its receive window with the file's contents. */
#define SPLICE_MAX_BYTES	256U

/* Fill an aes_gcm_128 cinfo with fresh urandom-derived material:
 * iv + salt + key + rec_seq are randomised together; version and
 * cipher_type are stamped in afterwards.  rand_bytes_or_zero falls
 * back to generate_rand_bytes if /dev/urandom isn't available — the
 * resulting key is still random enough to avoid colliding with any
 * fixed test vector inside the kernel. */
static void fill_cinfo_aes_gcm_128(struct tls12_crypto_info_aes_gcm_128 *ci,
				   unsigned short version)
{
	int fd;

	memset(ci, 0, sizeof(*ci));

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t off = 0;
		size_t want = sizeof(ci->iv) + sizeof(ci->key) +
			      sizeof(ci->salt) + sizeof(ci->rec_seq);
		unsigned char buf[sizeof(ci->iv) + sizeof(ci->key) +
				  sizeof(ci->salt) + sizeof(ci->rec_seq)];

		while ((size_t)off < want) {
			ssize_t n = read(fd, buf + off, want - off);
			if (n <= 0)
				break;
			off += n;
		}
		close(fd);
		if ((size_t)off == want) {
			memcpy(ci->iv,      buf, sizeof(ci->iv));
			memcpy(ci->key,     buf + sizeof(ci->iv),
			       sizeof(ci->key));
			memcpy(ci->salt,    buf + sizeof(ci->iv) +
			       sizeof(ci->key), sizeof(ci->salt));
			memcpy(ci->rec_seq, buf + sizeof(ci->iv) +
			       sizeof(ci->key) + sizeof(ci->salt),
			       sizeof(ci->rec_seq));
		} else {
			generate_rand_bytes((unsigned char *)ci->iv,
					    sizeof(ci->iv));
			generate_rand_bytes((unsigned char *)ci->key,
					    sizeof(ci->key));
			generate_rand_bytes((unsigned char *)ci->salt,
					    sizeof(ci->salt));
			generate_rand_bytes((unsigned char *)ci->rec_seq,
					    sizeof(ci->rec_seq));
		}
	} else {
		generate_rand_bytes((unsigned char *)ci->iv, sizeof(ci->iv));
		generate_rand_bytes((unsigned char *)ci->key, sizeof(ci->key));
		generate_rand_bytes((unsigned char *)ci->salt, sizeof(ci->salt));
		generate_rand_bytes((unsigned char *)ci->rec_seq,
				    sizeof(ci->rec_seq));
	}

	ci->info.version     = version;
	ci->info.cipher_type = TLS_CIPHER_AES_GCM_128;
}

/* Fork a one-shot loopback acceptor.  Parent ends up connected (or
 * EINPROGRESS) to *out_addr; the child accept()s once, drains anything
 * the parent sends, and exits.  Returns the connected client fd on
 * success, -1 on failure.  The acceptor pid is reaped via waitpid() in
 * the caller's cleanup path so a half-built pair never leaves a
 * zombie. */
static int open_loopback_pair(pid_t *out_pid)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	int listener;
	int cli = -1;
	int one = 1;
	pid_t pid;

	*out_pid = -1;

	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		return -1;
	(void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto fail;
	if (listen(listener, 1) < 0)
		goto fail;
	if (getsockname(listener, (struct sockaddr *)&addr, &slen) < 0)
		goto fail;

	pid = fork();
	if (pid < 0)
		goto fail;
	if (pid == 0) {
		/* Acceptor child.  accept() one connection, drain a small
		 * amount of data so the parent's sends don't all go to the
		 * receive queue and stall on watermarks, then exit.  Cap the
		 * lifetime with our own SIGALRM in case the parent dies
		 * before connect()ing. */
		int s;
		unsigned char drain[1024];

		alarm(2);
		s = accept(listener, NULL, NULL);
		if (s >= 0) {
			ssize_t n;
			int loops = 16;

			while (loops-- > 0) {
				n = recv(s, drain, sizeof(drain), MSG_DONTWAIT);
				if (n <= 0)
					break;
			}
			close(s);
		}
		close(listener);
		_exit(0);
	}

	cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (cli < 0) {
		close(listener);
		goto reap;
	}
	(void)fcntl(cli, F_SETFL, O_NONBLOCK);
	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS) {
		close(cli);
		cli = -1;
		close(listener);
		goto reap;
	}
	close(listener);

	*out_pid = pid;
	return cli;

reap:
	{
		int status;
		(void)waitpid(pid, &status, WNOHANG);
	}
	return -1;

fail:
	close(listener);
	return -1;
}

static void reap_acceptor(pid_t pid)
{
	int status;
	int waited = 0;

	if (pid <= 0)
		return;

	/* The acceptor exits as soon as its peer closes, which we do
	 * before this call.  Bound the wait with a few WNOHANG polls
	 * separated by short sleeps; if it still hasn't gone, send a
	 * SIGTERM and reap blocking. */
	while (waited++ < 8) {
		pid_t r = waitpid(pid, &status, WNOHANG);
		if (r == pid || r < 0)
			return;
		{
			struct timespec ts = { 0, 1000000L };  /* 1 ms */
			(void)nanosleep(&ts, NULL);
		}
	}
	(void)kill(pid, SIGTERM);
	(void)waitpid(pid, &status, 0);
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

bool tls_ulp_churn(struct childdata *child)
{
	struct tls12_crypto_info_aes_gcm_128 cinfo;
	unsigned char payload[64];
	unsigned char rxbuf[256];
	struct timespec t0;
	pid_t acceptor = -1;
	int s = -1;
	int splice_src = -1;
	unsigned short version;
	unsigned int iters;
	unsigned int i;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.tls_ulp_churn_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_tls_ulp || ns_unsupported_tls_tx ||
	    ns_unsupported_aes_gcm_128) {
		__atomic_add_fetch(&shm->stats.tls_ulp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	s = open_loopback_pair(&acceptor);
	if (s < 0) {
		__atomic_add_fetch(&shm->stats.tls_ulp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/* Step 2: install kTLS ULP.  ENOPROTOOPT means no CONFIG_TLS;
	 * EPERM is unusual here (TCP_ULP doesn't typically gate on
	 * caps) but treat it the same — neither flips mid-process. */
	if (setsockopt(s, IPPROTO_TCP, TCP_ULP, "tls", 3) < 0) {
		if (errno == ENOPROTOOPT || errno == EPERM)
			ns_unsupported_tls_ulp = true;
		__atomic_add_fetch(&shm->stats.tls_ulp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tls_ulp_churn_ulp_install_ok,
			   1, __ATOMIC_RELAXED);

	/* Step 3: install TLS_TX with a fresh urandom key.  Pick TLS 1.2
	 * vs 1.3 randomly so both record-format variants get coverage on
	 * the install + rekey paths. */
	version = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;
	fill_cinfo_aes_gcm_128(&cinfo, version);

	rc = setsockopt(s, SOL_TLS, TLS_TX, &cinfo, sizeof(cinfo));
	if (rc < 0) {
		if (errno == ENOPROTOOPT || errno == EOPNOTSUPP)
			ns_unsupported_tls_tx = true;
		else if (errno == EINVAL)
			ns_unsupported_aes_gcm_128 = true;
		__atomic_add_fetch(&shm->stats.tls_ulp_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tls_ulp_churn_tx_install_ok,
			   1, __ATOMIC_RELAXED);

	/* Step 4: install TLS_RX matching.  Errors here are not gated
	 * because the install side is what guards the latches; the RX
	 * arm is best-effort and either succeeds (strparser comes up
	 * alongside the TX path) or fails harmlessly. */
	fill_cinfo_aes_gcm_128(&cinfo, version);
	(void)setsockopt(s, SOL_TLS, TLS_RX, &cinfo, sizeof(cinfo));

	/* Step 5: drive tls_sw_sendmsg. */
	generate_rand_bytes(payload, sizeof(payload));
	if (send(s, payload, 1 + ((unsigned int)rand() % sizeof(payload)),
		 MSG_DONTWAIT | MSG_NOSIGNAL) > 0)
		__atomic_add_fetch(&shm->stats.tls_ulp_churn_send_ok,
				   1, __ATOMIC_RELAXED);

	/* Step 6: drive tls_sw_splice_eof.  The splice source is a
	 * regular file fd we open on demand; if /etc/passwd isn't there
	 * (chroot, slimmed sysroot) we silently skip — the rest of the
	 * sequence still has coverage value. */
	splice_src = open(SPLICE_SRC_PATH, O_RDONLY | O_CLOEXEC);
	if (splice_src >= 0) {
		off_t off_in = 0;
		ssize_t n;

		n = splice(splice_src, &off_in, s, NULL,
			   SPLICE_MAX_BYTES,
			   SPLICE_F_NONBLOCK | SPLICE_F_MORE);
		if (n > 0)
			__atomic_add_fetch(&shm->stats.tls_ulp_churn_splice_ok,
					   1, __ATOMIC_RELAXED);
		close(splice_src);
		splice_src = -1;
	}

	/* Step 7: rekey burst.  Each iteration installs TLS_TX with a
	 * fresh urandom key and pushes a small send through the just-
	 * rotated cipher state.  Iter count is jittered + budgeted; the
	 * wall-clock cap fires if the loop spins past STORM_BUDGET_NS
	 * regardless of iter count. */
	iters = BUDGETED(CHILD_OP_TLS_ULP_CHURN,
			 JITTER_RANGE(ULP_CHURN_ITERS_BASE));
	for (i = 0; i < iters; i++) {
		if (ns_since(&t0) >= STORM_BUDGET_NS)
			break;

		fill_cinfo_aes_gcm_128(&cinfo, version);
		rc = setsockopt(s, SOL_TLS, TLS_TX, &cinfo, sizeof(cinfo));
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.tls_ulp_churn_rekey_ok,
					   1, __ATOMIC_RELAXED);

			generate_rand_bytes(payload, sizeof(payload));
			(void)send(s, payload,
				   1 + ((unsigned int)rand() % sizeof(payload)),
				   MSG_DONTWAIT | MSG_NOSIGNAL);
		}
		/* Failed rekey is itself an exercised reject edge — kTLS
		 * historically returned EBUSY for in-place TX re-init.  We
		 * don't bump a separate counter for it; the runs vs
		 * rekey_ok ratio is the signal. */
	}

	/* Step 8: recv whatever the acceptor managed to send back (it
	 * doesn't, but recv()ing on the TLS-armed RX path drives
	 * tls_sw_recvmsg / tls_strp on an empty queue, which is its own
	 * coverage edge — strparser teardown vs queue-empty). */
	{
		ssize_t n = recv(s, rxbuf, sizeof(rxbuf), MSG_DONTWAIT);
		if (n > 0)
			__atomic_add_fetch(&shm->stats.tls_ulp_churn_recv_ok,
					   1, __ATOMIC_RELAXED);
	}

	(void)shutdown(s, SHUT_RDWR);

out:
	if (splice_src >= 0)
		close(splice_src);
	if (s >= 0)
		close(s);
	reap_acceptor(acceptor);
	return true;
}
