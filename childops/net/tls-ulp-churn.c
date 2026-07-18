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
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "tls.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/splice.h"
#include "kernel/socket.h"
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
 * cipher_type are stamped in afterwards.  The caller passes in an
 * already-open /dev/urandom fd (or -1) so the open() doesn't repeat
 * inside the rekey burst loop; we fall back to generate_rand_bytes if
 * the fd is unavailable — the resulting key is still random enough to
 * avoid colliding with any fixed test vector inside the kernel. */
static void fill_cinfo_aes_gcm_128(struct tls12_crypto_info_aes_gcm_128 *ci,
				   unsigned short version, int urandom_fd)
{
	memset(ci, 0, sizeof(*ci));

	if (urandom_fd >= 0) {
		ssize_t off = 0;
		size_t want = sizeof(ci->iv) + sizeof(ci->key) +
			      sizeof(ci->salt) + sizeof(ci->rec_seq);
		unsigned char buf[sizeof(ci->iv) + sizeof(ci->key) +
				  sizeof(ci->salt) + sizeof(ci->rec_seq)];

		while ((size_t)off < want) {
			ssize_t n = read(urandom_fd, buf + off, want - off);
			if (n <= 0)
				break;
			off += n;
		}
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
		 * receive queue and stall on watermarks, then exit. */
		int s;
		unsigned char drain[1024];

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
		(void)waitpid_eintr(pid, &status, WNOHANG);
	}
	return -1;

fail:
	close(listener);
	return -1;
}

/* Step 2: install kTLS ULP on the loopback fd.  ENOPROTOOPT means no
 * CONFIG_TLS; EPERM is unusual here (TCP_ULP doesn't typically gate on
 * caps) but treat it the same — neither flips mid-process, so latch the
 * per-process cap-gate and bump setup_failed on either errno.  Returns
 * 0 on success or -1 when tls_ulp_churn should bail to its out: cleanup
 * (s closed, acceptor reaped). */
static int tls_ulp_churn_iter_install_tls_ulp(int s, struct childdata *child)
{
	if (setsockopt(s, IPPROTO_TCP, TCP_ULP, "tls", 3) < 0) {
		if (errno == ENOPROTOOPT || errno == EPERM) {
			ns_unsupported_tls_ulp = true;
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats arrays, same pattern
			 * the child.c dispatch loop uses for the unguarded
			 * write that motivated this guard. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		__atomic_add_fetch(&shm->stats.tls_ulp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.tls_ulp_churn.ulp_install_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/* Steps 3+4: pick TLS 1.2 vs 1.3 randomly so both record-format variants
 * get coverage on the install + rekey paths, then install TLS_TX with a
 * fresh urandom key and TLS_RX matching.  TX install errors latch the
 * per-process gates (ns_unsupported_tls_tx on ENOPROTOOPT/EOPNOTSUPP,
 * ns_unsupported_aes_gcm_128 on EINVAL) and trigger the caller's goto
 * out cleanup.  RX install is best-effort: either succeeds (strparser
 * comes up alongside the TX path) or fails harmlessly.  Writes the
 * chosen version into *version_out so the subsequent rekey burst can
 * stay on the same record-format variant. */
static int tls_ulp_churn_iter_install_keys(int s, unsigned short *version_out,
					   struct childdata *child,
					   int urandom_fd)
{
	struct tls12_crypto_info_aes_gcm_128 cinfo;
	unsigned short version;
	int rc;

	version = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;
	fill_cinfo_aes_gcm_128(&cinfo, version, urandom_fd);

	rc = setsockopt(s, SOL_TLS, TLS_TX, &cinfo, sizeof(cinfo));
	if (rc < 0) {
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * arrays, same pattern the child.c dispatch loop uses for
		 * the unguarded write that motivated this guard. */
		const enum child_op_type op = child->op_type;
		const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

		if (errno == ENOPROTOOPT || errno == EOPNOTSUPP) {
			ns_unsupported_tls_tx = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		} else if (errno == EINVAL) {
			ns_unsupported_aes_gcm_128 = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.tls_ulp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.tls_ulp_churn.tx_install_ok,
			   1, __ATOMIC_RELAXED);

	fill_cinfo_aes_gcm_128(&cinfo, version, urandom_fd);
	(void)setsockopt(s, SOL_TLS, TLS_RX, &cinfo, sizeof(cinfo));

	*version_out = version;
	return 0;
}

/* Steps 5+6: drive tls_sw_sendmsg with a single best-effort send of
 * urandom-keyed payload, then drive tls_sw_splice_eof from /etc/passwd
 * into the TLS-armed socket.  The splice source is opened on demand and
 * closed inline; if /etc/passwd isn't there (chroot, slimmed sysroot)
 * the splice is silently skipped — the rest of the sequence still has
 * coverage value.  Returns void: both syscalls are best-effort and the
 * caller has no branch on either outcome. */
static void tls_ulp_churn_iter_initial_traffic(int s)
{
	unsigned char payload[64];
	int splice_src;

	generate_rand_bytes(payload, sizeof(payload));
	if (send(s, payload, 1 + rnd_modulo_u32(sizeof(payload)),
		 MSG_DONTWAIT | MSG_NOSIGNAL) > 0)
		__atomic_add_fetch(&shm->stats.tls_ulp_churn.send_ok,
				   1, __ATOMIC_RELAXED);

	splice_src = open(SPLICE_SRC_PATH, O_RDONLY | O_CLOEXEC);
	if (splice_src >= 0) {
		off_t off_in = 0;
		ssize_t n;

		n = splice(splice_src, &off_in, s, NULL,
			   SPLICE_MAX_BYTES,
			   SPLICE_F_NONBLOCK | SPLICE_F_MORE);
		if (n > 0)
			__atomic_add_fetch(&shm->stats.tls_ulp_churn.splice_ok,
					   1, __ATOMIC_RELAXED);
		close(splice_src);
	}
}

/* Step 7: rekey burst.  Each iteration installs TLS_TX with a fresh
 * urandom-keyed cinfo and pushes a small send through the just-rotated
 * cipher state; 1-in-8 iterations also shrink SNDBUF and replay the
 * splice path against the rotated key to drive the strparser-on-rekey +
 * tls_sw_splice_eof back-pressure edge.  Iter count is JITTER+BUDGETED
 * around ULP_CHURN_ITERS_BASE; the wall-clock cap fires inline against
 * @t0 whenever the loop spins past STORM_BUDGET_NS regardless of iter
 * count.  Returns void: failed rekey is itself an exercised reject edge
 * (kTLS historically returned EBUSY for in-place TX re-init) so neither
 * outcome triggers a caller-side branch. */
static void tls_ulp_churn_iter_rekey_burst(int s, unsigned short version,
					   const struct timespec *t0,
					   int urandom_fd)
{
	struct tls12_crypto_info_aes_gcm_128 cinfo;
	unsigned char payload[64];
	unsigned int iters, i;
	int rc, sp_src;

	/* Splice source is reused across the whole burst: the coverage
	 * target is the splice path against the rotated key, not a fresh
	 * struct file per iteration.  off_in is passed by pointer so the
	 * fd's f_pos is not consumed; resetting off_in to 0 inside the
	 * loop keeps every splice rooted at the start of the file. */
	sp_src = open(SPLICE_SRC_PATH, O_RDONLY | O_CLOEXEC);

	iters = BUDGETED(CHILD_OP_TLS_ULP_CHURN,
			 JITTER_RANGE(ULP_CHURN_ITERS_BASE));
	for (i = 0; i < iters; i++) {
		if (ns_since(t0) >= STORM_BUDGET_NS)
			break;

		fill_cinfo_aes_gcm_128(&cinfo, version, urandom_fd);
		rc = setsockopt(s, SOL_TLS, TLS_TX, &cinfo, sizeof(cinfo));
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.tls_ulp_churn.rekey_ok,
					   1, __ATOMIC_RELAXED);

			generate_rand_bytes(payload, sizeof(payload));
			(void)send(s, payload,
				   1 + rnd_modulo_u32(sizeof(payload)),
				   MSG_DONTWAIT | MSG_NOSIGNAL);
		}
		/* Failed rekey is itself an exercised reject edge — kTLS
		 * historically returned EBUSY for in-place TX re-init.  We
		 * don't bump a separate counter for it; the runs vs
		 * rekey_ok ratio is the signal. */

		/* Splice back-pressure probe: shrink SNDBUF to a hard floor
		 * and replay the splice path against the just-rotated key.
		 * Drives the strparser-on-rekey + tls_sw_splice_eof
		 * back-pressure edge — the kernel has to spill into its
		 * partial-record retry path when the send buffer can't
		 * absorb the whole splice in one go.  1/8 cadence keeps the
		 * per-iter cost bounded; the rekey burst itself is the
		 * hot path. */
		if (sp_src >= 0 && ONE_IN(8)) {
			int snd = 8192;
			off_t off_in = 0;
			ssize_t n;

			/* SO_SNDBUFFORCE bypasses wmem_max with CAP_NET_ADMIN;
			 * non-privileged callers fall back to SO_SNDBUF where
			 * the kernel-min floor (SOCK_MIN_SNDBUF) still bites. */
			if (setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE,
				       &snd, sizeof(snd)) < 0 &&
			    errno == EPERM)
				(void)setsockopt(s, SOL_SOCKET, SO_SNDBUF,
						 &snd, sizeof(snd));

			n = splice(sp_src, &off_in, s, NULL,
				   SPLICE_MAX_BYTES,
				   SPLICE_F_NONBLOCK | SPLICE_F_MORE);
			if (n > 0)
				__atomic_add_fetch(&shm->stats.tls_ulp_churn.splice_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	if (sp_src >= 0)
		close(sp_src);
}

/* Step 8 + Step 9: drain the RX queue once (recv on the TLS-armed RX
 * path drives tls_sw_recvmsg / tls_strp even on the empty-queue case,
 * which is the strparser teardown vs queue-empty coverage edge) and
 * flush the socket with shutdown(SHUT_RDWR).  Returns void: both
 * syscalls are best-effort and the caller has no branch on either. */
static void tls_ulp_churn_iter_recv_and_shutdown(int s)
{
	unsigned char rxbuf[256];
	ssize_t n;

	n = recv(s, rxbuf, sizeof(rxbuf), MSG_DONTWAIT);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.tls_ulp_churn.recv_ok,
				   1, __ATOMIC_RELAXED);

	(void)shutdown(s, SHUT_RDWR);
}

bool tls_ulp_churn(struct childdata *child)
{
	struct timespec t0;
	pid_t acceptor = -1;
	int s = -1;
	int urandom_fd = -1;
	unsigned short version;

	__atomic_add_fetch(&shm->stats.tls_ulp_churn.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_tls_ulp || ns_unsupported_tls_tx ||
	    ns_unsupported_aes_gcm_128) {
		__atomic_add_fetch(&shm->stats.tls_ulp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	s = open_loopback_pair(&acceptor);
	if (s < 0) {
		__atomic_add_fetch(&shm->stats.tls_ulp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (tls_ulp_churn_iter_install_tls_ulp(s, child) != 0)
		goto out;

	urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

	if (tls_ulp_churn_iter_install_keys(s, &version, child, urandom_fd) != 0)
		goto out;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	tls_ulp_churn_iter_initial_traffic(s);

	tls_ulp_churn_iter_rekey_burst(s, version, &t0, urandom_fd);

	tls_ulp_churn_iter_recv_and_shutdown(s);

out:
	if (urandom_fd >= 0)
		close(urandom_fd);
	if (s >= 0)
		close(s);
	reap_acceptor(acceptor);
	return true;
}
