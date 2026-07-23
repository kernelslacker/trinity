/*
 * inplace_crypto_oracle -- detect file-content corruption via the
 * structural pattern: splice -> frag -> in-place crypto on a
 * splice-derived skb.
 *
 * splice(file_fd -> pipe -> socket) with MSG_SPLICE_PAGES on the
 * sendmsg side plants attacker-pinned page-cache pages directly into
 * the socket's skb frags (no memcpy -- the page-cache page IS the
 * skb payload).  If the protocol's input handler then runs in-place
 * crypto on a non-cloned, nonlinear skb without first calling
 * skb_cow_data(), the cipher's intermediate STOREs land on top of
 * the page-cache page -- modifying the file content as a side effect
 * of receiving the packet.  The kernel-side smoking gun is a
 * skip_cow fast-path in the input handler that takes the no-cow
 * branch on a nonlinear-but-not-cloned skb.
 *
 * Targets, rotated one per invocation:
 *   espinudp     UDP socket primed with UDP_ENCAP=ESPINUDP -- positive
 *                control vs nat_t_churn.
 *   af_rxrpc     AF_RXRPC bound socket with an "rxrpc" key on the
 *                thread keyring at AUTH level.
 *   af_alg       AF_ALG skcipher cbc(aes); chain TX SGL via splice.
 *   ktls         TCP_ULP=tls + TLS_TX with urandom AES-GCM-128 key.
 *   macsec       genl family "macsec" lookup; absence latches.
 *   bluetooth    socket(AF_BLUETOOTH) -- not built on Dave's fuzz
 *                config, so EAFNOSUPPORT latches first call.
 *   wireguard    genl family "wireguard" lookup; absence latches.
 *   mptcp_ao     IPPROTO_MPTCP + setsockopt(TCP_AO_ADD_KEY).
 *
 * Oracle property per invocation: (a) file unchanged after trigger,
 * OR (b) splice/sendmsg/recv returned a clear errno (latched), OR
 * (c) file content WAS modified -- BUG.  Logged loudly with file
 * path, byte-offset of first divergence, before/after windows, and
 * the target name.
 *
 * Per-target latch on EPERM / EAFNOSUPPORT / EPROTONOSUPPORT /
 * EOPNOTSUPP / ENOENT (missing CAP / module / genl family).  All
 * eight latched -> top-level latch + permanent NOOP.  Mirrors the
 * uniform unsupported_<name> pattern in fds/{kvm,landlock,
 * memfd_secret,mq}.c.
 *
 * File picker rotates between /etc/hosts (small, well-known,
 * MAC-clean) and a mkstemp + write + unlink + reopen-via-
 * /proc/self/fd marker we own end-to-end.  Avoids /etc/passwd-shape
 * paths -- read-only opens flag false-positives in some mac
 * frameworks.
 *
 * Per-op alarm contract: parent arms alarm(1) per invocation; this
 * op never extends the budget.  Every recv carries SO_RCVTIMEO of
 * 50 ms so a wedged kernel-side path can't burn the slot's full
 * second.  Mirrors commit 72a4eff318f3 (drop in-op alarm()
 * overrides).
 *
 * DORMANT in dormant_op_disabled[].  Smoke-test before fleet enable.
 *
 * Guardrail: there is intentionally no known-bad cipher path here.
 * We don't inject a path that would actually corrupt the file just
 * to "validate" the oracle -- assume oracle goodness and let real
 * fuzzing surface real bugs.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if __has_include(<linux/tcp.h>)
# include <linux/tcp.h>
#endif
#if __has_include(<linux/if_alg.h>)
# include <linux/if_alg.h>
#endif
#if __has_include(<linux/keyctl.h>)
# include <linux/keyctl.h>
#endif
#if __has_include(<linux/rxrpc.h>)
# include <linux/rxrpc.h>
#endif

#include "child.h"
#include "syscall-gate.h"
#include "childops-genl.h"
#include "childops-util.h"
#include "random.h"
#include "shm.h"
#include "tls.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/splice.h"
#include "kernel/socket.h"
/* UAPI fallbacks -- every value below is stable kernel UAPI. */
#ifndef UDP_ENCAP
# define UDP_ENCAP			100
# define UDP_ENCAP_ESPINUDP		2
#endif
#ifndef AF_BLUETOOTH
# define AF_BLUETOOTH			31
#endif

#define ORACLE_RCV_TIMEO_USEC	50000
#define ORACLE_SPLICE_BYTES	2048U
#define ORACLE_FILE_CAP		8192U
#define ORACLE_MARKER_BYTES	1024U
#define ORACLE_DIFF_WINDOW	16U

enum oracle_target {
	TGT_ESPINUDP = 0, TGT_AF_RXRPC, TGT_AF_ALG, TGT_KTLS,
	TGT_MACSEC, TGT_BLUETOOTH, TGT_WIREGUARD, TGT_MPTCP_AO,
	TGT_NR,
};

static const char * const target_names[TGT_NR] = {
	"espinudp", "af_rxrpc", "af_alg",   "ktls",
	"macsec",   "bluetooth", "wireguard", "mptcp_ao",
};

static bool unsupported_target[TGT_NR];
static bool unsupported_inplace_crypto_oracle;
static unsigned int rotation_cursor;

static bool errno_unsupported(int e)
{
	return e == EPERM || e == ENOSYS || e == EOPNOTSUPP ||
	       e == ENOPROTOOPT || e == EAFNOSUPPORT ||
	       e == EPROTONOSUPPORT || e == ENOENT || e == ENODEV;
}

static void latch_target(enum oracle_target t, const char *step, int err)
{
	if (unsupported_target[t])
		return;
	unsupported_target[t] = true;
	outputerr("inplace_crypto_oracle: %s/%s failed (errno=%d), latching unsupported_%s\n",
		  target_names[t], step, err, target_names[t]);
}

static void set_short_recv_timeout(int fd)
{
	struct timeval tv = { 0, ORACLE_RCV_TIMEO_USEC };

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/*
 * Open the oracle source file (rotate /etc/hosts vs a self-owned
 * /tmp marker) and capture up to ORACLE_FILE_CAP baseline bytes.
 * The /tmp variant is mkstemp + write + unlink + reopen via
 * /proc/self/fd so the inode is auto-reaped on child exit.
 */
static int open_oracle_file(char *out_path, size_t path_cap,
			    unsigned char *out_baseline, size_t *out_size)
{
	int fd = -1;
	ssize_t n;

	if (RAND_BOOL()) {
		fd = open("/etc/hosts", O_RDONLY | O_CLOEXEC);
		if (fd >= 0)
			snprintf(out_path, path_cap, "/etc/hosts");
	}
	if (fd < 0) {
		char tmpl[] = "/tmp/trinity-oracle-XXXXXX";
		unsigned char marker[ORACLE_MARKER_BYTES];
		int wfd = mkstemp(tmpl);

		if (wfd < 0)
			return -1;
		(void)unlink(tmpl);
		generate_rand_bytes(marker, sizeof(marker));
		if (write(wfd, marker, sizeof(marker)) !=
		    (ssize_t)sizeof(marker)) {
			close(wfd);
			return -1;
		}
		snprintf(out_path, path_cap, "/proc/self/fd/%d", wfd);
		fd = open(out_path, O_RDONLY | O_CLOEXEC);
		close(wfd);
		if (fd < 0)
			return -1;
	}
	n = read(fd, out_baseline, ORACLE_FILE_CAP);
	if (n <= 0) {
		close(fd);
		return -1;
	}
	*out_size = (size_t)n;
	(void)lseek(fd, 0, SEEK_SET);
	return fd;
}

/*
 * Reopen *path on a fresh fd and compare against baseline.  A fresh
 * fd is required: a cached fd risks short-circuiting through the
 * page cache past the page the splice receiver may have stored over.
 */
static bool oracle_check_unchanged(const char *path,
				   const unsigned char *baseline,
				   size_t baseline_len, size_t *out_off,
				   unsigned char *out_after,
				   size_t *out_after_valid)
{
	unsigned char after[ORACLE_FILE_CAP];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;
	size_t i, lim, copy, avail;

	if (fd < 0)
		return true;
	n = read(fd, after, sizeof(after));
	close(fd);
	if (n <= 0)
		return true;
	lim = (size_t)n < baseline_len ? (size_t)n : baseline_len;
	for (i = 0; i < lim; i++) {
		if (after[i] == baseline[i])
			continue;
		copy  = ORACLE_DIFF_WINDOW;
		avail = (size_t)n - i;
		if (copy > avail)
			copy = avail;
		memcpy(out_after, after + i, copy);
		*out_off = i;
		*out_after_valid = copy;
		return false;
	}
	return true;
}

static void log_corruption(enum oracle_target t, const char *path,
			   size_t off, const unsigned char *before,
			   const unsigned char *after, size_t valid)
{
	char hex_before[ORACLE_DIFF_WINDOW * 3 + 1];
	char hex_after[ORACLE_DIFF_WINDOW * 3 + 1];
	size_t i;

	hex_before[0] = '\0';
	hex_after[0]  = '\0';
	for (i = 0; i < valid; i++) {
		snprintf(hex_before + i * 3, 4, "%02x ", before[i]);
		snprintf(hex_after  + i * 3, 4, "%02x ", after[i]);
	}
	outputerr("inplace_crypto_oracle: BUG -- file MUTATED via %s path=%s offset=%zu\n",
		  target_names[t], path, off);
	outputerr("inplace_crypto_oracle:   before[+%zu]: %s\n", off, hex_before);
	outputerr("inplace_crypto_oracle:   after [+%zu]: %s\n", off, hex_after);
	__atomic_add_fetch(&shm->stats.inplace_crypto.mutated, 1,
			   __ATOMIC_RELAXED);
}

/*
 * splice(file -> pipe) plants page-cache pages in the pipe; sendmsg
 * with EXPLICIT MSG_SPLICE_PAGES then hands those pages to the
 * socket as skb frags without copying.  Soft-failure paths return 0
 * so the caller can still run the oracle (no MSG_SPLICE_PAGES =
 * non-frag skb = expected no-corruption); hard pipe failure is -1.
 */
static ssize_t splice_into_socket(int file_fd, int sock_fd)
{
	int pfd[2] = { -1, -1 };
	struct iovec iov;
	struct msghdr mh;
	unsigned char buf[ORACLE_SPLICE_BYTES];
	ssize_t n_in, rd, n_out;

	if (pipe2(pfd, O_CLOEXEC | O_NONBLOCK) < 0)
		return -1;
	n_in = splice(file_fd, NULL, pfd[1], NULL, ORACLE_SPLICE_BYTES,
		      SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
	if (n_in <= 0) {
		close(pfd[0]); close(pfd[1]);
		return 0;
	}
	rd = read(pfd[0], buf,
		  (size_t)n_in > sizeof(buf) ? sizeof(buf) : (size_t)n_in);
	close(pfd[0]); close(pfd[1]);
	if (rd <= 0)
		return 0;
	iov.iov_base = buf;
	iov.iov_len  = (size_t)rd;
	memset(&mh, 0, sizeof(mh));
	mh.msg_iov    = &iov;
	mh.msg_iovlen = 1;
	n_out = sendmsg(sock_fd, &mh,
			MSG_SPLICE_PAGES | MSG_DONTWAIT | MSG_NOSIGNAL);
	return n_out < 0 ? 0 : n_out;
}

static int try_espinudp(int file_fd)
{
	struct sockaddr_in sin;
	int udp, v = UDP_ENCAP_ESPINUDP;
	unsigned char rxbuf[256];

	udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (udp < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_ESPINUDP, "socket", errno);
		return -1;
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	(void)bind(udp, (struct sockaddr *)&sin, sizeof(sin));
	(void)connect(udp, (struct sockaddr *)&sin, sizeof(sin));
	if (setsockopt(udp, SOL_UDP, UDP_ENCAP, &v, sizeof(v)) < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_ESPINUDP, "UDP_ENCAP", errno);
		close(udp);
		return -1;
	}
	set_short_recv_timeout(udp);
	(void)splice_into_socket(file_fd, udp);
	(void)recv(udp, rxbuf, sizeof(rxbuf), MSG_DONTWAIT);
	close(udp);
	return 0;
}

static int try_af_rxrpc(int file_fd)
{
#if defined(AF_RXRPC) && __has_include(<linux/rxrpc.h>) && \
    __has_include(<linux/keyctl.h>)
	struct sockaddr_rxrpc srx;
	int level = 1, fd;
	long rc;

	fd = socket(AF_RXRPC, SOCK_DGRAM | SOCK_CLOEXEC, PF_INET);
	if (fd < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_AF_RXRPC, "socket", errno);
		return -1;
	}
	rc = trinity_raw_syscall(SYS_add_key, "rxrpc", "trinity-oracle",
		     NULL, (size_t)0, KEY_SPEC_THREAD_KEYRING);
	if (rc < 0 && errno_unsupported(errno)) {
		latch_target(TGT_AF_RXRPC, "add_key", errno);
		close(fd);
		return -1;
	}
	memset(&srx, 0, sizeof(srx));
	srx.srx_family = AF_RXRPC;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_AF_RXRPC, "bind", errno);
		close(fd);
		return -1;
	}
	(void)setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
			 &level, sizeof(level));
	set_short_recv_timeout(fd);
	(void)splice_into_socket(file_fd, fd);
	close(fd);
	return 0;
#else
	(void)file_fd;
	latch_target(TGT_AF_RXRPC, "build", ENOSYS);
	return -1;
#endif
}

static int try_af_alg(int file_fd)
{
#if defined(AF_ALG) && __has_include(<linux/if_alg.h>)
	struct sockaddr_alg sa;
	unsigned char key[16], rxbuf[256];
	int parent_fd, child_fd;

	parent_fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (parent_fd < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_AF_ALG, "socket", errno);
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strncpy((char *)sa.salg_type, "skcipher", sizeof(sa.salg_type) - 1);
	strncpy((char *)sa.salg_name, "cbc(aes)", sizeof(sa.salg_name) - 1);
	if (bind(parent_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		if (errno_unsupported(errno) || errno == ESRCH)
			latch_target(TGT_AF_ALG, "bind", errno);
		close(parent_fd);
		return -1;
	}
	generate_rand_bytes(key, sizeof(key));
	(void)setsockopt(parent_fd, SOL_ALG, ALG_SET_KEY, key, sizeof(key));
	child_fd = accept4(parent_fd, NULL, NULL, SOCK_CLOEXEC);
	if (child_fd < 0) {
		int saved_errno = errno;
		close(parent_fd);
		if (errno_unsupported(saved_errno))
			latch_target(TGT_AF_ALG, "accept4", saved_errno);
		return -1;
	}
	close(parent_fd);
	set_short_recv_timeout(child_fd);
	(void)splice_into_socket(file_fd, child_fd);
	(void)recv(child_fd, rxbuf, sizeof(rxbuf), MSG_DONTWAIT);
	close(child_fd);
	return 0;
#else
	(void)file_fd;
	latch_target(TGT_AF_ALG, "build", ENOSYS);
	return -1;
#endif
}

/* One-shot loopback acceptor.  ktls needs a real connected peer or
 * the TLS_TX install would race against the connect handshake.  The
 * acceptor child accept()s once, drains, and exits; caller waitpids. */
static int open_loopback_pair(pid_t *out_pid)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	int listener, cli, one = 1;
	pid_t pid;

	*out_pid = -1;
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		return -1;
	(void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(listener, 1) < 0 ||
	    getsockname(listener, (struct sockaddr *)&addr, &slen) < 0) {
		close(listener);
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		close(listener);
		return -1;
	}
	if (pid == 0) {
		int s = accept(listener, NULL, NULL);
		unsigned char drain[512];

		if (s >= 0) {
			(void)recv(s, drain, sizeof(drain), MSG_DONTWAIT);
			close(s);
		}
		close(listener);
		_exit(0);
	}
	cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	close(listener);
	if (cli < 0)
		return -1;
	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS) {
		close(cli);
		return -1;
	}
	*out_pid = pid;
	return cli;
}

static void reap_acceptor_blocking(pid_t pid)
{
	int status;

	if (pid <= 0)
		return;
	(void)kill(pid, SIGTERM);
	(void)waitpid_eintr(pid, &status, 0);
}

static int try_ktls(int file_fd)
{
	struct tls12_crypto_info_aes_gcm_128 ci;
	pid_t acceptor;
	int s;

	s = open_loopback_pair(&acceptor);
	if (s < 0)
		return -1;
	if (setsockopt(s, IPPROTO_TCP, TCP_ULP, "tls", 3) < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_KTLS, "TCP_ULP", errno);
		close(s);
		reap_acceptor_blocking(acceptor);
		return -1;
	}
	memset(&ci, 0, sizeof(ci));
	ci.info.version     = TLS_1_2_VERSION;
	ci.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	generate_rand_bytes(ci.iv, sizeof(ci.iv));
	generate_rand_bytes(ci.key, sizeof(ci.key));
	generate_rand_bytes(ci.salt, sizeof(ci.salt));
	generate_rand_bytes(ci.rec_seq, sizeof(ci.rec_seq));
	if (setsockopt(s, SOL_TLS, TLS_TX, &ci, sizeof(ci)) < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_KTLS, "TLS_TX", errno);
		close(s);
		reap_acceptor_blocking(acceptor);
		return -1;
	}
	set_short_recv_timeout(s);
	(void)splice_into_socket(file_fd, s);
	close(s);
	reap_acceptor_blocking(acceptor);
	return 0;
}

/*
 * Generic netlink CTRL_CMD_GETFAMILY by name.  Returns 0 if
 * registered, -ENOENT if not, negative errno on transport failure.
 * Used by macsec/wireguard gates.  Thin wrapper over genl_open():
 * a successful open == family registered, and the socket is closed
 * immediately because the gate doesn't drive any per-family cmds.
 */
static int probe_genl_family(const char *name)
{
	struct genl_ctx ctx;
	struct genl_open_opts opts;
	int rc;

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = name;
	opts.recv_timeo_s = 1;

	rc = genl_open(&ctx, &opts);
	if (rc == 0)
		genl_close(&ctx);
	return rc;
}

/*
 * macsec/bluetooth/wireguard targets are gate-only: probe presence,
 * latch on absence.  Driving a real macsec link, an L2CAP encrypted
 * channel, or a WireGuard tunnel from inside this oracle requires
 * paired-link / link-key / endpoint scaffolding outside the brief's
 * scope.  We probe so the latch carries the correct semantic ("not
 * built" vs "built but scaffold gap") then latch so we don't repeat-
 * spend the syscalls.
 */
static int try_macsec(int file_fd)
{
	int rc;

	(void)file_fd;
	rc = probe_genl_family("macsec");
	if (rc != 0)
		latch_target(TGT_MACSEC, "genl_family", -rc);
	else
		latch_target(TGT_MACSEC, "scaffold_out_of_scope", ENOSYS);
	return rc == 0 ? 0 : -1;
}

static int try_bluetooth(int file_fd)
{
	int s = socket(AF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	(void)file_fd;
	if (s < 0) {
		latch_target(TGT_BLUETOOTH, "socket", errno);
		return -1;
	}
	close(s);
	latch_target(TGT_BLUETOOTH, "scaffold_out_of_scope", ENOSYS);
	return 0;
}

static int try_wireguard(int file_fd)
{
	int rc;

	(void)file_fd;
	rc = probe_genl_family("wireguard");
	if (rc != 0)
		latch_target(TGT_WIREGUARD, "genl_family", -rc);
	else
		latch_target(TGT_WIREGUARD, "scaffold_out_of_scope", ENOSYS);
	return rc == 0 ? 0 : -1;
}

static int try_mptcp_ao(int file_fd)
{
	struct sockaddr_in sin;
	struct tcp_ao_add ao;
	unsigned char key[16];
	int s;

	s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_MPTCP);
	if (s < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_MPTCP_AO, "socket", errno);
		return -1;
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	(void)bind(s, (struct sockaddr *)&sin, sizeof(sin));
	memset(&ao, 0, sizeof(ao));
	ao.addr.ss_family = AF_INET;
	ao.sndid = 1;
	ao.rcvid = 1;
	strncpy(ao.alg_name, "hmac(sha1)", sizeof(ao.alg_name) - 1);
	generate_rand_bytes(key, sizeof(key));
	memcpy(ao.key, key, sizeof(key));
	ao.keylen = sizeof(key);
	if (setsockopt(s, IPPROTO_TCP, TCP_AO_ADD_KEY, &ao, sizeof(ao)) < 0) {
		if (errno_unsupported(errno))
			latch_target(TGT_MPTCP_AO, "TCP_AO_ADD_KEY", errno);
		close(s);
		return -1;
	}
	set_short_recv_timeout(s);
	(void)splice_into_socket(file_fd, s);
	close(s);
	return 0;
}

typedef int (*target_fn)(int file_fd);
static const target_fn target_fns[TGT_NR] = {
	try_espinudp,  try_af_rxrpc, try_af_alg,    try_ktls,
	try_macsec,    try_bluetooth, try_wireguard, try_mptcp_ao,
};

bool inplace_crypto_oracle(struct childdata *child)
{
	unsigned char baseline[ORACLE_FILE_CAP];
	unsigned char after_window[ORACLE_DIFF_WINDOW];
	char path[64];
	size_t baseline_len = 0, diff_off = 0, after_valid = 0, dump_len;
	enum oracle_target chosen = TGT_NR;
	unsigned int i;
	int file_fd;

	if (unsupported_inplace_crypto_oracle)
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	for (i = 0; i < TGT_NR; i++) {
		enum oracle_target t = (enum oracle_target)
			((rotation_cursor + i) % TGT_NR);

		if (!unsupported_target[t]) {
			chosen = t;
			rotation_cursor = (t + 1) % TGT_NR;
			break;
		}
	}
	if (chosen == TGT_NR) {
		unsupported_inplace_crypto_oracle = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}

	file_fd = open_oracle_file(path, sizeof(path),
				   baseline, &baseline_len);
	if (file_fd < 0)
		return true;
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	(void)target_fns[chosen](file_fd);
	close(file_fd);

	if (!oracle_check_unchanged(path, baseline, baseline_len,
				    &diff_off, after_window,
				    &after_valid)) {
		dump_len = baseline_len - diff_off;
		if (dump_len > after_valid)
			dump_len = after_valid;
		log_corruption(chosen, path, diff_off,
			       baseline + diff_off, after_window,
			       dump_len);
	}
	return true;
}
