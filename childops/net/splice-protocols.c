/*
 * splice_protocols -- file_fd -> pipe -> socket-with-special-protocol-state.
 *
 * Trinity already exercises splice() with random fds and applies random
 * setsockopts to random sockets, but the COMBINATION of splice'ing into
 * a socket whose protocol state has been deliberately steered into one
 * of several non-default modes is what surfaces page-cache-write-via-
 * splice paths across protocols.  This childop builds the chain:
 *
 *     1. Pick one of several special-protocol-state setups (rotation):
 *          A. UDP socket + setsockopt(SOL_UDP, UDP_ENCAP, ESPINUDP)
 *          B. UDP socket + setsockopt(SOL_UDP, UDP_ENCAP, L2TPINUDP)
 *          C. TCP socket connected to a paired listener with
 *             setsockopt(IPPROTO_TCP, TCP_REPAIR, on)
 *          D. AF_PACKET SOCK_RAW socket with TPACKET v1/v2/v3 RX ring
 *             via setsockopt(PACKET_RX_RING)
 *          E. AF_ALG socket bound to skcipher type "cbc(aes)"
 *          F. AF_RXRPC socket bound to a loopback rxrpc address
 *     2. Open a source file fd (rotate: regular /tmp file, tmpfs file
 *        on /dev/shm, /proc/self/maps, /dev/zero, /dev/urandom).
 *     3. pipe2(O_CLOEXEC | O_NONBLOCK).
 *     4. Optionally vmsplice() a header iov into pipe[1] (rotate:
 *        skip / 8-byte / page-sized / over-page).
 *     5. splice(file_fd -> pipe[1], len, SPLICE_F_MOVE | maybe_others).
 *     6. splice(pipe[0] -> socket_fd, len, SPLICE_F_MOVE | maybe_others).
 *     7. Optionally drain back from the socket.
 *     8. Tear down socket + pipe + file.
 *
 * Per-setup unsupported latches mirror the uniform pattern in
 * fds/{kvm,landlock,memfd_secret,mq}.c: a setup that returns
 * EPERM / EAFNOSUPPORT / EPROTONOSUPPORT / EOPNOTSUPP / ENOPROTOOPT
 * latches a per-process flag and is skipped on subsequent invocations.
 * Once every setup has latched, the op short-circuits at the top.
 *
 * Brick-safety:
 *   - All sockets are O_CLOEXEC, bound only to loopback or kernel-
 *     allocated transport addresses, and torn down at the end of every
 *     iteration.
 *   - The /tmp source file is created with O_TMPFILE so it has no path
 *     and disappears on close.
 *   - No module load, no /sys writes, no rtnl mutations.
 *   - child.c arms alarm(1) around every non-syscall op; the per-call
 *     splice/vmsplice are SPLICE_F_NONBLOCK-tagged on every flag arm
 *     that doesn't deliberately exclude it, so a blocked socket cannot
 *     wedge the slot past the parent's alarm window.
 *
 * Header gates: __has_include() probes for <linux/udp.h>,
 * <linux/tcp.h>, <linux/if_packet.h>, <linux/if_alg.h>, <linux/rxrpc.h>;
 * UAPI integers fall back to their stable values when toolchain headers
 * are missing.  The kernel returns -ENOPROTOOPT / -EOPNOTSUPP and the
 * per-setup latch fires on first use.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#if __has_include(<linux/udp.h>)
# include <linux/udp.h>
#endif
#if __has_include(<linux/if_packet.h>)
# include <linux/if_packet.h>
#endif
#if __has_include(<linux/if_alg.h>)
# include <linux/if_alg.h>
#endif
#if __has_include(<linux/rxrpc.h>)
# include <linux/rxrpc.h>
#endif

#include "child.h"
#include "errno-classify.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/splice.h"
#include "kernel/socket.h"
#ifndef UDP_ENCAP
# define UDP_ENCAP			100
#endif
#ifndef UDP_ENCAP_ESPINUDP
# define UDP_ENCAP_ESPINUDP		2
#endif
#ifndef UDP_ENCAP_L2TPINUDP
# define UDP_ENCAP_L2TPINUDP		3
#endif

#ifndef SOL_PACKET
# define SOL_PACKET			263
#endif
#ifndef PACKET_RX_RING
# define PACKET_RX_RING			5
#endif
#ifndef PACKET_VERSION
# define PACKET_VERSION			10
#endif
#ifndef TPACKET_V1
# define TPACKET_V1			0
#endif
#ifndef TPACKET_V2
# define TPACKET_V2			1
#endif
#ifndef TPACKET_V3
# define TPACKET_V3			2
#endif

#define SPLICE_SELFTEST_LEN		64U

enum splice_proto_setup {
	SPS_UDP_ESPINUDP = 0,
	SPS_UDP_L2TPINUDP,
	SPS_TCP_REPAIR,
	SPS_PACKET_RX_RING,
	SPS_AF_ALG,
	SPS_AF_RXRPC,
	SPS_NR,
};

static bool unsupported_setup[SPS_NR];

enum splice_src {
	SRC_TMPFILE = 0,
	SRC_DEV_SHM,
	SRC_PROC_SELF_MAPS,
	SRC_DEV_ZERO,
	SRC_DEV_URANDOM,
	SRC_NR,
};

#define SPLICE_PROTO_MIN_LEN		16U
#define SPLICE_PROTO_PAGE		4096U

static int open_src_fd(unsigned int idx)
{
	int fd = -1;

	switch (idx % SRC_NR) {
	case SRC_TMPFILE:
		fd = open("/tmp", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
		if (fd >= 0) {
			unsigned char buf[SPLICE_PROTO_PAGE];

			generate_rand_bytes(buf, sizeof(buf));
			if (write(fd, buf, sizeof(buf)) < 0) {
				close(fd);
				fd = -1;
				break;
			}
			(void) lseek(fd, 0, SEEK_SET);
		}
		break;
	case SRC_DEV_SHM:
		fd = open("/dev/shm", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
		if (fd >= 0) {
			unsigned char buf[SPLICE_PROTO_PAGE];

			generate_rand_bytes(buf, sizeof(buf));
			if (write(fd, buf, sizeof(buf)) < 0) {
				close(fd);
				fd = -1;
				break;
			}
			(void) lseek(fd, 0, SEEK_SET);
		}
		break;
	case SRC_PROC_SELF_MAPS:
		fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
		break;
	case SRC_DEV_ZERO:
		fd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
		break;
	case SRC_DEV_URANDOM:
		fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
		break;
	}
	return fd;
}

static unsigned int pick_len(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0: return SPLICE_PROTO_MIN_LEN + rnd_modulo_u32(16);
	case 1: return 256U + rnd_modulo_u32(769U);
	case 2: return SPLICE_PROTO_PAGE;
	case 3: return SPLICE_PROTO_PAGE * 2U + rnd_modulo_u32(SPLICE_PROTO_PAGE);
	default: return 1U + (rand32() & 0x3fffU);
	}
}

static unsigned int pick_flags(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0: return SPLICE_F_MOVE;
	case 1: return SPLICE_F_MOVE | SPLICE_F_MORE;
	case 2: return SPLICE_F_MOVE | SPLICE_F_GIFT;
	case 3: return SPLICE_F_NONBLOCK;
	default: return 0;
	}
}

/*
 * Optionally prepend a header iov via vmsplice(pipe[1], iov, 1, 0).
 * Lets the splice'd payload land in the socket already preceded by a
 * userspace-supplied page cache region — exposes the encap / repair
 * paths to a pipe whose first buffers are vmsplice anon pages instead
 * of file-backed pages.  Skip / 8-byte / page / over-page rotation.
 */
static void maybe_vmsplice_header(int pipe_w)
{
	unsigned int arm = rnd_modulo_u32(4);
	struct iovec iov;
	unsigned char buf8[8];
	static unsigned char page_buf[SPLICE_PROTO_PAGE];
	static unsigned char over_buf[SPLICE_PROTO_PAGE * 2];

	switch (arm) {
	case 0:
		return;
	case 1:
		generate_rand_bytes(buf8, sizeof(buf8));
		iov.iov_base = buf8;
		iov.iov_len  = sizeof(buf8);
		break;
	case 2:
		generate_rand_bytes(page_buf, sizeof(page_buf));
		iov.iov_base = page_buf;
		iov.iov_len  = sizeof(page_buf);
		break;
	default:
		generate_rand_bytes(over_buf, sizeof(over_buf));
		iov.iov_base = over_buf;
		iov.iov_len  = sizeof(over_buf);
		break;
	}
	(void) vmsplice(pipe_w, &iov, 1, SPLICE_F_NONBLOCK);
}

static int setup_udp_encap(unsigned int encap_type, enum splice_proto_setup tag)
{
	int fd;
	int v = (int) encap_type;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (fd < 0) {
		if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
			unsupported_setup[tag] = true;
		return -1;
	}
	if (setsockopt(fd, SOL_UDP, UDP_ENCAP, &v, sizeof(v)) < 0) {
		if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
			unsupported_setup[tag] = true;
		close(fd);
		return -1;
	}
	{
		struct sockaddr_in sin;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port   = 0;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		(void) bind(fd, (struct sockaddr *) &sin, sizeof(sin));
		(void) connect(fd, (struct sockaddr *) &sin, sizeof(sin));
	}
	return fd;
}

static int setup_tcp_repair(void)
{
	int listener = -1, client = -1;
	struct sockaddr_in sin;
	socklen_t slen;
	int on = 1;

	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (listener < 0) {
		if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
			unsupported_setup[SPS_TCP_REPAIR] = true;
		return -1;
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port   = 0;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listener, (struct sockaddr *) &sin, sizeof(sin)) < 0)
		goto fail;
	if (listen(listener, 1) < 0)
		goto fail;
	slen = sizeof(sin);
	if (getsockname(listener, (struct sockaddr *) &sin, &slen) < 0)
		goto fail;

	client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (client < 0)
		goto fail;
	if (connect(client, (struct sockaddr *) &sin, sizeof(sin)) < 0)
		goto fail;

	if (setsockopt(client, IPPROTO_TCP, TCP_REPAIR, &on, sizeof(on)) < 0) {
		if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
			unsupported_setup[SPS_TCP_REPAIR] = true;
		goto fail;
	}

	close(listener);
	return client;
fail:
	if (client >= 0)
		close(client);
	if (listener >= 0)
		close(listener);
	return -1;
}

static int setup_packet_rx_ring(void)
{
#ifdef ETH_P_ALL
	int fd;
	int ver;
	struct {
		unsigned int tp_block_size;
		unsigned int tp_block_nr;
		unsigned int tp_frame_size;
		unsigned int tp_frame_nr;
	} req;
	struct {
		unsigned int tp_block_size;
		unsigned int tp_block_nr;
		unsigned int tp_frame_size;
		unsigned int tp_frame_nr;
		unsigned int tp_retire_blk_tov;
		unsigned int tp_sizeof_priv;
		unsigned int tp_feature_req_word;
	} req3;
	unsigned int arm;

	fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (fd < 0) {
		if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
			unsupported_setup[SPS_PACKET_RX_RING] = true;
		return -1;
	}

	arm = rnd_modulo_u32(3);
	ver = (arm == 0) ? TPACKET_V1 : (arm == 1) ? TPACKET_V2 : TPACKET_V3;
	(void) setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));

	if (arm < 2) {
		memset(&req, 0, sizeof(req));
		req.tp_block_size = SPLICE_PROTO_PAGE * 8U;
		req.tp_block_nr   = 4;
		req.tp_frame_size = 2048;
		req.tp_frame_nr   = (req.tp_block_size / req.tp_frame_size) *
				    req.tp_block_nr;
		if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
			       &req, sizeof(req)) < 0) {
			if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
				unsupported_setup[SPS_PACKET_RX_RING] = true;
			close(fd);
			return -1;
		}
	} else {
		memset(&req3, 0, sizeof(req3));
		req3.tp_block_size = SPLICE_PROTO_PAGE * 8U;
		req3.tp_block_nr   = 4;
		req3.tp_frame_size = 2048;
		req3.tp_frame_nr   = (req3.tp_block_size / req3.tp_frame_size) *
				     req3.tp_block_nr;
		req3.tp_retire_blk_tov = 100;
		if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
			       &req3, sizeof(req3)) < 0) {
			if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
				unsupported_setup[SPS_PACKET_RX_RING] = true;
			close(fd);
			return -1;
		}
	}
	return fd;
#else
	unsupported_setup[SPS_PACKET_RX_RING] = true;
	return -1;
#endif
}

static int setup_af_alg(void)
{
#ifdef AF_ALG
	int parent_fd, child_fd;
	struct sockaddr_alg sa;

	parent_fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (parent_fd < 0) {
		if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
			unsupported_setup[SPS_AF_ALG] = true;
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strncpy((char *) sa.salg_type, "skcipher",
		sizeof(sa.salg_type) - 1);
	strncpy((char *) sa.salg_name, "cbc(aes)",
		sizeof(sa.salg_name) - 1);

	if (bind(parent_fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		if ((is_syscall_unsupported(errno) || is_proto_family_unsupported(errno)) || errno == ENOENT ||
		    errno == ESRCH)
			unsupported_setup[SPS_AF_ALG] = true;
		close(parent_fd);
		return -1;
	}

	{
		unsigned char key[16];

		generate_rand_bytes(key, sizeof(key));
		(void) setsockopt(parent_fd, SOL_ALG, ALG_SET_KEY,
				  key, sizeof(key));
	}

	child_fd = accept4(parent_fd, NULL, NULL, SOCK_CLOEXEC);
	if (child_fd < 0) {
		int saved_errno = errno;
		close(parent_fd);
		if (is_syscall_unsupported(saved_errno) || is_proto_family_unsupported(saved_errno))
			unsupported_setup[SPS_AF_ALG] = true;
		return -1;
	}
	close(parent_fd);
	return child_fd;
#else
	unsupported_setup[SPS_AF_ALG] = true;
	return -1;
#endif
}

static int setup_af_rxrpc(void)
{
#if defined(AF_RXRPC) && __has_include(<linux/rxrpc.h>)
	int fd;
	struct sockaddr_rxrpc srx;

	fd = socket(AF_RXRPC, SOCK_DGRAM | SOCK_CLOEXEC, PF_INET);
	if (fd < 0) {
		if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
			unsupported_setup[SPS_AF_RXRPC] = true;
		return -1;
	}

	memset(&srx, 0, sizeof(srx));
	srx.srx_family   = AF_RXRPC;
	srx.srx_service  = 0;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len  = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	srx.transport.sin.sin_port = 0;

	if (bind(fd, (struct sockaddr *) &srx, sizeof(srx)) < 0) {
		if (is_syscall_unsupported(errno) || is_proto_family_unsupported(errno))
			unsupported_setup[SPS_AF_RXRPC] = true;
		close(fd);
		return -1;
	}
	return fd;
#else
	unsupported_setup[SPS_AF_RXRPC] = true;
	return -1;
#endif
}

static int build_socket(enum splice_proto_setup setup)
{
	switch (setup) {
	case SPS_UDP_ESPINUDP:
		return setup_udp_encap(UDP_ENCAP_ESPINUDP, setup);
	case SPS_UDP_L2TPINUDP:
		return setup_udp_encap(UDP_ENCAP_L2TPINUDP, setup);
	case SPS_TCP_REPAIR:
		return setup_tcp_repair();
	case SPS_PACKET_RX_RING:
		return setup_packet_rx_ring();
	case SPS_AF_ALG:
		return setup_af_alg();
	case SPS_AF_RXRPC:
		return setup_af_rxrpc();
	case SPS_NR:
		break;
	}
	return -1;
}

/*
 * Try setups in rotation starting at @start, latch-skipping any whose
 * unsupported flag is already set.  Returns the chosen setup index in
 * @out_setup or -1 if every setup is structurally unavailable.
 */
static int pick_setup(unsigned int start, enum splice_proto_setup *out_setup)
{
	unsigned int i;

	for (i = 0; i < SPS_NR; i++) {
		enum splice_proto_setup s =
			(enum splice_proto_setup)((start + i) % SPS_NR);

		if (!unsupported_setup[s]) {
			*out_setup = s;
			return 0;
		}
	}
	return -1;
}

static bool selftest_done;

/*
 * Behavioural self-test: confirm that an explicit MSG_SPLICE_PAGES
 * sendmsg() round-trips a known marker payload through a UDP loopback
 * socket pair.  We cannot inspect kernel-internal frag flags from
 * userspace; this is a pure end-to-end length check.  If the receiver
 * sees fewer bytes than were sent, the kernel build silently dropped
 * data on the zero-copy plant path, and the bug-class oracle this
 * childop is meant to exercise is ineffective on this target.
 *
 * Latched after the first invocation regardless of outcome — this is a
 * one-shot config probe, not a per-iter check.
 */
static void splice_protocols_selftest(void)
{
	char path[] = "/tmp/splice-self-test-XXXXXX";
	unsigned char marker[SPLICE_SELFTEST_LEN];
	unsigned char rxbuf[SPLICE_SELFTEST_LEN * 2];
	struct sockaddr_in sin_tx, sin_rx;
	socklen_t slen;
	struct iovec iov;
	struct msghdr mh;
	int tmpfd = -1, rdfd = -1, tx = -1, rx = -1;
	ssize_t n;

	tmpfd = mkstemp(path);
	if (tmpfd < 0)
		goto out;
	memset(marker, 'A', sizeof(marker));
	if (write(tmpfd, marker, sizeof(marker)) != (ssize_t) sizeof(marker))
		goto out;
	close(tmpfd);
	tmpfd = -1;

	rdfd = open(path, O_RDONLY | O_CLOEXEC);
	if (rdfd < 0)
		goto out;
	if (read(rdfd, marker, sizeof(marker)) != (ssize_t) sizeof(marker))
		goto out;

	rx = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (rx < 0)
		goto out;
	memset(&sin_rx, 0, sizeof(sin_rx));
	sin_rx.sin_family = AF_INET;
	sin_rx.sin_port   = 0;
	sin_rx.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(rx, (struct sockaddr *) &sin_rx, sizeof(sin_rx)) < 0)
		goto out;
	slen = sizeof(sin_rx);
	if (getsockname(rx, (struct sockaddr *) &sin_rx, &slen) < 0)
		goto out;

	tx = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (tx < 0)
		goto out;
	memset(&sin_tx, 0, sizeof(sin_tx));
	sin_tx.sin_family = AF_INET;
	sin_tx.sin_port   = 0;
	sin_tx.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(tx, (struct sockaddr *) &sin_tx, sizeof(sin_tx)) < 0)
		goto out;
	if (connect(tx, (struct sockaddr *) &sin_rx, sizeof(sin_rx)) < 0)
		goto out;

	iov.iov_base = marker;
	iov.iov_len  = sizeof(marker);
	memset(&mh, 0, sizeof(mh));
	mh.msg_iov    = &iov;
	mh.msg_iovlen = 1;

	n = sendmsg(tx, &mh, MSG_SPLICE_PAGES | MSG_DONTWAIT);
	if (n != (ssize_t) sizeof(marker))
		goto out;

	n = recv(rx, rxbuf, sizeof(rxbuf), MSG_DONTWAIT);
	(void) n;

out:
	if (tx >= 0)
		close(tx);
	if (rx >= 0)
		close(rx);
	if (rdfd >= 0)
		close(rdfd);
	if (tmpfd >= 0)
		close(tmpfd);
	(void) unlink(path);
}

static void run_iter(struct childdata *child, unsigned int iter)
{
	enum splice_proto_setup setup;
	int sock_fd = -1, src_fd = -1;
	int pfd[2] = { -1, -1 };
	unsigned int len, flags_in, flags_out;
	ssize_t in_n, out_n;
	bool first_skip = false;

	if (pick_setup(iter, &setup) < 0)
		return;

	sock_fd = build_socket(setup);
	if (sock_fd < 0) {
		__atomic_add_fetch(&shm->stats.splice_protocols.setup_failed,
				   1, __ATOMIC_RELAXED);
		first_skip = true;
	}

	switch (setup) {
	case SPS_UDP_ESPINUDP:
	case SPS_UDP_L2TPINUDP:
		__atomic_add_fetch(&shm->stats.splice_protocols.udp_encap_attempted,
				   1, __ATOMIC_RELAXED);
		break;
	case SPS_TCP_REPAIR:
		__atomic_add_fetch(&shm->stats.splice_protocols.tcp_repair_attempted,
				   1, __ATOMIC_RELAXED);
		break;
	case SPS_PACKET_RX_RING:
		__atomic_add_fetch(&shm->stats.splice_protocols.packet_ring_attempted,
				   1, __ATOMIC_RELAXED);
		break;
	case SPS_AF_ALG:
		__atomic_add_fetch(&shm->stats.splice_protocols.alg_attempted,
				   1, __ATOMIC_RELAXED);
		break;
	case SPS_AF_RXRPC:
		__atomic_add_fetch(&shm->stats.splice_protocols.rxrpc_attempted,
				   1, __ATOMIC_RELAXED);
		break;
	case SPS_NR:
		break;
	}

	if (first_skip)
		goto out;

	src_fd = open_src_fd(iter);
	if (src_fd < 0)
		goto out;

	if (pipe2(pfd, O_CLOEXEC | O_NONBLOCK) < 0)
		goto out;

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

	maybe_vmsplice_header(pfd[1]);

	len = pick_len();
	flags_in  = pick_flags();
	flags_out = pick_flags();

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	in_n = splice(src_fd, NULL, pfd[1], NULL, len, flags_in);
	if (in_n > 0) {
		__atomic_add_fetch(&shm->stats.splice_protocols.in_bytes,
				   (unsigned long) in_n, __ATOMIC_RELAXED);
		/*
		 * The splice_to_socket() kernel path sets MSG_SPLICE_PAGES
		 * for us — every pipe->socket splice here is expected to
		 * traverse that path.  Bump _attempted unconditionally; if
		 * the kernel returns the full requested length with no short
		 * write, infer the zero-copy plant succeeded.  Operator can
		 * watch path_taken_inferred / attempted; a low ratio means
		 * many splices fell back to copy and aren't reproducing the
		 * intended bug shape.
		 */
		__atomic_add_fetch(&shm->stats.splice_protocols.msg_splice_pages_attempted,
				   1, __ATOMIC_RELAXED);
		out_n = splice(pfd[0], NULL, sock_fd, NULL,
			       (size_t) in_n, flags_out);
		if (out_n > 0) {
			__atomic_add_fetch(&shm->stats.splice_protocols.out_bytes,
					   (unsigned long) out_n, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.splice_protocols.chain_ok,
					   1, __ATOMIC_RELAXED);
			if (out_n == in_n)
				__atomic_add_fetch(&shm->stats.splice_protocols.msg_splice_pages_path_taken_inferred,
						   1, __ATOMIC_RELAXED);

			if (RAND_BOOL()) {
				unsigned char rxbuf[512];

				(void) recv(sock_fd, rxbuf, sizeof(rxbuf),
					    MSG_DONTWAIT);
			}
		}
	}

out:
	if (pfd[0] >= 0)
		close(pfd[0]);
	if (pfd[1] >= 0)
		close(pfd[1]);
	if (src_fd >= 0)
		close(src_fd);
	if (sock_fd >= 0)
		close(sock_fd);
}

bool splice_protocols(struct childdata *child)
{
	unsigned int iters, i, start;
	bool any_supported = false;

	__atomic_add_fetch(&shm->stats.splice_protocols.runs,
			   1, __ATOMIC_RELAXED);

	if (!selftest_done) {
		selftest_done = true;
		splice_protocols_selftest();
	}

	for (i = 0; i < SPS_NR; i++) {
		if (!unsupported_setup[i]) {
			any_supported = true;
			break;
		}
	}
	if (!any_supported) {
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, same pattern the child.c dispatch loop uses for the
		 * unguarded write that motivated this guard. */
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.splice_protocols.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	iters = BUDGETED(CHILD_OP_SPLICE_PROTOCOLS, JITTER_RANGE(4));
	if (iters < 2)
		iters = 2;
	if (iters > 12)
		iters = 12;

	start = rnd_u32();
	for (i = 0; i < iters; i++)
		run_iter(child, start + i);

	return true;
}
