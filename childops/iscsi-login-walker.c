/*
 * iscsi_login_walker - drive the in-kernel LIO iSCSI Login state machine
 * past the front-door BHS / text-key parser rejection gates so trinity
 * reaches the deeper command-dispatch paths in drivers/target/iscsi/
 * where the higher-value command-side bugs live.
 *
 * Why a second iscsi childop:
 *
 *   The existing iscsi_target_probe childop opens a TCP connection to
 *   127.0.0.1:3260 and either fires a wholly-random 48-byte BHS, a
 *   fuzzed text-key Login, or a single well-formed Login followed by
 *   one fuzzed SCSI Command.  A recent kernel-side log survey of a run
 *   that reached the target for the first time recorded ~1820 LIO
 *   rejection messages, every one of them at the front-door framing /
 *   parser gates:
 *
 *     "Unable to locate '=' separator for key" -- text-key parser
 *     "Illegal login_req->flags Combination"   -- CSG/NSG/TRANSIT mix
 *     "Login request has both CONTINUE and TRANSIT" -- mutex flag combo
 *     "Received unknown opcode 0x01-0x1b"      -- BHS opcode validator
 *
 *   Zero kernel-side BUG/Oops in that window.  The dispatcher coverage
 *   is bottlenecked on the framing, not the deeper logic.
 *
 * What this childop does in this commit:
 *
 *   INIT (only state implemented today): open a nonblocking TCP
 *   connection to 127.0.0.1:3260, send one well-formed Login Request
 *   PDU with CSG=0 (SecurityNegotiation), no TRANSIT, no CONTINUE, and
 *   a tidy InitiatorName + AuthMethod=None data segment.  The target
 *   should accept the framing and reply with a Login Response keeping
 *   us in CSG=0.  We drain whatever it sends and close the socket.
 *
 *   Subsequent commits extend the walker to drive SECURITY_NEG, OP_NEG,
 *   and FFP state transitions, then add a chaos toggle that retains
 *   the random-byte coverage the older probe was producing.
 *
 * Safety:
 *
 *   - Loopback only: hardcoded 127.0.0.1:3260, never any other address.
 *   - Nonblocking socket + poll-based timeouts so a wedged peer cannot
 *     pin the child past the SIGALRM(1s) child.c safety net.
 *   - ECONNREFUSED on the first connect latches a per-child
 *     "no target present" flag and the walker silently no-ops for the
 *     rest of the process lifetime, matching iscsi_target_probe.
 *   - Socket always closed on every exit path regardless of state.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

/* iSCSI constants from RFC 7143 §11.  Defined locally so we don't drag
 * in <scsi/iscsi_proto.h> which is not present on every sysroot. */
#define ISCSI_TARGET_PORT		3260
#define ISCSI_OP_LOGIN			0x03	/* Login Request */
#define ISCSI_OP_IMMEDIATE		0x40	/* I bit in opcode byte */
#define ISCSI_BHS_LEN			48

/* Login flags byte layout (BHS byte 1):
 *   bit 7 (0x80) - TRANSIT (T)
 *   bit 6 (0x40) - CONTINUE (C)  -- mutually exclusive with TRANSIT
 *   bits 3..2    - CSG (Current Stage)
 *   bits 1..0    - NSG (Next Stage)
 * CSG / NSG values:
 *   0b00 - SecurityNegotiation
 *   0b01 - LoginOperationalNegotiation
 *   0b11 - FullFeaturePhase
 *
 * INIT state: CSG=0, NSG=0, T=0, C=0 -> flag byte 0x00.  Keeps the
 * target in SecurityNegotiation; the response will echo CSG=0 and we
 * will iterate forward in later commits. */
#define ISCSI_LOGIN_FLAGS_INIT		0x00

/* Cap on Login text data we'll generate per PDU.  Demo-mode LIO accepts
 * up to MaxRecvDataSegmentLength bytes, but small keeps us well under
 * any reasonable receive-buffer pressure and bounds the per-cycle
 * memcpy / send work. */
#define LOGIN_TEXT_MAX			512

/* Receive buffer for login responses.  Login responses are normally
 * <=256 bytes; we only need to drain the socket, not parse it. */
#define ISCSI_RX_BUF			1024

/* poll timeouts.  Connect window kept at 1s to absorb scheduler jitter
 * on a busy host; per-recv window kept short so a single cycle never
 * pins the child past the SIGALRM(1s) child.c safety net. */
#define ISCSI_CONNECT_TIMEOUT_MS	1000
#define ISCSI_RECV_TIMEOUT_MS		200

/* Inner-loop iteration base.  BUDGETED + JITTER_RANGE keeps actual
 * iters in the 1-3 range under default budget; adapt_budget can grow
 * it on productive runs without growing wall-clock significantly since
 * each iter is bounded by ISCSI_RECV_TIMEOUT_MS + tiny TCP RTT. */
#define ISCSI_WALKER_ITERS_BASE		2U

/* Latched once per child on the first ECONNREFUSED: no LIO target is
 * listening, so further attempts in this process are pure waste. */
static bool ns_unsupported;

/* Encode 24-bit big-endian length into bhs[5..7].  iSCSI DataSegment
 * lengths are 24-bit MSB-first; this is the only multi-byte field we
 * need to byte-swap by hand (ITT / CmdSN / ExpStatSN are u32 fields
 * but the kernel treats them as opaque echo cookies for the response
 * direction, so random-ish values in any byte order are fine). */
static void put_be24(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)((v >> 16) & 0xff);
	p[1] = (unsigned char)((v >> 8)  & 0xff);
	p[2] = (unsigned char)(v & 0xff);
}

/* Random bytes via rnd_u64() rather than libc rand() — per the tree
 * rules, rand() is migrating out and rnd_u64() is the mutex-free
 * splitmix64 replacement. */
static void rnd_fill(unsigned char *buf, size_t len)
{
	size_t i;
	uint64_t r = 0;

	for (i = 0; i < len; i++) {
		if ((i & 7) == 0)
			r = rnd_u64();
		buf[i] = (unsigned char)(r & 0xff);
		r >>= 8;
	}
}

/* Nonblocking connect to the loopback iSCSI portal with a poll-based
 * timeout.  Returns the connected fd, or -1 with errno preserved on
 * failure / timeout.  Caller checks errno == ECONNREFUSED specifically
 * to latch the no-target gate. */
static int iscsi_connect(int timeout_ms)
{
	struct sockaddr_in srv;
	struct pollfd pfd;
	int sockerr = 0;
	socklen_t slen = sizeof(sockerr);
	int fd;
	int rc;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;

	memset(&srv, 0, sizeof(srv));
	srv.sin_family = AF_INET;
	srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	srv.sin_port = htons(ISCSI_TARGET_PORT);

	rc = connect(fd, (const struct sockaddr *)&srv, sizeof(srv));
	if (rc == 0)
		return fd;
	if (errno != EINPROGRESS) {
		int saved = errno;

		close(fd);
		errno = saved;
		return -1;
	}

	pfd.fd = fd;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0) {
		close(fd);
		errno = (rc == 0) ? ETIMEDOUT : errno;
		return -1;
	}
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &slen) < 0 ||
	    sockerr != 0) {
		close(fd);
		errno = sockerr ? sockerr : EIO;
		return -1;
	}
	return fd;
}

/* Drain whatever the target sent back, up to ISCSI_RX_BUF bytes.
 * Bumps bytes_in for operator visibility.  Doesn't try to parse the
 * response — the kernel-side coverage is in handling our request, not
 * in what comes back. */
static void iscsi_drain(int fd)
{
	unsigned char buf[ISCSI_RX_BUF];
	struct pollfd pfd;
	ssize_t n;
	int rc;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	rc = poll(&pfd, 1, ISCSI_RECV_TIMEOUT_MS);
	if (rc <= 0)
		return;

	n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.iscsi_walker_bytes_in,
				   (unsigned long)n, __ATOMIC_RELAXED);
}

/* Text-key data segment for the INIT-state Login PDU.  CSG=0 means the
 * target is in SecurityNegotiation and expects InitiatorName plus
 * AuthMethod.  AuthMethod=None matches a demo-mode LIO target with
 * authentication=0; the well-formed framing keeps us past the
 * "Unable to locate '=' separator" parser arm so the kernel walks the
 * real text-key handlers. */
static const char login_text_init[] =
	"InitiatorName=iqn.1993-08.org.debian:01:w\0"
	"AuthMethod=None\0";

/* Build a Login Request PDU for the INIT state: CSG=0, no TRANSIT, no
 * CONTINUE, ISID randomised, TSIH=0 (new session), CID=1, CmdSN=0,
 * ExpStatSN=0.  Returns the total PDU length (BHS + padded data
 * segment). */
static size_t build_login_init(unsigned char *out)
{
	unsigned char *bhs = out;
	unsigned char *data = out + ISCSI_BHS_LEN;
	/* sizeof includes the trailing implicit '\0'; we want every
	 * NUL-terminated key in the buffer to land on the wire including
	 * the very last one's separator. */
	size_t data_len = sizeof(login_text_init) - 1;
	size_t padded = (data_len + 3) & ~(size_t)3;

	memset(bhs, 0, ISCSI_BHS_LEN);
	bhs[0] = ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE;
	bhs[1] = ISCSI_LOGIN_FLAGS_INIT;
	bhs[2] = 0;					/* Version-max */
	bhs[3] = 0;					/* Version-min */
	bhs[4] = 0;					/* TotalAHSLength */
	rnd_fill(bhs + 8, 6);				/* ISID */
	bhs[14] = 0;					/* TSIH high */
	bhs[15] = 0;					/* TSIH low (new session) */
	rnd_fill(bhs + 16, 4);				/* ITT */
	bhs[20] = 0;
	bhs[21] = 1;					/* CID = 1 */
	/* CmdSN = 0, ExpStatSN = 0 for a fresh login */
	memset(bhs + 24, 0, 8);

	memcpy(data, login_text_init, data_len);
	if (padded > data_len)
		memset(data + data_len, 0, padded - data_len);

	put_be24(bhs + 5, (uint32_t)padded);
	return ISCSI_BHS_LEN + padded;
}

bool iscsi_login_walker(struct childdata *child)
{
	unsigned char pdu[ISCSI_BHS_LEN + LOGIN_TEXT_MAX];
	unsigned int iters;
	unsigned int i;
	int fd;
	ssize_t n;
	size_t pdu_len;

	(void)child;

	__atomic_add_fetch(&shm->stats.iscsi_walker_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	iters = BUDGETED(CHILD_OP_ISCSI_LOGIN_WALKER,
			 JITTER_RANGE(ISCSI_WALKER_ITERS_BASE));
	if (iters == 0)
		iters = 1;

	for (i = 0; i < iters; i++) {
		fd = iscsi_connect(ISCSI_CONNECT_TIMEOUT_MS);
		if (fd < 0) {
			if (errno == ECONNREFUSED) {
				ns_unsupported = true;
				__atomic_add_fetch(&shm->stats.iscsi_walker_no_target,
						   1, __ATOMIC_RELAXED);
				return true;
			}
			__atomic_add_fetch(&shm->stats.iscsi_walker_setup_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}
		__atomic_add_fetch(&shm->stats.iscsi_walker_connected, 1,
				   __ATOMIC_RELAXED);

		pdu_len = build_login_init(pdu);
		n = send(fd, pdu, pdu_len, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0) {
			__atomic_add_fetch(&shm->stats.iscsi_walker_state_init_sent,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.iscsi_walker_bytes_out,
					   (unsigned long)n, __ATOMIC_RELAXED);
		}

		iscsi_drain(fd);

		(void)shutdown(fd, SHUT_RDWR);
		close(fd);
	}

	return true;
}
