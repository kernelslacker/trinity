/*
 * iscsi_login_walker - drive the in-kernel LIO iSCSI Login state machine
 * past the front-door BHS / text-key parser rejection gates so trinity
 * reaches FullFeaturePhase, where the higher-value command-side bugs in
 * drivers/target/iscsi/ live.
 *
 * Why response-driven:
 *
 *   The earlier fire-and-forget walker sent three Login PDUs back-to-back
 *   and only drained the responses without parsing them.  LIO rejected
 *   every negotiation because we never echoed the target-assigned TSIH
 *   on the second PDU and never advanced ExpStatSN past the StatSN the
 *   target minted in its first response.  Symptom: ~75k "Login
 *   negotiation failed" per run and FFP never reached.
 *
 *   The new walk is response-driven and completes the login in two PDUs:
 *
 *   PDU1 SecurityNegotiation + transit-to-Op:
 *          opcode 0x43 (Login | Immediate), flags 0x81 (T=1, CSG=0,
 *          NSG=1).  Data segment carries InitiatorName, SessionType=
 *          Normal, TargetName, AuthMethod=None so LIO can pick the ACL
 *          up-front, agree to no authentication and advance to Op.
 *
 *   READ   48-byte Login Response BHS.  Verify opcode 0x23 and
 *          Status-Class == 0.  Capture the TSIH the target assigned
 *          and the StatSN it minted; both are required in PDU2.
 *
 *   PDU2 LoginOperationalNegotiation + transit-to-FFP:
 *          opcode 0x43, flags 0x87 (T=1, CSG=1, NSG=3).  BHS echoes
 *          the captured TSIH; ExpStatSN is set to StatSN+1 so the
 *          target's status-window is satisfied.  Data segment carries
 *          the operational keys (digests, burst / R2T limits, etc.).
 *
 *   READ   final 48-byte Login Response BHS.  Verify Status-Class == 0,
 *          T bit set, and NSG == FFP.  When all three hold the session
 *          is in FullFeaturePhase and the FFP fuzz burst may safely run.
 *
 * Chaos toggle: every ISCSI_WALKER_CHAOS_MODULO=5 invocations the
 * walker skips the state-machine walk entirely and sends a burst of
 * wholly-random 48-byte BHS PDUs.  Keeps the front-door BHS / parser
 * coverage the older iscsi_target_probe random-spam path was producing
 * intact, so the walker doesn't silently erode the coverage we had
 * before.
 *
 * Safety:
 *
 *   - Loopback only: hardcoded 127.0.0.1:3260, never any other address.
 *   - Nonblocking socket + poll-based timeouts so a wedged peer cannot
 *     pin the child past the SIGALRM(1s) child.c safety net.
 *   - Response BHS read loops on partial recvs to the full 48 bytes or
 *     the per-recv timeout; short read / RST / EPIPE / bad opcode /
 *     non-zero Status-Class all close the socket and continue.
 *   - ECONNREFUSED on the first connect latches a per-child
 *     "no target present" flag and the walker silently no-ops for the
 *     rest of the process lifetime, matching iscsi_target_probe.
 *   - Socket always closed on every exit path regardless of state.
 */

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/socket.h"
/* iSCSI constants from RFC 7143 §11.  Defined locally so we don't drag
 * in <scsi/iscsi_proto.h> which is not present on every sysroot. */
#define ISCSI_TARGET_PORT		3260
#define ISCSI_OP_LOGIN			0x03	/* Login Request */
#define ISCSI_OP_LOGIN_RSP		0x23	/* Login Response */
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
 * PDU1 (SecurityNegotiation with transit to Op): T=1, C=0, CSG=0,
 * NSG=1 -> 0x81.  The data segment declares AuthMethod=None, so
 * SecurityNegotiation has no outstanding work and the TRANSIT bit tells
 * the target to move us to LoginOperationalNegotiation in its response.
 *
 * PDU2 (LoginOperationalNegotiation with transit to FFP): T=1, C=0,
 * CSG=1, NSG=3 -> 0x87.  Advances the session into FullFeaturePhase
 * where the post-login command dispatcher takes over. */
#define ISCSI_LOGIN_FLAGS_SEC_TO_OP		0x81
#define ISCSI_LOGIN_FLAGS_OP_TO_FF		0x87

/* Login Response BHS bit / offset layout, RFC 7143 §11.13.
 *   flags byte 1: TRANSIT bit is 0x80; NSG in bits 1..0.
 *   TSIH:            BE16 at [14..15]
 *   StatSN:          BE32 at [24..27]
 *   Status-Class:    byte at [36]
 *   Status-Detail:   byte at [37]
 * We only need the fields required to build PDU2 and to gate the FFP
 * burst; the rest of the response body is drained silently. */
#define ISCSI_RSP_FLAGS_TRANSIT		0x80
#define ISCSI_RSP_NSG_MASK		0x03
#define ISCSI_NSG_FFP			0x03

/* Cap on Login text data we'll generate per PDU.  Demo-mode LIO accepts
 * up to MaxRecvDataSegmentLength bytes, but small keeps us well under
 * any reasonable receive-buffer pressure and bounds the per-cycle
 * memcpy / send work. */
#define LOGIN_TEXT_MAX			512

/* Receive buffer for login responses.  The 48-byte BHS is what we
 * parse; the buffer is larger so the follow-up data segment can be
 * drained in one pass. */
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
 * lengths are 24-bit MSB-first. */
static void put_be24(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)((v >> 16) & 0xff);
	p[1] = (unsigned char)((v >> 8)  & 0xff);
	p[2] = (unsigned char)(v & 0xff);
}

/* Encode 32-bit big-endian value into a 4-byte field.  Used for the
 * ExpStatSN field of PDU2: LIO checks the running status window and
 * will drop the connection if the sequence number does not match the
 * StatSN it just handed us + 1. */
static void put_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)((v >> 24) & 0xff);
	p[1] = (unsigned char)((v >> 16) & 0xff);
	p[2] = (unsigned char)((v >> 8)  & 0xff);
	p[3] = (unsigned char)(v & 0xff);
}

/* Read a big-endian 32-bit value from a 4-byte BHS field. */
static uint32_t get_be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8)  |
	       ((uint32_t)p[3]);
}

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

/* Read exactly ISCSI_BHS_LEN bytes into bhs, looping on short reads and
 * poll()ing between them so a single slow response can still be fully
 * assembled inside ISCSI_RECV_TIMEOUT_MS wall-clock.  Returns 0 on
 * success, -1 on RST / EPIPE / timeout / peer close.  After a
 * successful BHS read the follow-up data segment (if any) is drained
 * from the socket best-effort so the next PDU we send doesn't share the
 * kernel's socket read cursor with unread response bytes. */
static int iscsi_read_bhs(int fd, unsigned char *bhs)
{
	struct pollfd pfd;
	size_t got = 0;
	ssize_t n;
	int rc;

	while (got < ISCSI_BHS_LEN) {
		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		rc = poll(&pfd, 1, ISCSI_RECV_TIMEOUT_MS);
		if (rc <= 0)
			return -1;
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			return -1;
		n = recv(fd, bhs + got, ISCSI_BHS_LEN - got, MSG_DONTWAIT);
		if (n <= 0) {
			if (n < 0 && errno == EAGAIN)
				continue;
			return -1;
		}
		got += (size_t)n;
		__atomic_add_fetch(&shm->stats.iscsi_walker.bytes_in,
				   (unsigned long)n, __ATOMIC_RELAXED);
	}
	return 0;
}

/* Drain the follow-up data segment of a Login Response, best-effort.
 * We do not need to parse it -- PDU2 does not consume any negotiated
 * key from the target -- but leaving unread bytes in the socket buffer
 * would blur the response cursor for the next PDU on this fd. */
static void iscsi_drain_after_bhs(int fd)
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
		__atomic_add_fetch(&shm->stats.iscsi_walker.bytes_in,
				   (unsigned long)n, __ATOMIC_RELAXED);
}

/* Text-key data segment for PDU1.  Declares the initiator identity, the
 * session type, the target we want to log into, and picks
 * AuthMethod=None so the target can transit us out of
 * SecurityNegotiation on its response.  TargetName is present here
 * (rather than in PDU2) because LIO validates the ACL lookup against
 * generate_node_acls=1 during SecurityNegotiation and needs the target
 * identity in-hand to do it. */
static const char login_text_pdu1[] =
	"InitiatorName=iqn.1993-08.org.debian:01:w\0"
	"SessionType=Normal\0"
	"TargetName=iqn.2026-05.fuzz:t\0"
	"AuthMethod=None\0";

/* Text-key data segment for PDU2.  Operational keys the kernel walks
 * during LoginOperationalNegotiation: digest algorithms, per-PDU / per-
 * burst size limits, R2T / immediate-data mode, and the standard
 * time-window keys.  All values are demo-mode-friendly. */
static const char login_text_pdu2[] =
	"HeaderDigest=None\0"
	"DataDigest=None\0"
	"MaxRecvDataSegmentLength=8192\0"
	"MaxBurstLength=262144\0"
	"FirstBurstLength=65536\0"
	"DefaultTime2Wait=2\0"
	"DefaultTime2Retain=20\0"
	"MaxOutstandingR2T=1\0"
	"MaxConnections=1\0"
	"InitialR2T=Yes\0"
	"ImmediateData=Yes\0"
	"DataPDUInOrder=Yes\0"
	"DataSequenceInOrder=Yes\0"
	"ErrorRecoveryLevel=0\0";

/* Build PDU1: SecurityNegotiation with transit-to-Op, carrying the
 * InitiatorName / SessionType / TargetName / AuthMethod=None keys.
 * ISID and ITT are caller-supplied so the response can be correlated
 * on the wire.  TSIH is 0 (new session); CmdSN and ExpStatSN are 0. */
static size_t build_login_pdu1(unsigned char *out, const uint8_t isid[6],
			       uint32_t itt)
{
	unsigned char *bhs = out;
	unsigned char *data = out + ISCSI_BHS_LEN;
	size_t data_len = sizeof(login_text_pdu1) - 1;
	size_t padded = (data_len + 3) & ~(size_t)3;

	memset(bhs, 0, ISCSI_BHS_LEN);
	bhs[0] = ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE;
	bhs[1] = ISCSI_LOGIN_FLAGS_SEC_TO_OP;
	bhs[2] = 0;					/* Version-max */
	bhs[3] = 0;					/* Version-min */
	bhs[4] = 0;					/* TotalAHSLength */
	memcpy(bhs + 8, isid, 6);			/* ISID */
	bhs[14] = 0;					/* TSIH high */
	bhs[15] = 0;					/* TSIH low (new session) */
	put_be32(bhs + 16, itt);			/* ITT */
	bhs[20] = 0;
	bhs[21] = 1;					/* CID = 1 */
	memset(bhs + 24, 0, 8);				/* CmdSN=0, ExpStatSN=0 */

	memcpy(data, login_text_pdu1, data_len);
	if (padded > data_len)
		memset(data + data_len, 0, padded - data_len);

	put_be24(bhs + 5, (uint32_t)padded);
	return ISCSI_BHS_LEN + padded;
}

/* Build PDU2: LoginOperationalNegotiation with transit-to-FFP.  Echoes
 * the target-assigned TSIH from PDU1's response and sets ExpStatSN to
 * the response StatSN + 1 so the target's status window is satisfied.
 * Same ISID as PDU1 so LIO threads the two PDUs onto the same session
 * state. */
static size_t build_login_pdu2(unsigned char *out, const uint8_t isid[6],
			       uint32_t itt, uint16_t tsih,
			       uint32_t exp_stat_sn)
{
	unsigned char *bhs = out;
	unsigned char *data = out + ISCSI_BHS_LEN;
	size_t data_len = sizeof(login_text_pdu2) - 1;
	size_t padded = (data_len + 3) & ~(size_t)3;

	memset(bhs, 0, ISCSI_BHS_LEN);
	bhs[0] = ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE;
	bhs[1] = ISCSI_LOGIN_FLAGS_OP_TO_FF;
	memcpy(bhs + 8, isid, 6);			/* same ISID */
	bhs[14] = (unsigned char)((tsih >> 8) & 0xff);	/* echo TSIH */
	bhs[15] = (unsigned char)(tsih & 0xff);
	put_be32(bhs + 16, itt);			/* ITT */
	bhs[20] = 0;
	bhs[21] = 1;					/* CID = 1 */
	put_be32(bhs + 24, 0);				/* CmdSN = 0 */
	put_be32(bhs + 28, exp_stat_sn);		/* ExpStatSN = StatSN+1 */

	memcpy(data, login_text_pdu2, data_len);
	if (padded > data_len)
		memset(data + data_len, 0, padded - data_len);

	put_be24(bhs + 5, (uint32_t)padded);
	return ISCSI_BHS_LEN + padded;
}

/* Post-login opcodes the FFP dispatcher accepts.  Bias the FFP fuzz
 * opcode field into this set so the per-opcode handlers see real
 * coverage instead of every PDU bouncing off the BHS opcode validator.
 *
 *   0x00  NOP-Out
 *   0x01  SCSI Command
 *   0x02  SCSI Task Management Function Request
 *   0x04  Text Request
 *   0x05  SCSI Data-Out
 *   0x06  Logout Request
 *   0x10  SNACK Request */
static const unsigned char ffp_opcodes[] = {
	0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x10,
};
#define NR_FFP_OPCODES	(sizeof(ffp_opcodes) / sizeof(ffp_opcodes[0]))

/* Cap on FFP fuzz data segment size.  Small keeps the dispatcher
 * engaged on the BHS / header validators rather than burning cycles
 * inside large copy_from_user paths that aren't the target. */
#define FFP_DATA_MAX	16U

/* Per-iteration FFP-PDU burst.  1-4 PDUs is enough to hit each
 * dispatcher arm a few times across a session lifetime without making
 * any one iteration unbounded. */
#define FFP_PDUS_MAX	4U

/* Chaos toggle: every Nth invocation of the walker bypasses the
 * state-machine path entirely and instead emits a burst of wholly-
 * random BHS PDUs (no Login walk, no FFP fuzz, just random bytes
 * straight at the BHS validators).  5 -> 20% chaos / 80% walk. */
#define ISCSI_WALKER_CHAOS_MODULO	5U

/* Per-iteration chaos burst: 1-3 random BHS PDUs.  Smaller than the
 * FFP burst because the chaos path is purely about retaining the
 * front-door coverage the older iscsi_target_probe produced; the
 * walker's main value is post-Login depth, not random spam volume. */
#define CHAOS_PDUS_MAX	3U

/* Build a FullFeaturePhase fuzz PDU.  Starts from a wholly-random BHS,
 * then biases the opcode 7/8 of the time into the FFP-valid set and
 * pins the AHS length / ISID / TSIH fields to values that won't cause
 * the dispatcher to reject before the per-opcode handler runs.  Data
 * segment is 0-15 random bytes plus 4-byte padding. */
static size_t build_ffp_fuzz(unsigned char *out, const uint8_t isid[6],
			     uint16_t tsih)
{
	unsigned char *bhs = out;
	unsigned char *data = out + ISCSI_BHS_LEN;
	size_t data_len;
	size_t padded;

	rnd_fill(bhs, ISCSI_BHS_LEN);
	if ((rnd_u32() & 7) != 0)
		bhs[0] = (unsigned char)((bhs[0] & 0x40) |
			ffp_opcodes[rnd_modulo_u32(NR_FFP_OPCODES)]);
	bhs[4] = (unsigned char)(bhs[4] & 0x03);	/* small AHS */
	memcpy(bhs + 8, isid, 6);			/* same session */
	bhs[14] = (unsigned char)((tsih >> 8) & 0xff);	/* target-assigned TSIH */
	bhs[15] = (unsigned char)(tsih & 0xff);
	/* ITT / CmdSN / ExpStatSN left random -- they are echo cookies
	 * and per-PDU window fields; the kernel either accepts a fresh
	 * tag or rejects it, both reasonable coverage. */

	data_len = rnd_modulo_u32(FFP_DATA_MAX);
	padded = (data_len + 3) & ~(size_t)3;
	if (padded > 0)
		rnd_fill(data, padded);
	put_be24(bhs + 5, (uint32_t)padded);

	return ISCSI_BHS_LEN + padded;
}

/* Chaos-path PDU: a wholly-random 48-byte BHS with the opcode masked
 * into the 0x00..0x1f range so the BHS opcode validator has a
 * non-trivial chance of selecting a defined initiator opcode.  AHS
 * length is masked small and DataSegmentLength is bounded so the
 * target doesn't sit waiting for megabytes of data we'll never send.
 * No data segment is emitted -- the chaos path is BHS-only, mirroring
 * the random-spam arm of the older iscsi_target_probe. */
static size_t build_chaos_bhs(unsigned char *out)
{
	rnd_fill(out, ISCSI_BHS_LEN);
	out[0] = (unsigned char)((out[0] & 0x40) | (out[0] & 0x1f));
	out[4] = (unsigned char)(out[4] & 0x03);
	out[5] = 0;
	out[6] = 0;
	out[7] = (unsigned char)(out[7] & 0x0f);
	return ISCSI_BHS_LEN;
}

/* Chaos-path burst: send 1..CHAOS_PDUS_MAX wholly-random BHS PDUs at the
 * connected socket, draining any response between each.  This mirrors the
 * random-spam arm of the older iscsi_target_probe and keeps front-door BHS
 * validator coverage intact when the walker skips the state-machine path. */
static void iscsi_send_chaos_burst(int fd, unsigned char *pdu)
{
	unsigned int chaos_pdus = 1 + rnd_modulo_u32(CHAOS_PDUS_MAX);
	unsigned int j;
	size_t pdu_len;
	ssize_t n;

	for (j = 0; j < chaos_pdus; j++) {
		pdu_len = build_chaos_bhs(pdu);
		n = send(fd, pdu, pdu_len,
			 MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0) {
			__atomic_add_fetch(&shm->stats.iscsi_walker.chaos_pdus,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.iscsi_walker.bytes_out,
					   (unsigned long)n,
					   __ATOMIC_RELAXED);
		}
		iscsi_drain_after_bhs(fd);
	}
}

/* Drive the response-driven Login walk on the connected socket.  On
 * success returns true with *tsih_out set to the target-assigned TSIH
 * so the caller can echo it into any follow-up FFP fuzz PDUs.  Any
 * short read / non-Login-Response opcode / non-zero Status-Class /
 * failure to see T=1 + NSG=FFP on the second response returns false
 * with the corresponding rejection counter bumped -- caller must not
 * follow up with an FFP burst on a false return. */
static bool iscsi_login_walk(int fd, unsigned char *pdu,
			     const uint8_t isid[6], uint16_t *tsih_out)
{
	unsigned char resp[ISCSI_BHS_LEN];
	uint32_t itt = rnd_u32();
	uint16_t tsih;
	uint32_t stat_sn;
	size_t pdu_len;
	ssize_t n;

	pdu_len = build_login_pdu1(pdu, isid, itt);
	n = send(fd, pdu, pdu_len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n <= 0)
		return false;
	__atomic_add_fetch(&shm->stats.iscsi_walker.state_security_sent,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.iscsi_walker.bytes_out,
			   (unsigned long)n, __ATOMIC_RELAXED);

	if (iscsi_read_bhs(fd, resp) < 0)
		return false;
	if (resp[0] != ISCSI_OP_LOGIN_RSP)
		return false;
	__atomic_add_fetch(&shm->stats.iscsi_walker.login_response_ok,
			   1, __ATOMIC_RELAXED);
	if (resp[36] != 0) {
		__atomic_add_fetch(&shm->stats.iscsi_walker.login_rejected,
				   1, __ATOMIC_RELAXED);
		return false;
	}
	tsih = (uint16_t)(((uint16_t)resp[14] << 8) | resp[15]);
	stat_sn = get_be32(resp + 24);
	iscsi_drain_after_bhs(fd);

	pdu_len = build_login_pdu2(pdu, isid, itt, tsih, stat_sn + 1);
	n = send(fd, pdu, pdu_len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n <= 0)
		return false;
	__atomic_add_fetch(&shm->stats.iscsi_walker.state_op_neg_sent,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.iscsi_walker.bytes_out,
			   (unsigned long)n, __ATOMIC_RELAXED);

	if (iscsi_read_bhs(fd, resp) < 0)
		return false;
	if (resp[0] != ISCSI_OP_LOGIN_RSP)
		return false;
	__atomic_add_fetch(&shm->stats.iscsi_walker.login_response_ok,
			   1, __ATOMIC_RELAXED);
	if (resp[36] != 0) {
		__atomic_add_fetch(&shm->stats.iscsi_walker.login_rejected,
				   1, __ATOMIC_RELAXED);
		return false;
	}
	if (!(resp[1] & ISCSI_RSP_FLAGS_TRANSIT))
		return false;
	if ((resp[1] & ISCSI_RSP_NSG_MASK) != ISCSI_NSG_FFP)
		return false;
	iscsi_drain_after_bhs(fd);

	__atomic_add_fetch(&shm->stats.iscsi_walker.ffp_reached, 1,
			   __ATOMIC_RELAXED);
	*tsih_out = tsih;
	return true;
}

/* FullFeaturePhase fuzz burst.  Only invoked after iscsi_login_walk
 * reported FFP was actually reached; the target-assigned TSIH is echoed
 * into each PDU so the session state stays coherent. */
static void iscsi_send_ffp_burst(int fd, unsigned char *pdu,
				 const uint8_t isid[6], uint16_t tsih)
{
	unsigned int j;
	unsigned int ffp_pdus = 1 + rnd_modulo_u32(FFP_PDUS_MAX);
	size_t pdu_len;
	ssize_t n;

	__atomic_add_fetch(&shm->stats.iscsi_walker.ffp_iters, 1,
			   __ATOMIC_RELAXED);
	for (j = 0; j < ffp_pdus; j++) {
		pdu_len = build_ffp_fuzz(pdu, isid, tsih);
		n = send(fd, pdu, pdu_len,
			 MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0) {
			__atomic_add_fetch(&shm->stats.iscsi_walker.ffp_pdus,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.iscsi_walker.bytes_out,
					   (unsigned long)n,
					   __ATOMIC_RELAXED);
		}
		iscsi_drain_after_bhs(fd);
	}
}

bool iscsi_login_walker(struct childdata *child)
{
	/* Per-child invocation counter for the chaos toggle.  Single-
	 * threaded inside a child (iscsi_target_probe does the same with
	 * its plain `static bool ns_unsupported`), so no atomic needed. */
	static unsigned int invocation_counter;

	unsigned char pdu[ISCSI_BHS_LEN + LOGIN_TEXT_MAX];
	unsigned int iters;
	unsigned int i;
	int fd;
	bool chaos;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.iscsi_walker.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	chaos = ((invocation_counter++ % ISCSI_WALKER_CHAOS_MODULO) == 0);
	if (chaos)
		__atomic_add_fetch(&shm->stats.iscsi_walker.chaos_runs, 1,
				   __ATOMIC_RELAXED);

	iters = BUDGETED(CHILD_OP_ISCSI_LOGIN_WALKER,
			 JITTER_RANGE(ISCSI_WALKER_ITERS_BASE));
	if (iters == 0)
		iters = 1;

	for (i = 0; i < iters; i++) {
		uint8_t isid[6];
		uint16_t tsih = 0;

		fd = iscsi_connect(ISCSI_CONNECT_TIMEOUT_MS);
		if (fd < 0) {
			if (errno == ECONNREFUSED) {
				ns_unsupported = true;
				if (valid_op)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
				__atomic_add_fetch(&shm->stats.iscsi_walker.no_target,
						   1, __ATOMIC_RELAXED);
				return true;
			}
			__atomic_add_fetch(&shm->stats.iscsi_walker.setup_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}
		__atomic_add_fetch(&shm->stats.iscsi_walker.connected, 1,
				   __ATOMIC_RELAXED);
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}

		if (chaos) {
			iscsi_send_chaos_burst(fd, pdu);

			(void)shutdown(fd, SHUT_RDWR);
			close(fd);
			continue;
		}

		/* Fresh ISID per iteration; both PDUs in the walk carry
		 * the same ISID so the kernel threads them into one
		 * session being driven forward. */
		rnd_fill(isid, sizeof(isid));

		if (iscsi_login_walk(fd, pdu, isid, &tsih))
			iscsi_send_ffp_burst(fd, pdu, isid, tsih);

		(void)shutdown(fd, SHUT_RDWR);
		close(fd);
	}

	return true;
}
