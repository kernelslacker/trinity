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
 * What this childop does:
 *
 *   INIT          open a nonblocking TCP connection to 127.0.0.1:3260
 *                 and send a Login Request PDU with CSG=0
 *                 (SecurityNegotiation), no TRANSIT, no CONTINUE, and a
 *                 well-formed InitiatorName + AuthMethod=None data
 *                 segment.  Target should accept the framing and reply
 *                 with a Login Response keeping us in CSG=0.
 *
 *   SECURITY_NEG  send a second Login Request PDU with TRANSIT=1,
 *                 CSG=0, NSG=1 (LoginOperationalNegotiation).  This is
 *                 the kernel's CSG=0 -> CSG=1 transition handler;
 *                 reaching it requires that the prior INIT PDU framing
 *                 was accepted, which is the whole point of walking the
 *                 state machine instead of one-shotting.
 *
 *   OP_NEG        send a third Login Request PDU with TRANSIT=1,
 *                 CSG=1, NSG=3 (FullFeaturePhase) carrying the
 *                 operational keys: TargetName, HeaderDigest=None,
 *                 DataDigest=None, MaxRecvDataSegmentLength=8192, plus
 *                 the rest of the OP_NEG mandatory set.
 *
 *   FFP           the Login phase is over; the kernel-side session is
 *                 in the post-login command-dispatch state.  Emit a
 *                 small burst (1-4) of fuzzed BHS PDUs with the opcode
 *                 biased into the FFP-valid set (NOP-Out, SCSI Cmd,
 *                 SCSI Task Mgmt, Text Req, SCSI Data-Out, Logout Req,
 *                 SNACK) and the rest of the header random.  This is
 *                 the path the CVE corpus drivers/target/iscsi work
 *                 exercises -- post-login command dispatch.
 *
 * Chaos toggle: every ISCSI_WALKER_CHAOS_MODULO=5 invocations the
 * walker skips the state-machine walk entirely and sends a burst of
 * wholly-random 48-byte BHS PDUs.  Keeps the front-door BHS / parser
 * coverage the older iscsi_target_probe random-spam path was
 * producing intact, so the new walker doesn't silently erode the
 * coverage we had before.
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
 * target in SecurityNegotiation; the response echoes CSG=0.
 *
 * SECURITY_NEG -> OP_NEG transition: T=1, C=0, CSG=0, NSG=1 -> 0x81.
 * Asks the kernel to advance from CSG=0 to CSG=1 on the next response.
 *
 * OP_NEG -> FFP transition: T=1, C=0, CSG=1, NSG=3 -> 0x87.  Asks the
 * kernel to advance from CSG=1 straight into FullFeaturePhase, where
 * the post-login command dispatcher takes over. */
#define ISCSI_LOGIN_FLAGS_INIT			0x00
#define ISCSI_LOGIN_FLAGS_TRANSIT_SEC_TO_OP	0x81
#define ISCSI_LOGIN_FLAGS_TRANSIT_OP_TO_FF	0x87

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
 * CONTINUE, ISID supplied by the caller (so subsequent PDUs in the
 * same iteration can reuse it for the same session), TSIH=0 (new
 * session), CID=1, CmdSN=0, ExpStatSN=0.  Returns the total PDU
 * length (BHS + padded data segment). */
static size_t build_login_init(unsigned char *out, uint8_t isid[6])
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
	memcpy(bhs + 8, isid, 6);			/* ISID */
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

/* Empty-but-valid Login Request PDU for the SECURITY_NEG -> OP_NEG
 * transition: TRANSIT=1, CSG=0, NSG=1, no data segment.  The kernel
 * sees AuthMethod=None from the prior INIT PDU, so SecurityNegotiation
 * has no outstanding work and the TRANSIT bit advances us to
 * LoginOperationalNegotiation on the next response. */
static size_t build_login_security_neg(unsigned char *out, uint8_t isid[6])
{
	unsigned char *bhs = out;

	memset(bhs, 0, ISCSI_BHS_LEN);
	bhs[0] = ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE;
	bhs[1] = ISCSI_LOGIN_FLAGS_TRANSIT_SEC_TO_OP;
	/* Version, AHS, DataSegmentLength all stay 0 */
	memcpy(bhs + 8, isid, 6);			/* same ISID */
	bhs[14] = 0;					/* TSIH high */
	bhs[15] = 0;					/* TSIH low */
	rnd_fill(bhs + 16, 4);				/* ITT */
	bhs[20] = 0;
	bhs[21] = 1;					/* CID = 1 */
	/* CmdSN = 0, ExpStatSN = 0 — Immediate Login doesn't advance
	 * the CmdSN window so leaving zeros matches the spec. */
	memset(bhs + 24, 0, 8);

	return ISCSI_BHS_LEN;
}

/* Text-key data segment for the OP_NEG state's TRANSIT -> FFP PDU.
 * Operational keys the kernel walks during LoginOperationalNegotiation:
 * TargetName is mandatory for normal sessions, HeaderDigest /
 * DataDigest negotiate the per-PDU CRC, MaxRecvDataSegmentLength caps
 * incoming PDU sizes, and the time-window / R2T / burst keys round out
 * the standard demo-mode acceptable set. */
static const char login_text_op_neg[] =
	"TargetName=iqn.2026-05.fuzz:t\0"
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

/* Build the OP_NEG -> FFP Login PDU: TRANSIT=1, CSG=1, NSG=3, with the
 * operational-keys data segment.  This is the gate to the post-login
 * command dispatcher; if the kernel accepts the framing and the keys,
 * the session is in FullFeaturePhase on the next response and SCSI
 * Command PDUs are now reachable. */
static size_t build_login_op_neg(unsigned char *out, uint8_t isid[6])
{
	unsigned char *bhs = out;
	unsigned char *data = out + ISCSI_BHS_LEN;
	size_t data_len = sizeof(login_text_op_neg) - 1;
	size_t padded = (data_len + 3) & ~(size_t)3;

	memset(bhs, 0, ISCSI_BHS_LEN);
	bhs[0] = ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE;
	bhs[1] = ISCSI_LOGIN_FLAGS_TRANSIT_OP_TO_FF;
	memcpy(bhs + 8, isid, 6);			/* same ISID */
	bhs[14] = 0;
	bhs[15] = 0;
	rnd_fill(bhs + 16, 4);				/* ITT */
	bhs[20] = 0;
	bhs[21] = 1;					/* CID = 1 */
	memset(bhs + 24, 0, 8);

	memcpy(data, login_text_op_neg, data_len);
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
static size_t build_ffp_fuzz(unsigned char *out, uint8_t isid[6])
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
	bhs[14] = 0;					/* TSIH high */
	bhs[15] = 0;					/* TSIH low */
	/* ITT / CmdSN / ExpStatSN left random — they are echo cookies
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
	ssize_t n;
	size_t pdu_len;
	bool chaos;

	__atomic_add_fetch(&shm->stats.iscsi_walker_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	chaos = ((invocation_counter++ % ISCSI_WALKER_CHAOS_MODULO) == 0);
	if (chaos)
		__atomic_add_fetch(&shm->stats.iscsi_walker_chaos_runs, 1,
				   __ATOMIC_RELAXED);

	iters = BUDGETED(CHILD_OP_ISCSI_LOGIN_WALKER,
			 JITTER_RANGE(ISCSI_WALKER_ITERS_BASE));
	if (iters == 0)
		iters = 1;

	for (i = 0; i < iters; i++) {
		uint8_t isid[6];

		fd = iscsi_connect(ISCSI_CONNECT_TIMEOUT_MS);
		if (fd < 0) {
			if (errno == ECONNREFUSED) {
				ns_unsupported = true;
				__atomic_store_n(&shm->stats.childop_latch_reason[child->op_type],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
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
		__atomic_add_fetch(&shm->stats.childop_setup_accepted[child->op_type],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop_data_path[child->op_type],
				   1, __ATOMIC_RELAXED);

		if (chaos) {
			unsigned int chaos_pdus = 1 + rnd_modulo_u32(CHAOS_PDUS_MAX);
			unsigned int j;

			for (j = 0; j < chaos_pdus; j++) {
				pdu_len = build_chaos_bhs(pdu);
				n = send(fd, pdu, pdu_len,
					 MSG_DONTWAIT | MSG_NOSIGNAL);
				if (n > 0) {
					__atomic_add_fetch(&shm->stats.iscsi_walker_chaos_pdus,
							   1, __ATOMIC_RELAXED);
					__atomic_add_fetch(&shm->stats.iscsi_walker_bytes_out,
							   (unsigned long)n,
							   __ATOMIC_RELAXED);
				}
				iscsi_drain(fd);
			}

			(void)shutdown(fd, SHUT_RDWR);
			close(fd);
			continue;
		}

		/* Fresh ISID per iteration; the three PDUs in the walk all
		 * carry the same ISID so the kernel treats them as one
		 * session being driven forward. */
		rnd_fill(isid, sizeof(isid));

		pdu_len = build_login_init(pdu, isid);
		n = send(fd, pdu, pdu_len, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0) {
			__atomic_add_fetch(&shm->stats.iscsi_walker_state_init_sent,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.iscsi_walker_bytes_out,
					   (unsigned long)n, __ATOMIC_RELAXED);
		}
		iscsi_drain(fd);

		pdu_len = build_login_security_neg(pdu, isid);
		n = send(fd, pdu, pdu_len, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0) {
			__atomic_add_fetch(&shm->stats.iscsi_walker_state_security_sent,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.iscsi_walker_bytes_out,
					   (unsigned long)n, __ATOMIC_RELAXED);
		}
		iscsi_drain(fd);

		pdu_len = build_login_op_neg(pdu, isid);
		n = send(fd, pdu, pdu_len, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0) {
			__atomic_add_fetch(&shm->stats.iscsi_walker_state_op_neg_sent,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.iscsi_walker_bytes_out,
					   (unsigned long)n, __ATOMIC_RELAXED);
		}
		iscsi_drain(fd);

		/* FullFeaturePhase fuzz burst.  The Login walk is over;
		 * the kernel-side session is in the post-login command-
		 * dispatch state (or it RST'd us mid-walk, in which case
		 * these sends just get EPIPE and the stat increments
		 * stop tracking).  Emit 1..FFP_PDUS_MAX fuzzed BHS PDUs
		 * with the opcode biased into the FFP-valid set. */
		__atomic_add_fetch(&shm->stats.iscsi_walker_ffp_iters, 1,
				   __ATOMIC_RELAXED);
		{
			unsigned int j;
			unsigned int ffp_pdus = 1 + rnd_modulo_u32(FFP_PDUS_MAX);

			for (j = 0; j < ffp_pdus; j++) {
				pdu_len = build_ffp_fuzz(pdu, isid);
				n = send(fd, pdu, pdu_len,
					 MSG_DONTWAIT | MSG_NOSIGNAL);
				if (n > 0) {
					__atomic_add_fetch(&shm->stats.iscsi_walker_ffp_pdus,
							   1, __ATOMIC_RELAXED);
					__atomic_add_fetch(&shm->stats.iscsi_walker_bytes_out,
							   (unsigned long)n,
							   __ATOMIC_RELAXED);
				}
				iscsi_drain(fd);
			}
		}

		(void)shutdown(fd, SHUT_RDWR);
		close(fd);
	}

	return true;
}
