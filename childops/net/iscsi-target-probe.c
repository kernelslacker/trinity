/*
 * iscsi_target_probe - exercise the in-kernel LIO iSCSI target's login
 * and post-login SCSI Command paths over a real loopback TCP connection.
 *
 * The wire-format parsers in drivers/target/iscsi/iscsi_target_nego.c
 * (Login Request BHS validation + text-key parameter list parsing) and
 * drivers/target/iscsi/iscsi_target.c (iscsit_handle_scsi_cmd dispatch
 * into target_core_mod's CDB tables) are unreachable from trinity's
 * NETLINK_ISCSI fuzzer: that's the configfs / NL control plane, not the
 * on-the-wire framer.  Hitting them requires an actual TCP connection
 * to a portal followed by a Login PDU whose BHS passes the opcode /
 * length validators and whose data segment claims valid-looking text
 * keys.  After a successful login, SCSI Command PDUs reach the CDB
 * dispatcher with the kernel-side INITIATOR_NEXUS already established.
 *
 * The fuzz box host-side setup leaves an LIO target listening on
 * 127.0.0.1:3260 with a small ramdisk backstore at LUN 0, configured in
 * demo mode so InitiatorName / TargetName are sufficient (no CHAP).
 * When the target isn't present (different host, no module loaded), the
 * very first connect() returns ECONNREFUSED and this childop latches a
 * per-child sticky flag so it stops probing.  No noisy spam.
 *
 * Per-invocation cycle:
 *   1. nonblocking connect(127.0.0.1:3260), poll(POLLOUT, 1s)
 *   2. pick one of four PDU shapes uniformly:
 *        (a) wholly random 48-byte BHS — exercises BHS validators
 *        (b) valid Login opcode with fuzzed text-key data segment
 *        (c) well-formed Login + post-login fuzzed SCSI Command CDB
 *        (d) Login PDU whose BHS DataSegmentLength is deliberately
 *            decoupled from the actual on-wire segment (over- /
 *            under-declare, huge near-24-bit-max, or zero-while-
 *            non-empty) — probes iscsit's length validators in
 *            drivers/target/iscsi/iscsi_target_nego.c and the
 *            text-buffer sizing path that allocates / copies against
 *            the declared length.  Arms (a)-(c) keep declared == actual
 *            so the existing truthful coverage doesn't regress.
 *   3. send() the PDU with MSG_DONTWAIT | MSG_NOSIGNAL
 *   4. drain any response with poll(POLLIN, 200ms) + recv()
 *   5. close
 *
 * Self-bounding: BUDGETED + JITTER_RANGE around base 2 (so 1-3 iters
 * per call), per-iteration poll timeouts are 1s connect + 200ms recv,
 * sockets are O_NONBLOCK so a wedged peer can't pin us past child.c's
 * SIGALRM(1s) safety net.  Loopback only.
 *
 * Failure modes (none propagated as childop failure):
 *   - ECONNREFUSED on the first connect: no LIO target running.
 *     Latched per-process via ns_unsupported.
 *   - socket() ENOMEM / EMFILE: counted, skip cycle.
 *   - send() EPIPE / ECONNRESET: target reset us mid-PDU — expected
 *     coverage when the BHS validator rejected the framing.
 *   - recv() EAGAIN after poll: target didn't reply within 200ms.
 *     Common for malformed PDUs that just get dropped.
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
#include "debug.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "generated/parser_vocab.h"

#include "kernel/socket.h"
/* iSCSI opcode constants from RFC 7143 §11.  Defined locally so we
 * don't drag in <scsi/iscsi_proto.h> / <linux/scsi/iscsi_proto.h>
 * which aren't shipped in every sysroot. */
#define ISCSI_TARGET_PORT		3260
#define ISCSI_OP_LOGIN			0x03	/* Login Request */
#define ISCSI_OP_SCSI_CMD		0x01	/* SCSI Command */
#define ISCSI_OP_IMMEDIATE		0x40	/* I bit in opcode byte */
#define ISCSI_BHS_LEN			48

/* Login flags byte: T=1 (Transit), C=0, CSG=01 (OperationalNegotiation),
 * NSG=11 (FullFeature).  Skips the SecurityNegotiation stage entirely,
 * which matches the demo_mode_write_protect=0 / authentication=0 LIO
 * target config we're talking to. */
#define ISCSI_LOGIN_FLAGS_TRANSIT_OP_TO_FF	0x87

/* SCSI Command flags: F=1 (Final PDU), R=1 (Read), ATTR=001 (SIMPLE).
 * Pairs with a 16-byte INQUIRY / READ_CAPACITY style CDB; the request
 * side never sends OutData so the W bit stays clear. */
#define ISCSI_SCSI_CMD_FLAGS_READ_SIMPLE	0xC1

/* Cap on Login text data we'll generate per PDU.  Demo-mode LIO accepts
 * up to MaxRecvDataSegmentLength bytes, but small keeps us well under
 * any reasonable receive-buffer pressure and bounds the per-cycle
 * memcpy / send work. */
#define LOGIN_TEXT_MAX			512

/* Receive buffer for login / scsi responses.  Login responses are
 * normally ~256 bytes; SCSI responses + sense data fit in <512.  We
 * only need to drain the socket, not parse it. */
#define ISCSI_RX_BUF			1024

/* poll timeouts.  Connect window kept at 1s to absorb scheduler jitter
 * on a busy fuzz host; per-recv window kept short so a single cycle
 * never pins the child past the SIGALRM(1s) child.c safety net. */
#define ISCSI_CONNECT_TIMEOUT_MS	1000
#define ISCSI_RECV_TIMEOUT_MS		200

/* Inner-loop iteration base.  BUDGETED + JITTER_RANGE keeps actual
 * iters in the 1-3 range under default budget; adapt_budget can grow
 * it on productive runs without growing the wall-clock significantly
 * since each iter is bounded by ISCSI_RECV_TIMEOUT_MS + tiny TCP RTT. */
#define ISCSI_ITERS_BASE		2U

/* Latched once per child on the first ECONNREFUSED: no LIO target is
 * listening, so further attempts in this process are pure waste. */
static bool ns_unsupported;

/* Encode 24-bit big-endian length into bhs[5..7].  iSCSI DataSegment
 * lengths are 24-bit MSB-first; this is the only multi-byte field
 * we need to byte-swap by hand (ITT / CmdSN / ExpStatSN are u32 fields
 * but the kernel treats them as opaque echo cookies for the response
 * direction, so randomising them in any byte order is fine). */
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

/* Nonblocking connect with a poll-based timeout.  Returns the connected
 * fd, or -1 with errno preserved on failure / timeout.  Caller checks
 * errno == ECONNREFUSED specifically to latch the no-target gate. */
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
		__atomic_add_fetch(&shm->stats.iscsi_target_probe.bytes_in,
				   (unsigned long)n, __ATOMIC_RELAXED);
}

/* Build a wholly-random 48-byte BHS.  The byte 0 opcode field is
 * masked into the ISCSI_OP_* range so the front-door opcode validator
 * has a non-trivial chance of selecting an interesting branch rather
 * than rejecting on "unknown opcode" every single iteration. */
static size_t build_random_bhs(unsigned char *out)
{
	rnd_fill(out, ISCSI_BHS_LEN);
	/* Bias the opcode into 0x00-0x1f range (the defined initiator
	 * opcodes all live there: NOP-Out 0x00, SCSI Cmd 0x01, SCSI
	 * Task Mgmt 0x02, Login 0x03, Text 0x04, SCSI Data-Out 0x05,
	 * Logout 0x06, SNACK 0x10).  Leave the I bit (0x40) random. */
	out[0] = (unsigned char)((out[0] & 0x40) | (out[0] & 0x1f));
	/* Force AHS length to a small value: most random patterns end up
	 * with absurd AHS lengths that the target rejects before the
	 * interesting code paths.  0-3 keeps the dispatcher engaged. */
	out[4] = (unsigned char)(out[4] & 0x03);
	/* Bound DataSegmentLength to a small value so the target doesn't
	 * sit waiting for megabytes of data we'll never send. */
	out[5] = 0;
	out[6] = 0;
	out[7] = (unsigned char)(out[7] & 0x0f);
	return ISCSI_BHS_LEN;
}

/* iSCSI login text-key vocabulary.  Built as the union of two disjoint
 * pools so emitted PDUs draw from the widest plausible RFC 3720 §12 /
 * §11 + LIO-extension set:
 *
 *   1. iscsi_login_key_vocab[] / iscsi_login_value_vocab[] from
 *      include/generated/parser_vocab.h -- mined offline from
 *      drivers/target/iscsi/iscsi_target_parameters.h by
 *      scripts/seed-vocab-from-dmesg.py, so the negotiation-token set
 *      tracks the kernel header at regen time.  Also carries the LIO
 *      default-value pool (LIO.Target, "0.0.0.0:0000,0", ...) which the
 *      parser's value handlers accept verbatim.
 *
 *   2. iscsi_login_*_extras[] below -- entries the offline miner does
 *      not surface today.  Keys: the CHAP_* security-negotiation set
 *      from iscsi_target_nego.c, plus MaxOutstandingUnexpectedPDUs.
 *      Values: small decimal literals and common buffer sizes for the
 *      numeric-key arithmetic parsers, the reverse-order "None,CRC32C"
 *      list-tokenizer probe, and two example iqn.* names for the
 *      Name-shaped key value handlers.
 *
 * The pools are kept disjoint by construction so pick_vocab() yields a
 * de-duplicated draw without runtime deduplication; when the generated
 * header grows to cover one of the extras, prune it from the list here.
 * Tokens are emitted bare (no '=') so the caller appends the separator
 * and value half itself -- this is what lets the text-key parser walk
 * past its initial separator check into the per-key value handlers. */
static const char *const iscsi_login_key_extras[] = {
	"CHAP_A",
	"CHAP_I",
	"CHAP_C",
	"CHAP_N",
	"CHAP_R",
	"MaxOutstandingUnexpectedPDUs",
};

static const char *const iscsi_login_value_extras[] = {
	"5",
	"3",
	"4",
	"512",
	"1024",
	"2048",
	"4096",
	"None,CRC32C",
	"iqn.2026-06.org.example:initiator",
	"iqn.2026-06.org.example:target",
};

/* Uniformly draw one entry from the concatenation of @primary[0..pn) and
 * @extras[0..en) without materialising the union -- pn and en are
 * compile-time constants so the modulo collapses to a single
 * rnd_modulo_u32() per call.  Caller passes the generated pool as
 * @primary and the inline extras as @extras; entries on either side
 * are weighted by pool size, which matches "draw uniformly from the
 * union" because the pools are disjoint. */
static const char *pick_vocab(const char *const *primary, unsigned int pn,
			      const char *const *extras, unsigned int en)
{
	unsigned int idx;

	BUG_ON(pn + en == 0);
	idx = rnd_modulo_u32(pn + en);

	return (idx < pn) ? primary[idx] : extras[idx - pn];
}

/* 1/VALUE_RANDOM_RECIP key=value pairs use a random-printable value
 * instead of a vocab value.  Keeps a deliberate fuzz signal on the
 * per-key value validators without dominating; the bulk of traffic
 * gets past framing into the post-parse handlers, which is the point. */
#define VALUE_RANDOM_RECIP	8U

static size_t build_login_fuzzed(unsigned char *out)
{
	unsigned char *bhs = out;
	unsigned char *data = out + ISCSI_BHS_LEN;
	size_t data_off = 0;
	size_t total;
	unsigned int nr_keys;
	unsigned int i;

	memset(bhs, 0, ISCSI_BHS_LEN);
	bhs[0] = ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE;
	bhs[1] = (unsigned char)(rnd_u32() & 0xff);	/* fuzz flags */
	bhs[2] = 0;					/* Version-max */
	bhs[3] = 0;					/* Version-min */
	bhs[4] = 0;					/* TotalAHSLength */
	rnd_fill(bhs + 8, 6);				/* ISID */
	/* TSIH = 0 (new session) at bhs[14..15] left as fuzz residue */
	rnd_fill(bhs + 16, 4);				/* ITT */
	bhs[20] = 0;
	bhs[21] = 1;					/* CID = 1 */
	/* CmdSN / ExpStatSN are echo cookies — random is fine */
	rnd_fill(bhs + 24, 8);

	/* Build 3-8 key=value pairs.  Each pair is emitted as
	 *   <key from the union pool> '=' <value> '\0'
	 * so the LIO text-key parser locates its separator on every
	 * entry and dispatches to the per-key value handler. */
	nr_keys = 3 + rnd_modulo_u32(6);
	for (i = 0; i < nr_keys; i++) {
		const char *key = pick_vocab(iscsi_login_key_vocab,
					     NR_ISCSI_LOGIN_KEY_VOCAB,
					     iscsi_login_key_extras,
					     ARRAY_SIZE(iscsi_login_key_extras));
		size_t key_len = strlen(key);
		bool random_value = (rnd_modulo_u32(VALUE_RANDOM_RECIP) == 0);
		const char *vocab_val = NULL;
		size_t val_len;
		size_t need;

		if (random_value) {
			val_len = 1 + rnd_modulo_u32(24);
		} else {
			vocab_val = pick_vocab(iscsi_login_value_vocab,
					       NR_ISCSI_LOGIN_VALUE_VOCAB,
					       iscsi_login_value_extras,
					       ARRAY_SIZE(iscsi_login_value_extras));
			val_len = strlen(vocab_val);
		}
		need = key_len + 1 + val_len + 1;	/* key + '=' + value + NUL */

		if (data_off + need >= LOGIN_TEXT_MAX)
			break;
		memcpy(data + data_off, key, key_len);
		data_off += key_len;
		data[data_off++] = '=';
		if (random_value) {
			while (val_len--) {
				unsigned int c = 32 + rnd_modulo_u32(95);

				data[data_off++] = (unsigned char)c;
			}
		} else {
			memcpy(data + data_off, vocab_val, val_len);
			data_off += val_len;
		}
		data[data_off++] = '\0';
	}
	/* Pad to 4-byte multiple */
	while (data_off & 3) {
		data[data_off++] = '\0';
	}

	put_be24(bhs + 5, (uint32_t)data_off);
	total = ISCSI_BHS_LEN + data_off;
	return total;
}

/* Build a well-formed Login Request that the target should accept under
 * demo mode: announces a typical InitiatorName and the configured
 * TargetName, declares AuthMethod=None, SessionType=Normal, and a
 * basic set of operational parameters.  The kernel walks the full
 * text-key handler set on this path and replies with a Login
 * Response. */
static const char login_text_well_formed[] =
	"InitiatorName=iqn.1993-08.org.debian:01:t\0"
	"TargetName=iqn.2026-05.fuzz:t\0"
	"SessionType=Normal\0"
	"AuthMethod=None\0"
	"HeaderDigest=None\0"
	"DataDigest=None\0"
	"DefaultTime2Wait=2\0"
	"DefaultTime2Retain=20\0"
	"MaxOutstandingR2T=1\0"
	"MaxConnections=1\0"
	"InitialR2T=Yes\0"
	"ImmediateData=Yes\0"
	"MaxBurstLength=262144\0"
	"FirstBurstLength=65536\0"
	"MaxRecvDataSegmentLength=8192\0"
	"DataPDUInOrder=Yes\0"
	"DataSequenceInOrder=Yes\0"
	"ErrorRecoveryLevel=0\0";

static size_t build_login_well_formed(unsigned char *out)
{
	unsigned char *bhs = out;
	unsigned char *data = out + ISCSI_BHS_LEN;
	/* sizeof includes the trailing implicit '\0'; we want every
	 * NUL-terminated key in the buffer to land on the wire, including
	 * the very last one's separator. */
	size_t data_len = sizeof(login_text_well_formed) - 1;
	size_t padded = (data_len + 3) & ~(size_t)3;

	memset(bhs, 0, ISCSI_BHS_LEN);
	bhs[0] = ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE;
	bhs[1] = ISCSI_LOGIN_FLAGS_TRANSIT_OP_TO_FF;
	bhs[2] = 0;
	bhs[3] = 0;
	bhs[4] = 0;
	rnd_fill(bhs + 8, 6);				/* ISID */
	bhs[14] = 0;					/* TSIH high */
	bhs[15] = 0;					/* TSIH low (new session) */
	rnd_fill(bhs + 16, 4);				/* ITT */
	bhs[20] = 0;
	bhs[21] = 1;					/* CID = 1 */
	/* CmdSN = 0, ExpStatSN = 0 for a fresh login */
	memset(bhs + 24, 0, 8);

	memcpy(data, login_text_well_formed, data_len);
	if (padded > data_len)
		memset(data + data_len, 0, padded - data_len);

	put_be24(bhs + 5, (uint32_t)padded);
	return ISCSI_BHS_LEN + padded;
}

/* Kinds of declared-vs-actual DataSegmentLength mismatch we inject when
 * the decoupled-length arm is selected.  All four bypass the truthful
 * encoding the other arms maintain — none of them changes how many
 * payload bytes go on the wire, only the 24-bit field in BHS[5..7]. */
enum length_decouple_kind {
	LENGTH_DECOUPLE_OVER,	/* declared > actual: kernel expects more */
	LENGTH_DECOUPLE_UNDER,	/* declared < actual: kernel sees less */
	LENGTH_DECOUPLE_HUGE,	/* declared near top of 24-bit range */
	LENGTH_DECOUPLE_ZERO,	/* declared == 0 while actual > 0 */
	LENGTH_DECOUPLE__NR,
};

/* Cap for the OVER bump.  Big enough to push the declared length past
 * MaxRecvDataSegmentLength on most LIO configs (default 8192) so the
 * length validator has to reject rather than silently allocate, but
 * small enough to keep arithmetic in u32 + put_be24's 24-bit field. */
#define LENGTH_DECOUPLE_OVER_BUMP_MAX	16384U

/* Overwrite the BHS DataSegmentLength (bytes 5..7) with a value that
 * does NOT match @actual.  Returns the declared length actually written
 * so the caller can record / count the magnitude.  Does not modify the
 * payload itself — only the wire-format declaration. */
static uint32_t decouple_data_length(unsigned char *bhs, uint32_t actual)
{
	uint32_t declared;
	enum length_decouple_kind kind;

	kind = (enum length_decouple_kind)rnd_modulo_u32(LENGTH_DECOUPLE__NR);

	/* UNDER and ZERO collapse to a real mismatch only when there's
	 * something to shrink.  If actual == 0, both produce 0, which
	 * isn't a decouple — promote to OVER instead. */
	if (actual == 0 &&
	    (kind == LENGTH_DECOUPLE_UNDER || kind == LENGTH_DECOUPLE_ZERO))
		kind = LENGTH_DECOUPLE_OVER;

	switch (kind) {
	case LENGTH_DECOUPLE_OVER:
		declared = actual + 1U +
			rnd_modulo_u32(LENGTH_DECOUPLE_OVER_BUMP_MAX);
		break;
	case LENGTH_DECOUPLE_UNDER:
		/* actual > 0 here: rnd_modulo_u32(actual) ∈ [0, actual-1]. */
		declared = rnd_modulo_u32(actual);
		break;
	case LENGTH_DECOUPLE_HUGE:
		/* Top byte of the 24-bit field set; low 16 bits random. */
		declared = 0x00ff0000U | (rnd_u32() & 0x0000ffffU);
		break;
	case LENGTH_DECOUPLE_ZERO:
	default:
		declared = 0;
		break;
	}
	declared &= 0x00ffffffU;
	put_be24(bhs + 5, declared);
	return declared;
}

/* Build a Login PDU whose declared DataSegmentLength is intentionally
 * inconsistent with the bytes we'll send.  Reuses one of the existing
 * truthful builders for the underlying shape so the rest of the BHS
 * stays plausible — only the length field is the variable.  Sent on
 * arm (d) only; the truthful builders are unmodified. */
static size_t build_login_decoupled_length(unsigned char *out)
{
	size_t total;
	uint32_t actual_data;

	/* Pick a sane base so the front-door opcode / flags validators
	 * have a chance to accept the PDU and let the length checks run.
	 * 50/50 between the two existing Login shapes. */
	if (rnd_u32() & 1U)
		total = build_login_fuzzed(out);
	else
		total = build_login_well_formed(out);

	actual_data = (uint32_t)(total - ISCSI_BHS_LEN);
	(void)decouple_data_length(out, actual_data);
	return total;
}

/* Build a SCSI Command PDU targeting LUN 0 with a fuzzed 16-byte CDB.
 * Sent only after a successful login PDU (arm c).  The kernel
 * dispatches into the per-CDB handler tables; READ-side commands are
 * the safest fuzz target since they don't transfer initiator-supplied
 * payload bytes that could exercise unrelated copy_from_user paths. */
static size_t build_scsi_cmd_fuzzed(unsigned char *out)
{
	unsigned char *bhs = out;

	memset(bhs, 0, ISCSI_BHS_LEN);
	bhs[0] = ISCSI_OP_SCSI_CMD;
	bhs[1] = ISCSI_SCSI_CMD_FLAGS_READ_SIMPLE;
	bhs[2] = 0;
	bhs[3] = 0;
	bhs[4] = 0;					/* TotalAHSLength */
	bhs[5] = 0;
	bhs[6] = 0;
	bhs[7] = 0;					/* DataSegmentLength = 0 */
	memset(bhs + 8, 0, 8);				/* LUN 0 */
	rnd_fill(bhs + 16, 4);				/* ITT */
	/* Expected Data Transfer Length: small (256-65535) so the target
	 * doesn't allocate huge buffers for our random CDB. */
	bhs[20] = 0;
	bhs[21] = 0;
	bhs[22] = (unsigned char)(1 + rnd_modulo_u32(255));
	bhs[23] = (unsigned char)rnd_u32();
	/* CmdSN, ExpStatSN are echo cookies; non-zero so the target
	 * advances its window. */
	bhs[24] = 0;
	bhs[25] = 0;
	bhs[26] = 0;
	bhs[27] = 1;					/* CmdSN = 1 */
	bhs[28] = 0;
	bhs[29] = 0;
	bhs[30] = 0;
	bhs[31] = 1;					/* ExpStatSN = 1 */
	/* Fuzz the 16-byte CDB.  Bias the first byte toward defined
	 * READ-class opcodes so we exercise interesting dispatcher arms
	 * more often than "unknown opcode" rejects: 0x12 INQUIRY,
	 * 0x25 READ_CAPACITY, 0x28 READ_10, 0x88 READ_16, 0x9E SERVICE_ACTION_IN_16,
	 * 0xA0 REPORT_LUNS, 0x00 TEST_UNIT_READY. */
	rnd_fill(bhs + 32, 16);
	{
		static const unsigned char cdb_opcodes[] = {
			0x00, 0x12, 0x25, 0x28, 0x88, 0x9E, 0xA0, 0x1A, 0x5A,
		};

		if ((rnd_u32() & 3) != 0)
			bhs[32] = cdb_opcodes[rnd_modulo_u32(sizeof(cdb_opcodes))];
	}
	return ISCSI_BHS_LEN;
}

bool iscsi_target_probe(struct childdata *child)
{
	unsigned char pdu[ISCSI_BHS_LEN + LOGIN_TEXT_MAX];
	unsigned int iters;
	unsigned int i;
	int fd;
	ssize_t n;
	size_t pdu_len;
	unsigned int arm;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.iscsi_target_probe.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	iters = BUDGETED(CHILD_OP_ISCSI_TARGET_PROBE,
			 JITTER_RANGE(ISCSI_ITERS_BASE));
	if (iters == 0)
		iters = 1;

	for (i = 0; i < iters; i++) {
		fd = iscsi_connect(ISCSI_CONNECT_TIMEOUT_MS);
		if (fd < 0) {
			if (errno == ECONNREFUSED) {
				/* No LIO target on this host.  Latch and
				 * be quiet for the rest of this child's
				 * life -- siblings will independently latch
				 * the first time they try.  init_child
				 * redirected stderr to /dev/null so the
				 * previous outputerr here was lost; the
				 * iscsi_target_probe_no_target counter is
				 * the survivor signal. */
				ns_unsupported = true;
				if (valid_op)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
				__atomic_add_fetch(&shm->stats.iscsi_target_probe.no_target,
						   1, __ATOMIC_RELAXED);
				return true;
			}
			__atomic_add_fetch(&shm->stats.iscsi_target_probe.setup_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}
		__atomic_add_fetch(&shm->stats.iscsi_target_probe.connected,
				   1, __ATOMIC_RELAXED);
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}

		arm = rnd_modulo_u32(4);
		switch (arm) {
		case 0:
			pdu_len = build_random_bhs(pdu);
			break;
		case 1:
			pdu_len = build_login_fuzzed(pdu);
			break;
		case 2:
			pdu_len = build_login_well_formed(pdu);
			break;
		default:
			pdu_len = build_login_decoupled_length(pdu);
			__atomic_add_fetch(&shm->stats.iscsi_target_probe.length_decoupled,
					   1, __ATOMIC_RELAXED);
			break;
		}

		n = send(fd, pdu, pdu_len, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0) {
			__atomic_add_fetch(&shm->stats.iscsi_target_probe.login_sent,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.iscsi_target_probe.bytes_out,
					   (unsigned long)n, __ATOMIC_RELAXED);
		}

		iscsi_drain(fd);
		__atomic_add_fetch(&shm->stats.iscsi_target_probe.login_replies,
				   1, __ATOMIC_RELAXED);

		/* Arm (c): after the well-formed Login, send one fuzzed
		 * SCSI Command PDU.  We don't track whether the login
		 * actually succeeded (the target's reply parser is out
		 * of scope) — if it failed the SCSI Command just gets
		 * dropped or RST'd, which is itself reasonable coverage
		 * of the post-login state-machine validators. */
		if (arm == 2) {
			pdu_len = build_scsi_cmd_fuzzed(pdu);
			n = send(fd, pdu, pdu_len,
				 MSG_DONTWAIT | MSG_NOSIGNAL);
			if (n > 0) {
				__atomic_add_fetch(&shm->stats.iscsi_target_probe.scsi_cmd_sent,
						   1, __ATOMIC_RELAXED);
				__atomic_add_fetch(&shm->stats.iscsi_target_probe.bytes_out,
						   (unsigned long)n,
						   __ATOMIC_RELAXED);
			}
			iscsi_drain(fd);
		}

		(void)shutdown(fd, SHUT_RDWR);
		close(fd);
	}

	return true;
}
