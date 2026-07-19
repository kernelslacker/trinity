/*
 * sctp_chunk_rx - inject crafted IPv4(SCTP) packets with malformed INIT /
 * INIT_ACK / COOKIE_ECHO chunks onto the loopback RX path inside a private
 * netns, so the kernel's chunk-walk / parameter-walk parsers in net/sctp/
 * sm_make_chunk.c, sm_statefuns.c (sctp_sf_do_5_1B_init /
 * sctp_sf_do_5_1D_ce / sctp_sf_ootb) and net/sctp/sm_sideeffect.c see the
 * length-fuzzed inputs that only enter through the wire.  Fills the
 * coverage gap sctp-assoc-churn.c explicitly documents: the socket-API
 * lifecycle path never enters the RX chunk-parse code because associations
 * only exist after the four-way INIT/COOKIE handshake completes, and the
 * setsockopt front door refuses to hand fuzzed bytes to the chunk walker.
 *
 * Bug class of interest: SCTP INIT / COOKIE_ECHO chunk and parameter TLV
 * length validation.  The recurring shape is "declared-length trusted
 * past the buffer end" -- a chunk_length or param_length claims more
 * bytes than remain in the packet, or an embedded chunk-inside-cookie
 * caches a length that the outer walker rechecks against the wire and
 * disagrees with (the class the recent stable backports around cookie
 * INIT-length validation address).  Truncation-past-a-parsed-length is
 * the specific KASAN-visible shape we aim at.  We do NOT try to repro a
 * fixed bug -- HMAC verification will reject any COOKIE_ECHO we forge
 * long before the fixed-length seam trips -- but reaching the length
 * checks that sit BEFORE HMAC verify still exercises the parser and
 * catches whatever KASAN-visible chunk-parse bugs exist.
 *
 * Sequence per invocation runs inside a userns_run_in_ns grandchild
 * (identity userns + CLONE_NEWNET, _exit reaps).  Persistent child runs a
 * one-shot best-effort modprobe of sctp before the userns hop
 * (finit_module needs CAP_SYS_MODULE in init_user_ns).  In the
 * grandchild:
 *   1. Bring lo up so 127.0.0.1 is a valid outer destination.
 *   2. Open an SCTP listen socket on 127.0.0.1:randport with
 *      O_NONBLOCK so any inbound ABORT/OOTB replies do not pin us.
 *      Doubles as the SCTP-module probe -- socket() failing with
 *      EPROTONOSUPPORT / EAFNOSUPPORT / ESOCKTNOSUPPORT / EACCES latches
 *      the whole op off for the remainder of the persistent child's
 *      lifetime (RELAXED-store to shm because the observation happens in
 *      a transient grandchild).
 *   3. Open SOCK_RAW / IPPROTO_RAW so we can hand-roll the IP + SCTP
 *      common header + chunk stack ourselves.  IP_HDRINCL is implicit
 *      for IPPROTO_RAW.
 *   4. BUDGETED+JITTER burst (base 6) of hand-rolled IPv4(SCTP) frames
 *      to 127.0.0.1:listen_port.  Each frame picks:
 *        - dominant chunk type (INIT / INIT_ACK / COOKIE_ECHO / SACK /
 *          HEARTBEAT / ABORT / random),
 *        - declared chunk length (truncated, exact, over-long, sub-4),
 *        - one or more parameter TLVs (IPv4 addr, IPv6 addr, state
 *          cookie, cookie preservative, supported addr types, hostname,
 *          unknown-type) each with a declared length that may lie
 *          about how many bytes actually follow,
 *        - optional additional chunks concatenated after the dominant
 *          one to exercise sctp_walk_chunks past a first-chunk length
 *          disagreement,
 *        - CRC-32c (Castagnoli, reversed poly 0x82F63B78) over the
 *          SCTP portion with the checksum field zeroed -- required for
 *          sctp_rcv_checksum() to accept the packet and dispatch to the
 *          state machine at all; without it, every frame is dropped
 *          before the chunk walker sees a byte.
 *   5. Send MSG_DONTWAIT so a queue-backed loopback cannot pin us past
 *      child.c's inherited SIGALRM(1s) safety net.
 *
 * Brick-safety: loopback only inside the private netns (outer daddr is
 * 127.0.0.1 inside the grandchild's own netns), one listener open/close
 * per invocation, all sends MSG_DONTWAIT, no persistent state.  Netns
 * destruction on grandchild exit catches any listener / raw fd left
 * behind by a mid-iteration bail.
 *
 * Latches: ns_unsupported_sctp_chunk_rx master gate on userns_run_in_ns()
 * -EPERM (unprivileged userns disabled).  shm->sctp_chunk_rx_kind_
 * unsupported on socket(IPPROTO_SCTP) EPROTONOSUPPORT /
 * ESOCKTNOSUPPORT / EAFNOSUPPORT / EACCES observed inside the
 * grandchild (missing CONFIG_IP_SCTP or a hardening policy blocking
 * raw SCTP sockets).  Per-kind latch lives in shm because the rejection
 * is observed inside the grandchild -- a process-local static would die
 * on _exit and re-attempt the missing kind forever.
 *
 * Not attempted here: reproducing a specific fixed cookie-length bug.
 * The kernel's HMAC verify will reject any forged COOKIE_ECHO before
 * the fixed length-cache check inside the cookie contents runs.  We
 * still land on the outer chunk-walk length checks and the parameter-
 * TLV walk inside sctp_process_init, which is where new bugs of the
 * same class typically surface.
 */

#include <errno.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <linux/netlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
#include "kernel/sctp.h"

/* IANA-assigned IP protocol number for SCTP.  Avoid pulling
 * netinet/in.h's IPPROTO_SCTP because it drags in symbols that
 * collide with the local kernel/socket.h wrappers on some libc
 * versions.  Value is stable per RFC 4960 s.15. */
#define IPPROTO_SCTP_LOCAL	132

/* SCTP chunk types (RFC 4960 s.3.2 chunk type registry). */
#define SCTP_CT_DATA		0x00
#define SCTP_CT_INIT		0x01
#define SCTP_CT_INIT_ACK	0x02
#define SCTP_CT_SACK		0x03
#define SCTP_CT_HEARTBEAT	0x04
#define SCTP_CT_HEARTBEAT_ACK	0x05
#define SCTP_CT_ABORT		0x06
#define SCTP_CT_SHUTDOWN	0x07
#define SCTP_CT_COOKIE_ECHO	0x0a
#define SCTP_CT_COOKIE_ACK	0x0b

/* SCTP parameter TLV types (RFC 4960 s.3.3.2.1 parameter registry). */
#define SCTP_P_IPV4_ADDR	0x0005
#define SCTP_P_IPV6_ADDR	0x0006
#define SCTP_P_STATE_COOKIE	0x0007
#define SCTP_P_COOKIE_PRESERV	0x0009
#define SCTP_P_HOSTNAME_ADDR	0x000b
#define SCTP_P_SUPPORTED_ADDR	0x000c

/* Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (grandchild's unshare(CLONE_NEWUSER) refused by a
 * hardened policy: user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we MUST
 * NOT touch the host's SCTP endpoint table, so the op stays disabled
 * for the remainder of this child's lifetime. */
static bool ns_unsupported_sctp_chunk_rx;

/* Per-grandchild bookkeeping.  Inherited as false at grandchild fork
 * time (the persistent child never sets it), set to true after the
 * grandchild's first rtnl_bring_lo_up() in its own fresh netns.  Dies
 * with the grandchild on _exit(), so each subsequent grandchild
 * correctly re-runs the bring-lo-up once in its own netns. */
static bool lo_brought_up;

/* Set once per persistent child after the modprobe attempt runs.
 * modprobe needs CAP_SYS_MODULE in init_user_ns, which the grandchild
 * does not hold, so it fires from the persistent child before the hop. */
static bool modprobe_attempted;

static bool kind_unsupported(void)
{
	return __atomic_load_n(&shm->sctp_chunk_rx_kind_unsupported,
			       __ATOMIC_RELAXED);
}

static void mark_kind_unsupported(void)
{
	__atomic_store_n(&shm->sctp_chunk_rx_kind_unsupported, true,
			 __ATOMIC_RELAXED);
}

/* Base per-invocation packet burst.  BUDGETED+JITTER scales it so a
 * productive run grows to ~iter*4 sends and an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT so the inherited SIGALRM(1s) cap
 * is not gated on socket-buffer backpressure. */
#define SCTP_CHUNK_RX_PACKET_BASE	6U

/* Outer packet buffer size.  Outer IPv4 (20) + SCTP common header (12)
 * + up to a few chunks with parameter TLVs fits well under 512; leaves
 * headroom for length randomisation past the declared chunk end. */
#define SCTP_PKT_MAX		512

/* Maximum extra chunks we tack onto the end of the dominant one so the
 * chunk walker keeps stepping past a first-chunk length disagreement.
 * Bounded so the packet stays under SCTP_PKT_MAX even with worst-case
 * chunk lengths. */
#define SCTP_EXTRA_CHUNKS_MAX	3U

/*
 * IPv4 header checksum, standard one's-complement over the 20-byte
 * header.  Kept local so this file has no dependency on utils/csum
 * plumbing.  Mirrors ip_gre-churn.c's ip_csum16.
 */
static __u16 ip_csum16(const void *data, size_t len)
{
	const __u16 *p = data;
	__u32 s = 0;

	while (len > 1) {
		s += *p++;
		len -= 2;
	}
	if (len)
		s += *(const __u8 *)p;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (__u16)~s;
}

/*
 * CRC-32c (Castagnoli, reversed polynomial 0x82F63B78) as required by
 * RFC 4960 s.6.8.  Bitwise implementation because a table pull would
 * bloat the file for a per-frame cost that is already noise next to
 * the socket call.  Not on any hot path -- runs once per injected
 * frame during a bounded burst.  Returns the finalised checksum
 * (inverted, in little-endian on the wire per RFC 3309 s.3.2 -- the
 * caller stores it as a __le32).
 */
static uint32_t sctp_crc32c(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xffffffffu;
	size_t i;
	int j;

	for (i = 0; i < len; i++) {
		crc ^= data[i];
		for (j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (0x82f63b78u & (uint32_t)(-(int32_t)(crc & 1u)));
	}
	return ~crc;
}

/*
 * Round v up to the next multiple of 4.  SCTP requires 4-byte alignment
 * between chunks and between parameter TLVs on the wire, regardless of
 * the length field's value.  Callers pad the buffer up to the aligned
 * offset with zero bytes.
 */
static size_t sctp_align4(size_t v)
{
	return (v + 3U) & ~(size_t)3U;
}

/*
 * Stamp a parameter TLV into buf at offset off.  Fields (all big-endian):
 *   type (2)   -- SCTP_P_* value
 *   length (2) -- declared length INCLUDING the 4-byte TLV header
 *   value ...  -- value_len bytes of body content
 * Returns the new (4-byte-aligned) offset.  If value_len > 0 and
 * declared_len is bigger than the header + body we actually write, that
 * is the intended "declared length lies" attack surface.
 */
static size_t stamp_param(uint8_t *buf, size_t off, size_t cap,
			  uint16_t type, uint16_t declared_len,
			  const void *value, size_t value_len)
{
	size_t written = 4 + value_len;

	if (off + written > cap)
		return off;
	*(uint16_t *)(buf + off + 0) = htons(type);
	*(uint16_t *)(buf + off + 2) = htons(declared_len);
	if (value_len)
		memcpy(buf + off + 4, value, value_len);
	off += written;
	while (off & 3U) {
		if (off >= cap)
			return off;
		buf[off++] = 0;
	}
	return off;
}

/*
 * Draw a plausibly-adversarial declared_length for a chunk or parameter
 * whose real body will be body_len bytes.  Mix in:
 *   - the exact length (body_len + hdr) -- baseline the walker should
 *     accept,
 *   - a truncated length (< real) -- walker over-reads its own bounds,
 *   - an over-long length (> real) -- walker over-reads INTO the next
 *     chunk / off the packet end,
 *   - a sub-header length (< 4) -- walker length-invariant check,
 *   - a length exactly equal to the header (empty body) -- edge case
 *     the assoc parser has historically flunked.
 * Caller supplies hdr (4 for chunks and TLVs).
 */
static uint16_t pick_declared_len(size_t body_len, size_t hdr)
{
	uint16_t real = (uint16_t)(hdr + body_len);
	uint32_t roll = rnd_modulo_u32(10);

	switch (roll) {
	case 0:
	case 1:
	case 2:
		return real;					/* exact */
	case 3:
	case 4:
		return real > hdr ? (uint16_t)(real - 1) : real;	/* trunc -1 */
	case 5:
		return real > hdr + 4 ? (uint16_t)(real - 4) : real;	/* trunc -4 */
	case 6:
		return (uint16_t)(real + 4);			/* over +4 */
	case 7:
		return (uint16_t)(real + 128);			/* over +128 */
	case 8:
		return (uint16_t)hdr;				/* empty body */
	default:
		return (uint16_t)(rnd_modulo_u32(4));		/* sub-header */
	}
}

/*
 * Draw the dominant chunk type for this packet.  Weighting favours the
 * INIT/INIT_ACK/COOKIE_ECHO seam the bug class lives at, but keeps
 * DATA/SACK/HEARTBEAT/ABORT and pure random types in the mix so the
 * chunk-type dispatch table (sctp_chunk_event_lookup) is exercised too.
 */
static uint8_t pick_chunk_type(void)
{
	uint32_t roll = rnd_modulo_u32(16);

	switch (roll) {
	case 0: case 1: case 2: case 3:
		return SCTP_CT_INIT;
	case 4: case 5:
		return SCTP_CT_INIT_ACK;
	case 6: case 7: case 8:
		return SCTP_CT_COOKIE_ECHO;
	case 9:
		return SCTP_CT_SACK;
	case 10:
		return SCTP_CT_HEARTBEAT;
	case 11:
		return SCTP_CT_ABORT;
	case 12:
		return SCTP_CT_SHUTDOWN;
	case 13:
		return SCTP_CT_DATA;
	default:
		return (uint8_t)rnd_modulo_u32(256);
	}
}

/*
 * Stamp the INIT / INIT_ACK fixed body (16 bytes) followed by a random
 * subset of parameter TLVs into buf at offset off, returning the offset
 * of the byte AFTER the last TLV.  Callers set the enclosing chunk's
 * declared length independently of what we write -- the whole point is
 * to let those disagree.
 */
static size_t stamp_init_body(uint8_t *buf, size_t off, size_t cap)
{
	uint32_t init_tag;
	uint32_t a_rwnd;
	uint16_t num_out;
	uint16_t num_in;
	uint32_t init_tsn;
	unsigned int nparams;
	unsigned int i;

	if (off + 16 > cap)
		return off;

	init_tag = rand32();
	a_rwnd   = rand32();
	num_out  = (uint16_t)(1 + rnd_modulo_u32(64));
	num_in   = (uint16_t)(1 + rnd_modulo_u32(64));
	init_tsn = rand32();

	*(uint32_t *)(buf + off + 0)  = htonl(init_tag);
	*(uint32_t *)(buf + off + 4)  = htonl(a_rwnd);
	*(uint16_t *)(buf + off + 8)  = htons(num_out);
	*(uint16_t *)(buf + off + 10) = htons(num_in);
	*(uint32_t *)(buf + off + 12) = htonl(init_tsn);
	off += 16;

	nparams = rnd_modulo_u32(6);
	for (i = 0; i < nparams; i++) {
		uint32_t pick = rnd_modulo_u32(7);
		uint16_t declared;
		uint8_t addr[16];
		uint8_t stub[64];
		size_t body_len;

		switch (pick) {
		case 0: {
			/* IPv4 address parameter: 4-byte body.  Declared
			 * length is fuzzed against the real 8. */
			uint32_t a = htonl(0x7f000001u |
					   (rnd_modulo_u32(255) << 8));
			declared = pick_declared_len(4, 4);
			off = stamp_param(buf, off, cap, SCTP_P_IPV4_ADDR,
					  declared, &a, 4);
			break;
		}
		case 1: {
			/* IPv6 address parameter: 16-byte body.  Random
			 * loopback-ish bytes; declared length is fuzzed. */
			generate_rand_bytes(addr, sizeof(addr));
			addr[0] = 0xfe;	/* link-local-ish, harmless */
			addr[1] = 0x80;
			declared = pick_declared_len(16, 4);
			off = stamp_param(buf, off, cap, SCTP_P_IPV6_ADDR,
					  declared, addr, 16);
			break;
		}
		case 2: {
			/* State cookie parameter: variable body up to 32
			 * bytes.  Declared length is deliberately fuzzed
			 * to hit the embedded-length caching seam. */
			body_len = 4 + rnd_modulo_u32(29);
			generate_rand_bytes(stub, body_len);
			declared = pick_declared_len(body_len, 4);
			off = stamp_param(buf, off, cap, SCTP_P_STATE_COOKIE,
					  declared, stub, body_len);
			break;
		}
		case 3: {
			/* Cookie preservative: 4-byte body. */
			uint32_t preserv = rand32();
			declared = pick_declared_len(4, 4);
			off = stamp_param(buf, off, cap, SCTP_P_COOKIE_PRESERV,
					  declared, &preserv, 4);
			break;
		}
		case 4: {
			/* Supported address types: 2-byte entries, count 1-4.
			 * The kernel walks this list checking each entry
			 * fits the declared param length. */
			unsigned int count = 1 + rnd_modulo_u32(4);
			uint16_t types[4] = {
				htons(SCTP_P_IPV4_ADDR),
				htons(SCTP_P_IPV6_ADDR),
				htons(SCTP_P_HOSTNAME_ADDR),
				htons((uint16_t)(rnd_modulo_u32(0xffffu))),
			};
			body_len = 2U * count;
			declared = pick_declared_len(body_len, 4);
			off = stamp_param(buf, off, cap,
					  SCTP_P_SUPPORTED_ADDR, declared,
					  types, body_len);
			break;
		}
		case 5: {
			/* Hostname address: variable-length ASCII-ish body.
			 * NUL-terminated in the wire format, but we allow
			 * the declared length to lie about the boundary. */
			body_len = 4 + rnd_modulo_u32(29);
			generate_rand_bytes(stub, body_len);
			stub[body_len - 1] = 0;
			declared = pick_declared_len(body_len, 4);
			off = stamp_param(buf, off, cap, SCTP_P_HOSTNAME_ADDR,
					  declared, stub, body_len);
			break;
		}
		default: {
			/* Unknown parameter type -- kernel branch action
			 * depends on the top two type bits per RFC 4960
			 * s.3.2.1.  Random type, random body. */
			uint16_t t = (uint16_t)(rnd_modulo_u32(0xffffu));
			body_len = rnd_modulo_u32(16);
			generate_rand_bytes(stub, body_len);
			declared = pick_declared_len(body_len, 4);
			off = stamp_param(buf, off, cap, t, declared,
					  stub, body_len);
			break;
		}
		}
	}
	return off;
}

/*
 * Stamp the body of the dominant chunk into buf, returning the offset
 * of the byte AFTER the body.  Body content depends on chunk type;
 * COOKIE_ECHO gets a fully random cookie blob (HMAC verify will drop
 * it, but only after the outer length checks the bug class lives in
 * have run).  DATA / SACK / HEARTBEAT / ABORT / SHUTDOWN / random get
 * short random-byte bodies; the interesting seam for those is the
 * chunk_length disagreement in the walker, not their body semantics.
 */
static size_t stamp_chunk_body(uint8_t *buf, size_t off, size_t cap,
			       uint8_t chunk_type)
{
	uint8_t stub[128];
	size_t body_len;

	switch (chunk_type) {
	case SCTP_CT_INIT:
	case SCTP_CT_INIT_ACK:
		return stamp_init_body(buf, off, cap);
	case SCTP_CT_COOKIE_ECHO:
		body_len = 4 + rnd_modulo_u32(60);
		if (off + body_len > cap)
			body_len = cap - off;
		generate_rand_bytes(stub, body_len);
		memcpy(buf + off, stub, body_len);
		return off + body_len;
	default:
		body_len = rnd_modulo_u32(16);
		if (off + body_len > cap)
			body_len = cap - off;
		generate_rand_bytes(stub, body_len);
		memcpy(buf + off, stub, body_len);
		return off + body_len;
	}
}

/*
 * Build one full IPv4(SCTP) frame in buf.  Returns the total wire length
 * ready for sendto().  Layout:
 *   [outer IPv4 (20 bytes)]
 *   [SCTP common header (12 bytes): sport, dport, verif_tag, checksum]
 *   [dominant chunk header (4) + body]
 *   [optional extra chunks (4 header + body each)]
 * The chunk-length fields are fuzzed via pick_declared_len(); the
 * checksum is a CRC-32c over the SCTP portion, with the checksum field
 * itself zeroed during computation (RFC 4960 s.6.8).  Outer IP length
 * and checksum are exact so the IP layer accepts and dispatches.
 */
static size_t build_frame(uint8_t *buf, uint16_t dst_port)
{
	struct iphdr *iph;
	size_t off;
	size_t sctp_start;
	size_t chunk_start;
	size_t body_end;
	size_t frame_end;
	uint8_t chunk_type;
	uint16_t declared;
	unsigned int extras;
	unsigned int i;
	uint32_t crc;

	memset(buf, 0, SCTP_PKT_MAX);
	iph = (struct iphdr *)buf;
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_SCTP_LOCAL;
	iph->saddr    = htonl(0x7f000001u);
	iph->daddr    = htonl(0x7f000001u);
	off = sizeof(*iph);

	/* SCTP common header. */
	sctp_start = off;
	*(uint16_t *)(buf + off + 0) = htons((uint16_t)(1024 + rnd_modulo_u32(60000)));
	*(uint16_t *)(buf + off + 2) = htons(dst_port);
	*(uint32_t *)(buf + off + 4) = rand32();		/* verification tag */
	*(uint32_t *)(buf + off + 8) = 0;			/* checksum -- filled below */
	off += 12;

	/* Dominant chunk. */
	chunk_type = pick_chunk_type();
	chunk_start = off;
	buf[off + 0] = chunk_type;
	buf[off + 1] = (uint8_t)(rnd_modulo_u32(256));	/* chunk flags */
	off += 4;
	body_end = stamp_chunk_body(buf, off, SCTP_PKT_MAX, chunk_type);
	declared = pick_declared_len(body_end - off, 4);
	*(uint16_t *)(buf + chunk_start + 2) = htons(declared);
	off = sctp_align4(body_end);
	if (off > SCTP_PKT_MAX)
		off = SCTP_PKT_MAX;

	/* Optional extra chunks -- exercises the chunk walker past a
	 * first-chunk length disagreement. */
	extras = rnd_modulo_u32(SCTP_EXTRA_CHUNKS_MAX + 1);
	for (i = 0; i < extras; i++) {
		size_t extra_start;
		uint8_t extra_type;
		size_t extra_body_end;
		uint16_t extra_declared;

		if (off + 8 >= SCTP_PKT_MAX)
			break;
		extra_type  = pick_chunk_type();
		extra_start = off;
		buf[off + 0] = extra_type;
		buf[off + 1] = (uint8_t)(rnd_modulo_u32(256));
		off += 4;
		extra_body_end = stamp_chunk_body(buf, off, SCTP_PKT_MAX,
						  extra_type);
		extra_declared = pick_declared_len(extra_body_end - off, 4);
		*(uint16_t *)(buf + extra_start + 2) = htons(extra_declared);
		off = sctp_align4(extra_body_end);
		if (off > SCTP_PKT_MAX)
			off = SCTP_PKT_MAX;
	}

	frame_end = off;

	/* SCTP checksum over sctp_start..frame_end with the checksum field
	 * zeroed (already zeroed above).  Stored little-endian on the wire
	 * per RFC 3309 s.3.2 -- crc32c_le is what the kernel computes. */
	crc = sctp_crc32c(buf + sctp_start, frame_end - sctp_start);
	buf[sctp_start + 8]  = (uint8_t)(crc >> 0);
	buf[sctp_start + 9]  = (uint8_t)(crc >> 8);
	buf[sctp_start + 10] = (uint8_t)(crc >> 16);
	buf[sctp_start + 11] = (uint8_t)(crc >> 24);

	/* Outer IPv4 tot_len + header checksum. */
	iph->tot_len = htons((uint16_t)frame_end);
	iph->check   = 0;
	iph->check   = ip_csum16(iph, sizeof(*iph));

	return frame_end;
}

/*
 * Per-invocation state shared across the sctp_chunk_rx_iter_* helpers.
 * Lives on the orchestrator's stack.  Fields default so the teardown
 * path can close-or-skip unconditionally regardless of which earlier
 * phase bailed.  child is the caller's struct childdata so phase
 * helpers can attribute per-childop yield counters to child->op_type.
 */
struct sctp_chunk_rx_iter_ctx {
	int listener;
	int raw;
	uint16_t listen_port_n;
	struct childdata *child;
};

/*
 * Open the SCTP listen socket on 127.0.0.1:0, recover the ephemeral
 * port via getsockname, then flip it to O_NONBLOCK so no inbound
 * ABORT / OOTB reply can pin us past child.c's SIGALRM(1s) safety net.
 * Doubles as the SCTP-module probe -- if socket() rejects with the
 * "protocol / family / type / permission" errno set, latch the whole
 * op off for the persistent child's lifetime.  Returns 0 on success or
 * -1 if the iteration should bail to the out: cleanup path.
 */
static int sctp_chunk_rx_iter_setup_listener(struct sctp_chunk_rx_iter_ctx *ctx)
{
	struct sockaddr_in sa;
	socklen_t slen;

	ctx->listener = socket(AF_INET, SOCK_SEQPACKET | SOCK_CLOEXEC,
			       IPPROTO_SCTP_LOCAL);
	if (ctx->listener < 0) {
		if (errno == EPROTONOSUPPORT || errno == ESOCKTNOSUPPORT ||
		    errno == EAFNOSUPPORT   || errno == EACCES) {
			mark_kind_unsupported();
			const enum child_op_type op = ctx->child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(0x7f000001u);
	sa.sin_port = 0;
	if (bind(ctx->listener, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -1;
	slen = sizeof(sa);
	if (getsockname(ctx->listener, (struct sockaddr *)&sa, &slen) < 0)
		return -1;
	ctx->listen_port_n = sa.sin_port;

	if (listen(ctx->listener, 4) < 0)
		return -1;

	(void)fcntl(ctx->listener, F_SETFL, O_NONBLOCK);
	return 0;
}

/*
 * Open SOCK_RAW / IPPROTO_RAW so we can hand-roll the outer IPv4 +
 * SCTP header + chunk stack.  IP_HDRINCL is implicit for IPPROTO_RAW.
 * On failure (typically EACCES with a hardening policy blocking raw
 * sockets in the grandchild's userns) we bail; a follow-up invocation
 * still gets a fresh grandchild and gets to try again -- unlike the
 * IPPROTO_SCTP socket check above, raw-socket denial can be transient.
 */
static int sctp_chunk_rx_iter_setup_raw(struct sctp_chunk_rx_iter_ctx *ctx)
{
	ctx->raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (ctx->raw < 0)
		return -1;
	return 0;
}

/*
 * BUDGETED+JITTER burst of hand-rolled IPv4(SCTP) frames at 127.0.0.1:
 * listen_port_n.  Each iteration rerolls the dominant chunk type, its
 * declared length, its parameter TLV list, and any trailing extra
 * chunks; a valid CRC-32c gets sctp_rcv() past the checksum gate and
 * the frame lands in the state machine.  MSG_DONTWAIT so a backed-up
 * loopback queue cannot stall the iteration past the inherited
 * SIGALRM(1s) cap.  Void return: burst outcome is purely stat ticks.
 */
static void sctp_chunk_rx_iter_send_burst(struct sctp_chunk_rx_iter_ctx *ctx)
{
	struct sockaddr_in dst;
	unsigned int iters;
	unsigned int i;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = htonl(0x7f000001u);

	iters = BUDGETED(CHILD_OP_SCTP_CHUNK_RX,
			 JITTER_RANGE(SCTP_CHUNK_RX_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		uint8_t pkt[SCTP_PKT_MAX];
		size_t len;
		ssize_t n;

		len = build_frame(pkt, ntohs(ctx->listen_port_n));
		n = sendto(ctx->raw, pkt, len, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.sctp_chunk_rx.packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Close whichever fds we managed to open.  Runs on every exit path --
 * both the success path falling through after the burst returns, and
 * the early-bail goto out from any earlier phase failure.  Fields
 * default to -1 via the orchestrator's designated initialiser so the
 * guards skip fds that were never opened.  Netns destruction on
 * grandchild exit catches anything left behind.
 */
static void sctp_chunk_rx_iter_teardown(struct sctp_chunk_rx_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);
	if (ctx->listener >= 0)
		close(ctx->listener);
}

struct sctp_chunk_rx_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any SCTP
 * listener, raw socket and packet buffers left behind are reaped along
 * with the namespace.  Return value is ignored by the helper.
 */
static int sctp_chunk_rx_in_ns(void *arg)
{
	struct sctp_chunk_rx_ctx *cctx = (struct sctp_chunk_rx_ctx *)arg;
	struct childdata *child = cctx->child;
	struct sctp_chunk_rx_iter_ctx ctx = {
		.listener = -1,
		.raw = -1,
		.child = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	struct nl_ctx nl = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (kind_unsupported())
		return 0;

	if (!lo_brought_up) {
		if (nl_open(&nl, &opts) == 0) {
			rtnl_bring_lo_up(&nl);
			nl_close(&nl);
			lo_brought_up = true;
		}
	}

	if (sctp_chunk_rx_iter_setup_listener(&ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (sctp_chunk_rx_iter_setup_raw(&ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	__atomic_add_fetch(&shm->stats.sctp_chunk_rx.listener_ok,
			   1, __ATOMIC_RELAXED);

	sctp_chunk_rx_iter_send_burst(&ctx);

out:
	sctp_chunk_rx_iter_teardown(&ctx);
	return 0;
}

bool sctp_chunk_rx(struct childdata *child)
{
	struct sctp_chunk_rx_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.sctp_chunk_rx.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_sctp_chunk_rx)
		return true;

	if (kind_unsupported()) {
		__atomic_add_fetch(&shm->stats.sctp_chunk_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!modprobe_attempted) {
		modprobe_attempted = true;
		try_modprobe("sctp");
	}

	rc = userns_run_in_ns(CLONE_NEWNET, sctp_chunk_rx_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_sctp_chunk_rx = true;
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.sctp_chunk_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.sctp_chunk_rx.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
