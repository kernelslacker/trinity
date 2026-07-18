/*
 * rxrpc_key_install -- fuzz net/rxrpc/key.c token parsers via add_key(2).
 *
 * The AF_RXRPC socket-family grammar can't reach the per-call security setup
 * (rxrpc_init_client_call_security -> init_connection_security / issue_challenge
 * / verify_response in rxkad.c / rxgk.c).  This op closes the easiest slice of
 * that gap: the kernel-side token parser rxrpc_preparse() in net/rxrpc/key.c,
 * reachable purely via add_key("rxrpc", ...) with no socket setup.
 *
 * Iterations rotate seven arms across the three wire formats behind the
 * parser: v1 binary RXKAD, AFS-XDR envelope (with XDR-RXKAD / XDR-RXGK
 * inners), and "rxrpc_s" server keys via preparse_server_key dispatch.
 * Malformed lengths, bad sec_ix, and truncated headers drive the parser
 * fall-through paths.
 *
 * Lifecycle: all keys land on KEY_SPEC_THREAD_KEYRING so thread exit
 * auto-reaps them.  Live serials are kept in a small ring so later iterations
 * KEYCTL_REVOKE / KEYCTL_UNLINK them and drive the rxrpc_destroy{,_s}
 * teardown paths.  -EDQUOT (keys.maxkeys cap) is expected and counted.
 *
 * can_run probe: add_key("rxrpc", "trinity-probe", NULL, 0,
 * KEY_SPEC_THREAD_KEYRING) hits the null-security fast path with no
 * allocation.  -ENOPROTOOPT / -ENOSYS / -EAFNOSUPPORT / -ENODEV latches
 * unsupported_rxrpc_key_install for the rest of the process (no CONFIG_RXRPC
 * or rxrpc.ko not loaded, so the key type isn't registered).
 *
 * Self-bounding: 200 ms wall-clock budget + MAX_ITERATIONS cap.  No socket,
 * no fds, no /sys writes, no module load -- pure parser fuzz.
 */

#include <errno.h>
#include <linux/keyctl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "childop-cmp.h"
#include "syscall-gate.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "kernel/socket.h"
#define BUDGET_NS	200000000L	/* 200 ms */
#define MAX_ITERATIONS	48
#define LIVE_KEYS_RING	8

/* Mirror the canonical RxRPC security indices so we don't depend on a
 * <linux/rxrpc.h> that may predate RXGK on older toolchains.  Values are
 * stable UAPI -- RXRPC_SECURITY_RXKAD == 2, RXRPC_SECURITY_YFS_RXGK == 6.
 * AFSTOKEN_MAX == 8, AFSTOKEN_CELL_MAX == 64 (cap on cellname length in
 * the XDR envelope). */
#define RXKAD_SEC_IDX		2u
#define RXGK_SEC_IDX		6u
#define XDR_AFSTOKEN_MAX	8
#define XDR_AFSTOKEN_CELL_MAX	64

/* Latched per-process: add_key("rxrpc", ...) returned an "rxrpc key type
 * not registered" errno on the can_run probe.  Set on the first call,
 * consulted at the top of the op so subsequent invocations short-circuit
 * without burning a syscall. */
static bool unsupported_rxrpc_key_install;
static bool probe_done;

enum rxrpc_key_arm {
	ARM_NULL = 0,
	ARM_SHORT_RANDOM,
	ARM_V1_BINARY,
	ARM_XDR_ENVELOPE,
	ARM_XDR_RXKAD,
	ARM_XDR_RXGK,
	ARM_SERVER_KEY,
	ARM_NR,
};

static bool errno_is_unsupported(int e)
{
	return e == ENOPROTOOPT || e == ENOSYS || e == EAFNOSUPPORT ||
	       e == ENODEV;
}

static void ring_insert(int32_t *ring, int32_t serial)
{
	unsigned int i, slot;

	for (i = 0; i < LIVE_KEYS_RING; i++) {
		if (ring[i] == 0) {
			ring[i] = serial;
			return;
		}
	}
	slot = rnd_modulo_u32(LIVE_KEYS_RING);
	ring[slot] = serial;
}

static int32_t ring_pick(const int32_t *ring)
{
	unsigned int i, count = 0;
	unsigned int picks[LIVE_KEYS_RING];

	for (i = 0; i < LIVE_KEYS_RING; i++) {
		if (ring[i] != 0)
			picks[count++] = i;
	}
	if (count == 0)
		return 0;
	return ring[picks[rnd_modulo_u32(count)]];
}

static void ring_drop(int32_t *ring, int32_t serial)
{
	unsigned int i;

	for (i = 0; i < LIVE_KEYS_RING; i++) {
		if (ring[i] == serial) {
			ring[i] = 0;
			return;
		}
	}
}

/* One-shot can_run probe: add an empty-payload "rxrpc" key.  This is the
 * cheapest possible parser entry -- rxrpc_preparse() returns 0 immediately
 * for datalen == 0 with no allocation, no inner-parser call, no token list
 * mutation.  Failure errnos that mean "key type not registered" latch the
 * unsupported flag for the rest of the process; transient errnos (EDQUOT,
 * EPERM from a restrictive keyring policy) do not latch. */
static void probe_rxrpc_key_supported(void)
{
	long rc;

	if (probe_done)
		return;
	probe_done = true;

	rc = trinity_raw_syscall(__NR_add_key, "rxrpc", "trinity-rxrpc-probe",
		     NULL, (size_t) 0,
		     (unsigned long) KEY_SPEC_THREAD_KEYRING);
	if (rc < 0 && errno_is_unsupported(errno)) {
		unsupported_rxrpc_key_install = true;
		__atomic_add_fetch(&shm->stats.rxrpc_key_install.unsupported,
				   1, __ATOMIC_RELAXED);
		outputerr("rxrpc_key_install: add_key(rxrpc) probe failed: %s -- latching unsupported_rxrpc_key_install\n",
			  strerror(errno));
	}
}

/* Append n bytes of random padding to the end of a buffer at offset *off,
 * advancing *off.  Caller has sized the buffer. */
static void append_rand(unsigned char *buf, size_t *off, size_t n)
{
	generate_rand_bytes(buf + *off, (unsigned int) n);
	*off += n;
}

/* Append a __be32 word at *off, advancing *off. */
static void append_be32(unsigned char *buf, size_t *off, uint32_t v)
{
	buf[*off + 0] = (unsigned char)((v >> 24) & 0xff);
	buf[*off + 1] = (unsigned char)((v >> 16) & 0xff);
	buf[*off + 2] = (unsigned char)((v >>  8) & 0xff);
	buf[*off + 3] = (unsigned char)( v        & 0xff);
	*off += 4;
}

/*
 * Build an XDR envelope head (flags + cellname + ntoken) into buf at
 * offset *off.  Cellname is forced to printable ASCII so the kernel's
 * isprint() loop accepts it on the happy path; one-in-eight iterations
 * intentionally injects a non-printable byte to drive the not_xdr branch.
 */
static void build_xdr_head(unsigned char *buf, size_t *off,
			   uint32_t flags, uint32_t cell_len,
			   uint32_t ntoken, bool inject_bad_byte)
{
	size_t i;
	size_t paddedlen = (cell_len + 3) & ~3U;

	append_be32(buf, off, flags);
	append_be32(buf, off, cell_len);

	for (i = 0; i < cell_len; i++)
		buf[*off + i] = (unsigned char) ('a' + (i % 26));
	if (inject_bad_byte && cell_len > 0)
		buf[*off + (size_t) rnd_modulo_u32(cell_len)] = 0x01;
	for (i = cell_len; i < paddedlen; i++)
		buf[*off + i] = 0;
	*off += paddedlen;

	append_be32(buf, off, ntoken);
}

/*
 * Build an XDR-RXKAD inner body (sec_ix == 2).  Layout per
 * rxrpc_preparse_xdr_rxkad: 8 __be32 header words (vice_id, kvno,
 * session_key[8 bytes spread across xdr[2]/xdr[3]], start, expiry,
 * primary_flag, ticket_length) followed by tktlen ticket bytes.
 */
static void build_xdr_rxkad_inner(unsigned char *buf, size_t *off,
				  uint32_t tktlen)
{
	size_t pad = (tktlen + 3) & ~3U;
	uint32_t i;

	append_be32(buf, off, (uint32_t) rand32());		/* vice_id */
	append_be32(buf, off, (uint32_t) rand32());		/* kvno */
	append_rand(buf, off, 8);				/* session_key */
	append_be32(buf, off, (uint32_t) rand32());		/* start */
	append_be32(buf, off, (uint32_t) rand32());		/* expiry */
	append_be32(buf, off, (uint32_t) rand32() & 1U);	/* primary_flag */
	append_be32(buf, off, tktlen);				/* ticket_length */

	for (i = 0; i < tktlen; i++)
		buf[*off + i] = (unsigned char) (rand32() & 0xff);
	for (i = tktlen; i < pad; i++)
		buf[*off + i] = 0;
	*off += pad;
}

/*
 * Build an XDR-RXGK inner body (sec_ix == 6).  Layout per
 * rxrpc_preparse_xdr_yfs_rxgk: six 64-bit fields (begintime, endtime,
 * level, lifetime, bytelife, enctype) then opaque key<> then opaque
 * ticket<>.  Lengths are length-prefixed and 4-padded.  Caller picks
 * keylen / tktlen so we can deliberately overshoot on some iterations.
 * Caller also picks endtime (s64 100ns-units) to cover the four
 * branches of the expiry check at net/rxrpc/key.c:232-237: zero (skip
 * the whole block), positive (rxrpc_s64_to_time64 -> nonneg ->
 * prep->expiry update), negative (rxrpc_s64_to_time64 -> negative ->
 * goto expired), and s64 extremes near INT64_MIN.
 */
static void build_xdr_rxgk_inner(unsigned char *buf, size_t *off,
				 uint32_t keylen, uint32_t tktlen,
				 int64_t level, int64_t enctype, int64_t endtime)
{
	uint32_t kpad = (keylen + 3) & ~3U;
	uint32_t tpad = (tktlen + 3) & ~3U;
	uint32_t i;

	append_be32(buf, off, (uint32_t) (rand32() & 0x7fffffff));	/* begintime hi */
	append_be32(buf, off, (uint32_t) rand32());			/* begintime lo */
	append_be32(buf, off, (uint32_t) ((uint64_t) endtime >> 32));	/* endtime hi */
	append_be32(buf, off, (uint32_t) ((uint64_t) endtime));		/* endtime lo */
	append_be32(buf, off, (uint32_t) ((uint64_t) level >> 32));
	append_be32(buf, off, (uint32_t) ((uint64_t) level));
	append_be32(buf, off, 0);					/* lifetime hi */
	append_be32(buf, off, (uint32_t) rand32());			/* lifetime lo */
	append_be32(buf, off, 0);					/* bytelife hi */
	append_be32(buf, off, (uint32_t) rand32());			/* bytelife lo */
	append_be32(buf, off, (uint32_t) ((uint64_t) enctype >> 32));
	append_be32(buf, off, (uint32_t) ((uint64_t) enctype));

	append_be32(buf, off, keylen);
	for (i = 0; i < keylen; i++)
		buf[*off + i] = (unsigned char) (rand32() & 0xff);
	for (i = keylen; i < kpad; i++)
		buf[*off + i] = 0;
	*off += kpad;

	append_be32(buf, off, tktlen);
	for (i = 0; i < tktlen; i++)
		buf[*off + i] = (unsigned char) (rand32() & 0xff);
	for (i = tktlen; i < tpad; i++)
		buf[*off + i] = 0;
	*off += tpad;
}

/*
 * Issue add_key("rxrpc", desc, payload, paylen, KEY_SPEC_THREAD_KEYRING).
 * Returns the new serial on success, 0 on failure (and bumps stats).
 */
static int32_t do_add_rxrpc(const char *desc,
			    const void *payload, size_t paylen)
{
	long rc;

	__atomic_add_fetch(&shm->stats.rxrpc_key_install.calls,
			   1, __ATOMIC_RELAXED);
	rc = trinity_cmp_syscall(__NR_add_key, "rxrpc", desc, payload, paylen,
		     (unsigned long) KEY_SPEC_THREAD_KEYRING);
	if (rc < 0) {
		if (errno == EDQUOT)
			__atomic_add_fetch(&shm->stats.rxrpc_key_install.quota_hits,
					   1, __ATOMIC_RELAXED);
		else if (errno_is_unsupported(errno) && !unsupported_rxrpc_key_install) {
			unsupported_rxrpc_key_install = true;
			__atomic_add_fetch(&shm->stats.rxrpc_key_install.unsupported,
					   1, __ATOMIC_RELAXED);
			outputerr("rxrpc_key_install: add_key(rxrpc) latched unsupported_rxrpc_key_install: %s\n",
				  strerror(errno));
		}
		return 0;
	}
	return (int32_t) rc;
}

/*
 * Same shape for "rxrpc_s" server keys.  No EDQUOT distinction needed --
 * the rxrpc_s preparse path goes through the same key_jar slab and the
 * quota-hit counter on the client side already covers the relevant
 * pressure regime.
 */
static int32_t do_add_rxrpc_s(const char *desc,
			      const void *payload, size_t paylen)
{
	long rc;

	__atomic_add_fetch(&shm->stats.rxrpc_key_install.calls,
			   1, __ATOMIC_RELAXED);
	rc = trinity_cmp_syscall(__NR_add_key, "rxrpc_s", desc, payload, paylen,
		     (unsigned long) KEY_SPEC_THREAD_KEYRING);
	if (rc < 0) {
		if (errno == EDQUOT)
			__atomic_add_fetch(&shm->stats.rxrpc_key_install.quota_hits,
					   1, __ATOMIC_RELAXED);
		return 0;
	}
	return (int32_t) rc;
}

static void arm_null(int32_t *ring, unsigned int iter)
{
	char desc[64];
	int32_t serial;

	snprintf(desc, sizeof(desc), "trinity-rxrpc-null-%u-%u",
		 (unsigned int) mypid(), iter);
	serial = do_add_rxrpc(desc, NULL, 0);
	if (serial != 0)
		ring_insert(ring, serial);
}

static void arm_short_random(int32_t *ring, unsigned int iter)
{
	unsigned char buf[28];
	size_t paylen;
	char desc[64];
	int32_t serial;

	/* datalen 1..27 -- below the 28-byte XDR cutoff so rxrpc_preparse()
	 * skips rxrpc_preparse_xdr() entirely and goes straight to the v1
	 * binary fast path.  Most lengths fail the kver / sizeof(*v1) /
	 * total-length checks at the top of the v1 branch. */
	paylen = (size_t) (1 + rnd_modulo_u32(27));
	generate_rand_bytes(buf, (unsigned int) paylen);

	snprintf(desc, sizeof(desc), "trinity-rxrpc-short-%u-%u",
		 (unsigned int) mypid(), iter);
	serial = do_add_rxrpc(desc, buf, paylen);
	if (serial != 0)
		ring_insert(ring, serial);
}

static void arm_v1_binary(int32_t *ring, unsigned int iter)
{
	unsigned char buf[256];
	size_t off = 0;
	uint32_t kver;
	uint16_t sec_idx, ticket_length;
	uint16_t actual_ticket;
	char desc[64];
	int32_t serial;

	/* Most of the time we want kver==1 and security_index==RXKAD so the
	 * parser walks through to the alloc/copy path.  One in four uses a
	 * deliberately wrong field to drive the early-reject branches.
	 *
	 * Each of the three v1-header fields is routed through the shadow
	 * consume resolver so the childop_cmp_consume_would_* counters
	 * size what a live pool-served constant would do at this site.
	 * kver / security_index are EXACT-family (equality gates in
	 * rxrpc_preparse_xdr / rxrpc_preparse v1); ticket_length is a
	 * BOUNDARY-family length check.  The resolver is shadow-only and
	 * returns the rng draw verbatim -- pick stream unchanged. */
	kver = (rnd_modulo_u32(4) == 0) ? (uint32_t)(rand32() | 2u) : 1u;
	kver = (uint32_t) childop_cmp_value(__NR_add_key, CMP_HINT_EXACT,
					     0UL, (unsigned long) kver);
	sec_idx = (rnd_modulo_u32(4) == 0)
			? (uint16_t)(rand32() & 0xff)
			: RXKAD_SEC_IDX;
	sec_idx = (uint16_t) childop_cmp_value(__NR_add_key, CMP_HINT_EXACT,
					        0UL, (unsigned long) sec_idx);
	ticket_length = (uint16_t) rnd_modulo_u32(64);
	ticket_length = (uint16_t) childop_cmp_value(__NR_add_key,
						     CMP_HINT_BOUNDARY,
						     0UL,
						     (unsigned long) ticket_length);

	/* On half the iterations we lie: payload size disagrees with
	 * advertised ticket_length, which trips the
	 * datalen != sizeof(*v1) + ticket_length check. */
	actual_ticket = ticket_length;
	if (rnd_modulo_u32(2) == 0)
		actual_ticket = (uint16_t)(rnd_modulo_u32(64) + 1);

	append_be32(buf, &off, kver);				/* kver */
	buf[off++] = (unsigned char)((sec_idx >> 8) & 0xff);	/* security_index hi */
	buf[off++] = (unsigned char)( sec_idx       & 0xff);
	buf[off++] = (unsigned char)((ticket_length >> 8) & 0xff);	/* ticket_length hi */
	buf[off++] = (unsigned char)( ticket_length       & 0xff);
	append_be32(buf, &off, (uint32_t) rand32());		/* expiry */
	append_be32(buf, &off, (uint32_t) rand32());		/* kvno */
	append_rand(buf, &off, 8);				/* session_key */

	if (off + actual_ticket > sizeof(buf))
		actual_ticket = (uint16_t)(sizeof(buf) - off);
	if (actual_ticket > 0)
		append_rand(buf, &off, actual_ticket);

	snprintf(desc, sizeof(desc), "trinity-rxrpc-v1-%u-%u",
		 (unsigned int) mypid(), iter);
	serial = do_add_rxrpc(desc, buf, off);
	if (serial != 0)
		ring_insert(ring, serial);
}

static void arm_xdr_envelope(int32_t *ring, unsigned int iter)
{
	unsigned char buf[512];
	size_t off = 0;
	size_t header_off;
	uint32_t flags, cell_len, ntoken;
	uint32_t toklen, sec_ix;
	bool inject_bad_byte;
	char desc[64];
	int32_t serial;

	/* flags must be 0 to walk past the early not_xdr; force it on
	 * three quarters of iterations and inject a junk value on the rest. */
	flags = (rnd_modulo_u32(4) == 0) ? (uint32_t) rand32() : 0;

	cell_len = 1 + rnd_modulo_u32(XDR_AFSTOKEN_CELL_MAX);
	ntoken = (rnd_modulo_u32(4) == 0)
			? (uint32_t)(rand32() & 0xff)
			: 1u + rnd_modulo_u32(XDR_AFSTOKEN_MAX);
	inject_bad_byte = (rnd_modulo_u32(8) == 0);

	build_xdr_head(buf, &off, flags, cell_len, ntoken, inject_bad_byte);

	/* One inner wrapper with a wholly-random sec_ix so we hit the
	 * default -> -EPROTONOSUPPORT branch in rxrpc_preparse_xdr() most
	 * of the time, and occasionally hit RXKAD/RXGK with a deliberately
	 * wrong toklen. */
	/* sec_ix is the XDR-envelope security-index equality gate
	 * (EXACT family; RXKAD==2 / RXGK==6 exemplars); toklen is a
	 * length check (BOUNDARY).  Shadow-resolve both -- returned
	 * value is discarded, rng draw commits verbatim. */
	sec_ix = (uint32_t) rand32();
	sec_ix = (uint32_t) childop_cmp_value(__NR_add_key, CMP_HINT_EXACT,
					       0UL, (unsigned long) sec_ix);
	toklen = 4 + rnd_modulo_u32(64);
	toklen = (uint32_t) childop_cmp_value(__NR_add_key, CMP_HINT_BOUNDARY,
					       0UL, (unsigned long) toklen);
	header_off = off;

	append_be32(buf, &off, toklen);
	append_be32(buf, &off, sec_ix);
	if (toklen > 4) {
		uint32_t pay = toklen - 4;
		uint32_t pad = (pay + 3) & ~3U;

		if (off + pad > sizeof(buf))
			pad = (uint32_t)(sizeof(buf) - off);
		append_rand(buf, &off, pad);
	}

	/* Make sure datalen > 28 so rxrpc_preparse_xdr() actually runs. */
	if (off <= 28) {
		size_t need = 32 - off;

		append_rand(buf, &off, need);
	}
	(void) header_off;

	snprintf(desc, sizeof(desc), "trinity-rxrpc-xdr-%u-%u",
		 (unsigned int) mypid(), iter);
	serial = do_add_rxrpc(desc, buf, off);
	if (serial != 0)
		ring_insert(ring, serial);
}

static void arm_xdr_rxkad(int32_t *ring, unsigned int iter)
{
	unsigned char buf[1024];
	size_t off = 0;
	size_t inner_start;
	uint32_t cell_len = 4;
	uint32_t tktlen;
	uint32_t toklen;
	char desc[64];
	int32_t serial;

	build_xdr_head(buf, &off, 0u, cell_len, 1u, false);

	/* tktlen mostly small (8..64), with occasional spike to drive the
	 * tktlen > AFSTOKEN_RK_TIX_MAX (12000) reject branch.  Shadow-
	 * resolve as BOUNDARY -- rng draw commits verbatim. */
	tktlen = (rnd_modulo_u32(8) == 0)
			? (uint32_t)(13000 + rnd_modulo_u32(1024))
			: (uint32_t)(8 + rnd_modulo_u32(56));
	tktlen = (uint32_t) childop_cmp_value(__NR_add_key, CMP_HINT_BOUNDARY,
					       0UL, (unsigned long) tktlen);

	/* One in four iterations advertises a toklen that disagrees with
	 * what we actually wrote, exercising the
	 * "toklen < 8*4 + tktlen" / total-length mismatch checks. */
	toklen = 8 * 4 + ((tktlen + 3) & ~3U);
	if (rnd_modulo_u32(4) == 0)
		toklen += rnd_modulo_u32(64);
	toklen = (uint32_t) childop_cmp_value(__NR_add_key, CMP_HINT_BOUNDARY,
					       0UL, (unsigned long) toklen);

	append_be32(buf, &off, toklen);
	append_be32(buf, &off, RXKAD_SEC_IDX);

	inner_start = off;
	if (tktlen > sizeof(buf) - inner_start - 8 * 4)
		tktlen = (uint32_t)(sizeof(buf) - inner_start - 8 * 4);
	build_xdr_rxkad_inner(buf, &off, tktlen);

	snprintf(desc, sizeof(desc), "trinity-rxrpc-xrxkad-%u-%u",
		 (unsigned int) mypid(), iter);
	serial = do_add_rxrpc(desc, buf, off);
	if (serial != 0)
		ring_insert(ring, serial);
}

/*
 * Pick an endtime (s64, 100ns units) for an XDR-RXGK token.  Four
 * sub-arms exercise the four reachable paths through the
 * key.c:232-237 expiry block:
 *
 *   (a) zero -- skip the whole block.  Kept on ~25% of iterations so
 *       the old behaviour (and the success path through
 *       memcpy+key-install) still gets exercised.
 *   (b) far future positive -- rxrpc_s64_to_time64 yields a non-
 *       negative time64_t; "expiry < prep->expiry" branch runs and
 *       prep->expiry is updated.  ~25%.
 *   (c) negative -- rxrpc_s64_to_time64 yields a negative time64_t
 *       (sign preserved through the do_div'd absolute value) so the
 *       "expiry < 0" check fires and we hit "goto expired".  Covers
 *       both small negatives and a wide random negative.  ~37%.
 *   (d) s64 extremes near INT64_MIN -- the function unconditionally
 *       does tmp = -time_in_100ns on the s64 negative branch; for
 *       INT64_MIN this is signed-overflow UB in C but the kernel
 *       builds with -fno-strict-overflow and the result is still a
 *       negative time64_t, so it still hits the expired branch.  This
 *       arm is the one most likely to trip a UBSAN sanitiser.  ~13%.
 *
 * Time scale: 100ns ticks.  10000000 ticks = 1 second.  ~2030 epoch
 * (1.9e9 sec) in 100ns is ~1.9e16 -- fits in s64 with plenty of room.
 */
static int64_t pick_xrxgk_endtime(void)
{
	switch (rnd_modulo_u32(8)) {
	case 0:
	case 1:
		return 0;
	case 2:
	case 3:
		/* Far-future positive: a sensible epoch plus jitter. */
		return (int64_t) 19000000000000000LL
			+ (int64_t) rnd_modulo_u32(1u << 24);
	case 4:
	case 5:
		/* Small negative -- minimal-magnitude expired.  Floor at
		 * 10^7 (== 1 second of 100ns ticks) so the kernel's
		 * rxrpc_s64_to_time64 do_div(/10000000) yields >= 1 and the
		 * returned time64_t is strictly negative; smaller magnitudes
		 * would truncate to 0 and bypass the expired branch. */
		return -(int64_t)(10000000u + rnd_modulo_u32(1u << 24));
	case 6: {
		/* Wide random negative across the s62 range.  Mask off the
		 * top two bits before casting so the magnitude lives in
		 * [0, 2^62 - 1] -- a u64 with bit 63 set would already be a
		 * negative int64_t after the cast and the unary minus would
		 * flip it back to positive (and -(INT64_MIN) is signed-
		 * overflow UB); the extra bit of headroom keeps the +10^7
		 * floor from overflowing int64_t.  Floor at 10^7 (== 1
		 * second of 100ns ticks) so do_div(/10000000) yields >= 1
		 * and the returned time64_t is strictly negative.  Result
		 * lives in [-(2^62 - 1 + 10^7), -10^7]. */
		uint64_t mag = (((uint64_t) rand32()) << 32)
			       | (uint64_t) rand32();
		mag &= ((uint64_t) 1 << 62) - 1;
		return -(int64_t)(10000000ULL + mag);
	}
	default:
		/* s64 extreme: INT64_MIN, INT64_MIN+1, or a near-min value. */
		switch (rnd_modulo_u32(3)) {
		case 0:
			return INT64_MIN;
		case 1:
			return INT64_MIN + 1;
		default:
			return -(int64_t)((uint64_t) 1 << 62)
				- (int64_t) rnd_modulo_u32(1u << 16);
		}
	}
}

static void arm_xdr_rxgk(int32_t *ring, unsigned int iter)
{
	unsigned char buf[1024];
	size_t off = 0;
	size_t inner_start;
	uint32_t cell_len = 4;
	uint32_t keylen, tktlen;
	uint32_t toklen;
	int64_t level, enctype, endtime;
	char desc[64];
	int32_t serial;

	build_xdr_head(buf, &off, 0u, cell_len, 1u, false);

	/* level normally walks the valid -1..2 range so we get past the
	 * level-bound check; occasionally goes wild to drive the
	 * tmp < -1 || tmp > RXRPC_SECURITY_ENCRYPT reject_token. */
	level = (rnd_modulo_u32(4) == 0)
			? (int64_t)(int32_t) rand32()
			: (int64_t) rnd_modulo_u32(4) - 1;
	switch (rnd_modulo_u32(8)) {
	case 0:
		enctype = (int64_t) -1 - (int64_t) rnd_modulo_u32(8);
		break;
	case 1: {
		/* Drive the `tmp > UINT_MAX` upper-reject edge in
		 * rxrpc_preparse_xdr_yfs_rxgk: emit a value in
		 * (UINT_MAX, INT64_MAX].  hi is in [1, 0x7FFFFFFF] so the
		 * top bit stays clear -- otherwise the s64 cast goes
		 * negative and we'd take the `tmp < 0` side instead. */
		uint64_t hi = 1u + rnd_modulo_u32(0x7FFFFFFFu);
		uint64_t lo = rnd_u32();
		enctype = (int64_t)((hi << 32) | lo);
		break;
	}
	default:
		enctype = (int64_t)(17 + rnd_modulo_u32(4));
		break;
	}
	/* enctype is an equality gate against the krb5 enctype table
	 * (17 == aes128-cts-hmac-sha1-96); shadow-resolve as EXACT.
	 * Return is discarded -- rng draw commits verbatim. */
	enctype = (int64_t) childop_cmp_value(__NR_add_key, CMP_HINT_EXACT,
					       0UL, (unsigned long) enctype);

	keylen = (rnd_modulo_u32(8) == 0)
			? (uint32_t)(70 + rnd_modulo_u32(64))
			: (uint32_t)(16 + rnd_modulo_u32(32));
	tktlen = (rnd_modulo_u32(16) == 0)
			? (uint32_t)(17000 + rnd_modulo_u32(256))
			: (uint32_t)(64 + rnd_modulo_u32(256));
	/* tktlen is the ticket length check; shadow-resolve as BOUNDARY. */
	tktlen = (uint32_t) childop_cmp_value(__NR_add_key, CMP_HINT_BOUNDARY,
					       0UL, (unsigned long) tktlen);

	endtime = pick_xrxgk_endtime();

	toklen = 4 + 6 * 8 + 4 + ((keylen + 3) & ~3U)
		 + 4 + ((tktlen + 3) & ~3U);
	/* toklen is the outer envelope length check; shadow-resolve
	 * as BOUNDARY so the counter partition matches the xrxkad arm. */
	toklen = (uint32_t) childop_cmp_value(__NR_add_key, CMP_HINT_BOUNDARY,
					       0UL, (unsigned long) toklen);

	append_be32(buf, &off, toklen);
	append_be32(buf, &off, RXGK_SEC_IDX);

	inner_start = off;
	if ((size_t)(6 * 8 + 8 + ((keylen + 3) & ~3U)
		     + ((tktlen + 3) & ~3U)) > sizeof(buf) - inner_start)
		tktlen = 16;
	build_xdr_rxgk_inner(buf, &off, keylen, tktlen, level, enctype, endtime);

	snprintf(desc, sizeof(desc), "trinity-rxrpc-xrxgk-%u-%u",
		 (unsigned int) mypid(), iter);
	serial = do_add_rxrpc(desc, buf, off);
	if (serial != 0) {
		/* Penetration marker: only bumped when the kernel returned a
		 * key serial, which means the XDR-RXGK token cleared every
		 * length check, level/enctype validation, the expiry check,
		 * and the kzalloc + memcpy(key) + memcpy(ticket) + key
		 * install.  Without this we can't tell whether the arm is
		 * just rattling the early length gates or actually fuzzing
		 * the deep parser. */
		__atomic_add_fetch(&shm->stats.rxrpc_key_install.xrxgk_accepted,
				   1, __ATOMIC_RELAXED);
		ring_insert(ring, serial);
	}
}

static void arm_server_key(int32_t *ring, unsigned int iter __unused__)
{
	unsigned char buf[64];
	char desc[96];
	int32_t serial;

	if (rnd_modulo_u32(2) == 0) {
		/* RXKAD server key.  description "<svc>:2", payload exactly
		 * 8 B per rxkad_preparse_server_key.  Service id is u16. */
		unsigned int svc = rnd_modulo_u32(65536);

		generate_rand_bytes(buf, 8);
		snprintf(desc, sizeof(desc), "%u:%u", svc, RXKAD_SEC_IDX);
		serial = do_add_rxrpc_s(desc, buf, 8);
	} else {
		/* RXGK server key.  description "<svc>:6:<kvno>:<enctype>",
		 * payload length must equal krb5->key_len for the named
		 * enctype.  17 = aes128-cts-hmac-sha1-96, key_len=16. */
		unsigned int svc = rnd_modulo_u32(65536);
		unsigned int kvno = (unsigned int)(rand32() & 0xffff);
		size_t paylen = 16;

		generate_rand_bytes(buf, (unsigned int) paylen);
		snprintf(desc, sizeof(desc), "%u:%u:%u:%u",
			 svc, RXGK_SEC_IDX, kvno, 17u);
		serial = do_add_rxrpc_s(desc, buf, paylen);

		/* One in eight server-key iterations also tries an
		 * intentionally bad description to drive the
		 * sscanf-mismatch / sec_class out-of-range branches in
		 * rxrpc_vet_description_s().  Ignore the result. */
		if (rnd_modulo_u32(8) == 0) {
			snprintf(desc, sizeof(desc), "%u:%u:%u",
				 svc, 0xffu, kvno);
			(void) do_add_rxrpc_s(desc, buf, 8);
		}
	}
	if (serial != 0)
		ring_insert(ring, serial);
}

/* Tear-down arm: pick a recently-added serial and revoke or unlink it.
 * This drives the rxrpc_destroy() / rxrpc_destroy_s() paths and the
 * security-specific token-list teardown (rxgk_free_server_key,
 * crypto_free_skcipher on rxkad's pcbc(des) instance). */
static void teardown_one(int32_t *ring)
{
	int32_t serial = ring_pick(ring);
	long rc;

	if (serial == 0)
		return;

	if (RAND_BOOL()) {
		rc = trinity_cmp_syscall(__NR_keyctl, (unsigned long) KEYCTL_REVOKE,
			     (unsigned long) serial, 0UL, 0UL, 0UL);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.rxrpc_key_install.revokes,
					   1, __ATOMIC_RELAXED);
		/* Revoked keys still occupy the serial; let it age out
		 * naturally so subsequent picks land on a -EKEYREVOKED
		 * read path too. */
	} else {
		rc = trinity_cmp_syscall(__NR_keyctl, (unsigned long) KEYCTL_UNLINK,
			     (unsigned long) serial,
			     (unsigned long) KEY_SPEC_THREAD_KEYRING,
			     0UL, 0UL);
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.rxrpc_key_install.revokes,
					   1, __ATOMIC_RELAXED);
			ring_drop(ring, serial);
		}
	}
}

bool rxrpc_key_install(struct childdata *child)
{
	int32_t live[LIVE_KEYS_RING];
	struct timespec start;
	unsigned int iter;
	unsigned int iters;

	__atomic_add_fetch(&shm->stats.rxrpc_key_install.runs,
			   1, __ATOMIC_RELAXED);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip every per-op
	 * stats write when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	probe_rxrpc_key_supported();
	if (unsupported_rxrpc_key_install) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	memset(live, 0, sizeof(live));
	clock_gettime(CLOCK_MONOTONIC, &start);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	iters = JITTER_RANGE(MAX_ITERATIONS);
	for (iter = 0; iter < iters; iter++) {
		enum rxrpc_key_arm arm =
			(enum rxrpc_key_arm) rnd_modulo_u32(ARM_NR);

		switch (arm) {
		case ARM_NULL:
			arm_null(live, iter);
			break;
		case ARM_SHORT_RANDOM:
			arm_short_random(live, iter);
			break;
		case ARM_V1_BINARY:
			arm_v1_binary(live, iter);
			break;
		case ARM_XDR_ENVELOPE:
			arm_xdr_envelope(live, iter);
			break;
		case ARM_XDR_RXKAD:
			arm_xdr_rxkad(live, iter);
			break;
		case ARM_XDR_RXGK:
			arm_xdr_rxgk(live, iter);
			break;
		case ARM_SERVER_KEY:
			arm_server_key(live, iter);
			break;
		case ARM_NR:
			break;
		}

		/* Every few iterations, force a teardown to keep the
		 * destroy paths exercised even when EDQUOT capped the
		 * recent add_keys to zero new serials. */
		if ((iter & 3) == 3)
			teardown_one(live);

		if (unsupported_rxrpc_key_install) {
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			return true;
		}
		if (budget_elapsed_ns(&start, BUDGET_NS))
			break;
	}

	return true;
}
