/*
 * af_alg_weak_cipher_probe -- enumerate which crypto template names
 * AF_ALG accepts via bind(AF_ALG, sockaddr_alg{salg_type, salg_name})
 * and surface the deprecated/weak templates the kernel still accepts.
 *
 * Two-axis fuzz value:
 *   (a) Hardening-gap detector -- any deprecated or structurally weak
 *       template that bind() accepts without refusal is a hardening
 *       opportunity (rotate it onto the "should refuse" list, or
 *       shrink the kernel build's enabled-cipher set).
 *   (b) Bug-class amplifier audit -- small-block / weak-key ciphers
 *       amplify in-place crypto bugs because they make brute-force
 *       STORE shaping cheap.  Enumerating which weak ciphers are
 *       reachable from userspace bounds the amplification surface.
 *
 * Per iteration walk:
 *   1. Pick a (salg_type, salg_name) entry from the rotation table.
 *   2. socket(AF_ALG, SOCK_SEQPACKET, 0).
 *   3. bind() to the (type, name) pair, capture errno.
 *   4. If bind succeeded:
 *        - bump per-entry _accepted counter
 *        - bump weak-bucket counter if entry is in the weak set
 *        - for skcipher/aead, try setsockopt(SOL_ALG, ALG_SET_KEY)
 *          with a small random key; bump _setkey_accepted on success
 *   5. If bind failed: bump per-entry rejected counter for that errno
 *   6. Close socket.
 *   7. Latch entry after LATCH_THRESHOLD consecutive identical
 *      outcomes; latched entries are skipped on subsequent picks.
 *
 * Top-level latch: socket(AF_ALG) returning EAFNOSUPPORT latches the
 * whole op as no-op for the rest of the run.  Mirrors the uniform
 * unsupported_<name> latch pattern from fds/{kvm,landlock,
 * memfd_secret,mq}.c and the per-target rotation in
 * inplace_crypto_oracle.c.
 *
 * Per-op alarm contract: parent arms alarm(1) per invocation; this op
 * does only bind/setkey/close per template -- no recv, no splice, no
 * wait paths.  The whole sweep is bounded by the rotation cursor (one
 * template per call, advanced).
 *
 * DORMANT in dormant_op_disabled[].  Smoke-test before fleet enable.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#if __has_include(<linux/if_alg.h>)
# include <linux/if_alg.h>
#endif

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/socket.h"
#define WEAK_CIPHER_LATCH_THRESHOLD	3U
#define WEAK_CIPHER_PROBE_KEY_BYTES	16U
#define WEAK_CIPHER_EBUSY_RETRY_USEC	1000

enum probe_class {
	PROBE_WEAK = 0,
	PROBE_STRONG,
};

enum probe_kind {
	KIND_SKCIPHER = 0,
	KIND_AEAD,
	KIND_HASH,
	KIND_COMPRESSION,
};

struct probe_entry {
	const char *salg_type;
	const char *salg_name;
	enum probe_class klass;
	enum probe_kind kind;

	/* Per-entry latch state (process-local; this op runs from a
	 * single child slot in the dedicated-altop or random-altop path
	 * and its file-scope state is private to the running child). */
	bool latched;
	unsigned int consecutive_count;
	int last_outcome;	/* 0 = accepted-with-setkey, >0 = errno from
				   bind, -1 = accepted-without-setkey-attempt,
				   INT_MIN initially */
	unsigned long accepted;
	unsigned long setkey_accepted;
	unsigned long rejected;
};

#define OUTCOME_INIT			(-2)
#define OUTCOME_ACCEPTED_NO_SETKEY	(-1)
#define OUTCOME_ACCEPTED_SETKEY		(0)

static struct probe_entry probe_table[] = {
	/* skcipher -- weak / deprecated */
	{ "skcipher", "pcbc(fcrypt)",        PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "cbc(des)",            PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "ecb(des)",            PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "pcbc(des)",           PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "cbc(des3_ede)",       PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "ecb(des3_ede)",       PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "cbc(blowfish)",       PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "ecb(blowfish)",       PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "cbc(cast5)",          PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "arc4",                PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "cbc(serpent)",        PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "cbc(twofish)",        PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "tnepres",             PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "khazad",              PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "seed",                PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "ecb(aes)",            PROBE_WEAK,   KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },

	/* aead -- weak / deprecated */
	{ "aead",     "authenc(hmac(md5),cbc(aes))",  PROBE_WEAK, KIND_AEAD, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "aead",     "authenc(hmac(sha1),cbc(des))", PROBE_WEAK, KIND_AEAD, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "aead",     "rfc4309(ccm(aes))",            PROBE_WEAK, KIND_AEAD, false, 0, OUTCOME_INIT, 0, 0, 0 },

	/* hash -- broken / probe-availability */
	{ "hash",     "md4",                 PROBE_WEAK,   KIND_HASH,        false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "hash",     "md5",                 PROBE_WEAK,   KIND_HASH,        false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "hash",     "crc32",               PROBE_WEAK,   KIND_HASH,        false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "hash",     "crc32c",              PROBE_WEAK,   KIND_HASH,        false, 0, OUTCOME_INIT, 0, 0, 0 },

	/* compression -- presence probe only, not really a security axis */
	{ "compression", "deflate",          PROBE_WEAK,   KIND_COMPRESSION, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "compression", "lz4",              PROBE_WEAK,   KIND_COMPRESSION, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "compression", "lzo",              PROBE_WEAK,   KIND_COMPRESSION, false, 0, OUTCOME_INIT, 0, 0, 0 },

	/* strong control set -- should always accept on a normal kernel.
	 * Any reject here surfaces a structurally-broken build. */
	{ "skcipher", "cbc(aes)",            PROBE_STRONG, KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "aead",     "gcm(aes)",            PROBE_STRONG, KIND_AEAD,     false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "hash",     "hmac(sha256)",        PROBE_STRONG, KIND_HASH,     false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "hash",     "sha256",              PROBE_STRONG, KIND_HASH,     false, 0, OUTCOME_INIT, 0, 0, 0 },
	{ "skcipher", "chacha20",            PROBE_STRONG, KIND_SKCIPHER, false, 0, OUTCOME_INIT, 0, 0, 0 },
};

#define PROBE_TABLE_LEN			ARRAY_SIZE(probe_table)

static bool unsupported_af_alg_top_level;
static unsigned int rotation_cursor;

static void update_outcome_latch(struct probe_entry *e, int outcome)
{
	if (e->last_outcome == outcome) {
		if (e->consecutive_count < WEAK_CIPHER_LATCH_THRESHOLD)
			e->consecutive_count++;
		if (e->consecutive_count >= WEAK_CIPHER_LATCH_THRESHOLD)
			e->latched = true;
	} else {
		e->last_outcome = outcome;
		e->consecutive_count = 1;
	}
}

static void bump_weak_bucket(enum probe_kind kind)
{
	switch (kind) {
	case KIND_SKCIPHER:
		__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.skcipher_weak_accepted,
				   1, __ATOMIC_RELAXED);
		break;
	case KIND_AEAD:
		__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.aead_weak_accepted,
				   1, __ATOMIC_RELAXED);
		break;
	case KIND_HASH:
		__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.hash_weak_accepted,
				   1, __ATOMIC_RELAXED);
		break;
	case KIND_COMPRESSION:
		break;
	}
}

/*
 * Drive one (type, name) entry through socket -> bind -> [setkey] ->
 * close.  Returns true if the top-level AF_ALG family probe latched
 * (caller should mark unsupported_af_alg_top_level and bail).  child
 * is threaded in so the per-childop yield counters
 * (childop_setup_accepted / childop_data_path / childop_latch_reason)
 * can be attributed to child->op_type; setup is "AF_ALG socket open",
 * data_path is "about to issue the bind() probe".
 */
static bool probe_one_entry(struct probe_entry *e, struct childdata *child)
{
	struct sockaddr_alg sa;
	unsigned char key[WEAK_CIPHER_PROBE_KEY_BYTES];
	int fd, bind_rc, set_rc, bind_errno;
	int outcome;
	bool retried = false;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.socket_failed,
				   1, __ATOMIC_RELAXED);
		if (errno == EAFNOSUPPORT) {
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			outputerr("af_alg_weak_cipher_probe: socket(AF_ALG) returned EAFNOSUPPORT, latching unsupported_af_alg_top_level\n");
			return true;
		}
		return false;
	}
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strncpy((char *)sa.salg_type, e->salg_type, sizeof(sa.salg_type) - 1);
	strncpy((char *)sa.salg_name, e->salg_name, sizeof(sa.salg_name) - 1);

	__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.total_bind_attempts,
			   1, __ATOMIC_RELAXED);
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

retry:
	bind_rc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	bind_errno = errno;
	if (bind_rc < 0 && bind_errno == EBUSY && !retried) {
		struct timespec ts = { 0, WEAK_CIPHER_EBUSY_RETRY_USEC * 1000L };

		retried = true;
		(void)nanosleep(&ts, NULL);
		goto retry;
	}

	if (bind_rc == 0) {
		__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.total_bind_accepted,
				   1, __ATOMIC_RELAXED);
		e->accepted++;

		if (e->klass == PROBE_WEAK) {
			__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.weak_accepted_total,
					   1, __ATOMIC_RELAXED);
			bump_weak_bucket(e->kind);
		}

		outcome = OUTCOME_ACCEPTED_NO_SETKEY;
		if (e->kind == KIND_SKCIPHER || e->kind == KIND_AEAD) {
			generate_rand_bytes(key, sizeof(key));
			set_rc = setsockopt(fd, SOL_ALG, ALG_SET_KEY,
					    key, sizeof(key));
			if (set_rc == 0) {
				e->setkey_accepted++;
				__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.setkey_accepted_total,
						   1, __ATOMIC_RELAXED);
				outcome = OUTCOME_ACCEPTED_SETKEY;
			}
			/* setkey EOPNOTSUPP / EINVAL is benign at this key
			 * size; do not latch on it. */
		}
	} else {
		e->rejected++;
		outcome = bind_errno;	/* >0 */

		if (e->klass == PROBE_STRONG)
			__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.strong_rejected,
					   1, __ATOMIC_RELAXED);
	}

	update_outcome_latch(e, outcome);
	close(fd);
	return false;
}

bool af_alg_weak_cipher_probe(struct childdata *child)
{
	unsigned int i;

	__atomic_add_fetch(&shm->stats.af_alg_weak_cipher_probe.runs,
			   1, __ATOMIC_RELAXED);

	if (unsupported_af_alg_top_level)
		return true;

	for (i = 0; i < PROBE_TABLE_LEN; i++) {
		unsigned int idx = (rotation_cursor + i) % PROBE_TABLE_LEN;
		struct probe_entry *e = &probe_table[idx];

		if (e->latched)
			continue;

		rotation_cursor = (idx + 1) % PROBE_TABLE_LEN;
		if (probe_one_entry(e, child))
			unsupported_af_alg_top_level = true;
		return true;
	}

	/* All entries latched -- nothing left to learn from this op. */
	unsupported_af_alg_top_level = true;
	/* child->op_type lives in shared memory and can be scribbled by a
	 * poisoned-arena write from a sibling; bounds-check the snapshot
	 * before indexing the NR_CHILD_OP_TYPES-sized stats arrays, same
	 * pattern the child.c dispatch loop uses for the unguarded write
	 * that motivated this guard. */
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_OTHER, __ATOMIC_RELAXED);
	}
	return true;
}
