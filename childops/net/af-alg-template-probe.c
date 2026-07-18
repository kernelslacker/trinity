/*
 * af_alg_template_probe - one-shot enumeration of which AF_ALG crypto
 * template names this kernel will accept via bind(AF_ALG, ...).
 *
 * Intent is observational, not exploratory: walk a fixed list of legacy
 * and weak templates (single-DES, 3DES, ARC4, MD4/MD5, the AFS
 * pcbc(fcrypt) curiosity, plus a few niche skciphers) and record one
 * accept/reject result per template into shm so an operator can grep
 * stats.dump after a run to learn which weak primitives the kernel
 * exposed on this build.
 *
 * Why bother: weak/legacy templates amplify any in-place-crypto
 * STORE-on-frag bug.  Small block sizes (DES = 8 bytes, fcrypt = 8
 * bytes) and tiny key spaces (DES = 56 bits, fcrypt = 56 bits) turn
 * STORE-shaping primitives that would be expensive on AES-256 into
 * brute-force-feasible exercises.  Knowing which of these the fleet's
 * kernels actually accept tells us which crypto data-path bugs are
 * within reach of a follow-on AF_ALG sendmsg/splice fuzzer without
 * having to guess from .config flags.
 *
 * Pure read-only probe: socket(AF_ALG, SOCK_SEQPACKET, 0), bind() with
 * the candidate sockaddr_alg, record errno-or-success, close().  No
 * setsockopt(ALG_SET_KEY), no accept(), no sendmsg() — those belong in
 * a dedicated data-path childop, not here.
 *
 * Front-door check: if socket(AF_ALG, ...) returns EAFNOSUPPORT the
 * kernel doesn't have CRYPTO_USER_API at all; the latch is flipped, an
 * unsupported counter is bumped, and the probe exits without spamming
 * 12 useless per-template attempts.
 *
 * One-shot semantics: a CAS on shm->stats.af_alg_probe_done elects a
 * single child to run the probe across the whole fleet.  Subsequent
 * calls (from the same child or any sibling) early-return.  A
 * per-process bool short-circuits the shm load on the hot path.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#include <string.h>
#endif

#include "child.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
struct af_alg_probe_entry {
	const char	*type;	/* salg_type, e.g. "skcipher", "hash" */
	const char	*name;	/* salg_name, e.g. "cbc(des)" */
	const char	*label;	/* sanitised operator-grade tag for stat_row */
};

/* Index here matches shm->stats.af_alg_probe_{accept,reject}[] slots.
 * NR_AF_ALG_PROBE_TEMPLATES in stats.h must equal ARRAY_SIZE(probe_table)
 * — checked by _Static_assert below.  Order is stable; appending a new
 * entry only adds slots to the tail. */
static const struct af_alg_probe_entry probe_table[] = {
	/* Single-DES family: 56-bit key, 8-byte block.  Brute-forceable
	 * in well under a day on commodity GPUs; if this kernel still
	 * accepts cbc(des) we can shape STOREs through an 8-byte block
	 * cipher and recover the plaintext. */
	{ "skcipher",	"cbc(des)",		"skcipher_cbc_des" },
	{ "skcipher",	"ecb(des)",		"skcipher_ecb_des" },
	{ "skcipher",	"pcbc(des)",		"skcipher_pcbc_des" },

	/* 3DES: still 8-byte block, 112-bit effective key.  Slow but
	 * routinely accepted in legacy-friendly kernels. */
	{ "skcipher",	"cbc(des3_ede)",	"skcipher_cbc_des3_ede" },

	/* ARC4: stream cipher, no block alignment, broken since the
	 * mid-2000s.  Used to be the bind-and-forget default for legacy
	 * ALG_RC4 callers. */
	{ "skcipher",	"arc4",			"skcipher_arc4" },

	/* AFS pcbc(fcrypt): 56-bit key, 8-byte block, ~18M ops/sec
	 * brute-force in user space.  AFS is the only consumer; if the
	 * kernel still binds it, the data-path is reachable for shaping. */
	{ "aead",	"pcbc(fcrypt)",		"aead_pcbc_fcrypt" },

	/* MD4 / MD5: collision-broken hashes.  Cheap to enumerate and a
	 * good signal for "this kernel still ships every legacy
	 * primitive the crypto API ever knew about". */
	{ "hash",	"md4",			"hash_md4" },
	{ "hash",	"md5",			"hash_md5" },

	/* Niche skciphers — in-tree but rarely enabled.  Probe them so
	 * we notice if a kernel build flips them on by accident. */
	{ "skcipher",	"tnepres",		"skcipher_tnepres" },
	{ "skcipher",	"khazad",		"skcipher_khazad" },
	{ "skcipher",	"seed",			"skcipher_seed" },

	/* Compression sanity check — confirms the AF_ALG type-plumbing
	 * works for non-cipher salg_type strings.  algif_compress is
	 * usually built into stock kernels; if this rejects, the type
	 * dispatcher itself is locked down. */
	{ "compression","deflate",		"compression_deflate" },
};

_Static_assert(ARRAY_SIZE(probe_table) == NR_AF_ALG_PROBE_TEMPLATES,
	"probe_table size must match NR_AF_ALG_PROBE_TEMPLATES");

/* Per-process short-circuit: avoid the shm load on every non-first
 * invocation in this child.  The shm CAS still gates the actual probe
 * across the fleet — this is purely a hot-path optimisation. */
static bool af_alg_probe_local_done;

#ifdef USE_IF_ALG
static void run_one_template(unsigned int idx)
{
	const struct af_alg_probe_entry *e = &probe_table[idx];
	struct sockaddr_alg sa;
	int sk;

	sk = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		/* Front-door already checked by caller — getting here means
		 * a transient socket() failure (ENFILE/EMFILE).  Count as
		 * reject so the operator sees something happened. */
		__atomic_add_fetch(&shm->stats.af_alg_probe_reject[idx],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.af_alg_probe_reject_total,
				   1, __ATOMIC_RELAXED);
		return;
	}

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strncpy((char *)sa.salg_type, e->type, sizeof(sa.salg_type) - 1);
	strncpy((char *)sa.salg_name, e->name, sizeof(sa.salg_name) - 1);

	if (bind(sk, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
		__atomic_add_fetch(&shm->stats.af_alg_probe_accept[idx],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.af_alg_probe_accept_total,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.af_alg_probe_reject[idx],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.af_alg_probe_reject_total,
				   1, __ATOMIC_RELAXED);
	}

	close(sk);
}
#endif /* USE_IF_ALG */

bool af_alg_template_probe(struct childdata *child)
{
	unsigned int expected = 0;
	unsigned int i;
#ifdef USE_IF_ALG
	int sk;
#endif
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (af_alg_probe_local_done)
		return true;

	/* Single-shot election across the fleet: only one child runs the
	 * probe; the rest see done==1 and early-return.  CAS on the shm
	 * latch with weak semantics — losers fall through to set the
	 * local short-circuit so they don't re-race next time.  The CAS
	 * itself is fleet self-election, not a kernel-feature latch, so
	 * the CAS loser doesn't store a childop_latch_reason. */
	if (!__atomic_compare_exchange_n(&shm->stats.af_alg_probe_done,
					 &expected, 1U, false,
					 __ATOMIC_ACQ_REL,
					 __ATOMIC_ACQUIRE)) {
		af_alg_probe_local_done = true;
		return true;
	}

	__atomic_add_fetch(&shm->stats.af_alg_probe_runs, 1, __ATOMIC_RELAXED);

#ifdef USE_IF_ALG
	/* Front-door check: open one AF_ALG socket up front.  If the
	 * kernel doesn't have CRYPTO_USER_API the family is unregistered
	 * and we'll see EAFNOSUPPORT immediately — bail without
	 * generating 12 identical per-template rejections. */
	sk = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		__atomic_add_fetch(&shm->stats.af_alg_probe_unsupported,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		outputerr("[af_alg_probe] AF_ALG unavailable (errno=%d), "
		          "skipping template enumeration\n", errno);
		af_alg_probe_local_done = true;
		return true;
	}
	close(sk);
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	for (i = 0; i < NR_AF_ALG_PROBE_TEMPLATES; i++)
		run_one_template(i);
#else
	(void)i;
	__atomic_add_fetch(&shm->stats.af_alg_probe_unsupported,
			   1, __ATOMIC_RELAXED);
	if (valid_op)
		__atomic_store_n(&shm->stats.childop.latch_reason[op],
				 CHILDOP_LATCH_UNSUPPORTED, __ATOMIC_RELAXED);
	outputerr("[af_alg_probe] built without linux/if_alg.h, "
	          "template enumeration disabled\n");
#endif

	af_alg_probe_local_done = true;
	return true;
}

const char *af_alg_probe_template_label(unsigned int idx)
{
	if (idx >= NR_AF_ALG_PROBE_TEMPLATES)
		return "unknown";
	return probe_table[idx].label;
}
