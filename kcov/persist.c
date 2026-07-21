/*
 * KCOV bitmap warm-start persistence, kernel fingerprinting, and the
 * cold parent-side scaffolding around them (streaming SHA-256, snapshot
 * cadence, bucket_seen canary).  Carved out of kcov.c to keep the
 * bitmap file format and its cross-run bookkeeping in one place; the
 * hot per-syscall collection path lives elsewhere in the kcov/
 * subdirectory.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "exit.h"		/* EXIT_SHM_CORRUPTION, STILL_RUNNING */
#include "fd.h"			/* read_all, write_all */
#include "kcov-internal.h"	/* kcov_kaslr_base, public kcov API */
#include "persist-util.h"	/* persist_sweep_stale_tmp */
#include "pids.h"		/* mypid */
#include "shm.h"		/* shm */
#include "stats.h"		/* stats_log_write */
#include "strategy.h"		/* NR_STRATEGIES */
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "trinity.h"		/* output */
#include "utils.h"		/* crc32 */

/*
 * Warm-start persistence for kcov_shm->bucket_seen[] + edges_found.
 *
 * Layout: a fixed header followed by KCOV_NUM_EDGES bytes of bucket_seen
 * payload.  Atomic .tmp + rename on save mirrors minicorpus.  No
 * __attribute__((packed)) -- the field sequence below is already
 * naturally aligned on the LP64 ABIs trinity targets.
 *
 * Fingerprint: sha256 over /proc/kallsyms with the leading address column
 * stripped from each line.  Two reasons we don't use utsname.release +
 * utsname.version like the other persisted artifacts:
 *
 *   1. The kernel can be rebuilt without bumping either utsname string
 *      (same source tree, same .config, different timestamp); a utsname
 *      fingerprint accepts a stale bitmap whose edges were measured
 *      against a binary with a different inlining / linker layout.
 *
 *   2. /proc/kallsyms shows zeroed addresses to non-root readers
 *      (kptr_restrict), so the file's raw bytes aren't a stable
 *      fingerprint between root and non-root runs of the same trinity
 *      against the same kernel.  Stripping the first whitespace-
 *      delimited token (the address, real or zero) leaves only the
 *      "<type> <name>[ [module]]" stream, which is identical for both
 *      readers and invariant across KASLR vs nokaslr boots of the same
 *      build.
 */
#define KCOV_BITMAP_FILE_MAGIC		0x4B434256U	/* "KCBV" */
/* Version 2 adds distinct_edges to the header.  Files written by
 * version 1 are rejected on load: distinct_edges cannot be reliably
 * reconstructed from bucket_seen[] (a non-zero byte could be the
 * result of a single first-bit transition or of multiple bucket
 * transitions on the same edge across prior sessions), so a
 * legacy-format file is treated as "no warm start available" and
 * the run begins cold.
 *
 * Version 3 appends per-syscall priors (per_syscall_edges and
 * per_syscall_calls of the writing session) after the bucket_seen
 * payload, with a separate priors_crc32 over the concatenated
 * arrays.  Version 2 files reject cleanly on the existing
 * version-mismatch path and the run begins cold; that is fine --
 * the priors are a soft signal and a single cold restart on the
 * format bump costs nothing the bitmap warm-start was already
 * providing.
 *
 * Version 4 added a boot_id guard from /proc/sys/kernel/random/boot_id
 * to reject cross-boot reloads.  Rationale at the time: the kallsyms
 * fingerprint is deliberately KASLR-invariant (right for identity --
 * same kernel image -> same fingerprint regardless of KASLR or
 * kptr_restrict) but bucket_seen[] was hashed from raw runtime PCs,
 * so a KASLR reroll across a reboot left the fingerprint matching yet
 * silently aliased every cached bucket to a different instruction.
 * boot_id papered over that without canonicalising PCs, at the cost
 * of forcing one cold start per reboot even when the kernel hadn't
 * changed.
 *
 * Version 5 fixes that properly: PCs are stripped of the runtime
 * KASLR base (see kcov_canon_pc / kcov_get_kaslr_base) before they
 * hit the bucket_seen[] hash, so the bucket index for an instruction
 * stays put across reboots of the same build.  The boot_id field and
 * its associated machinery are gone; in its place the header carries
 * kaslr_base purely as a load-time consistency gate -- if the file
 * was written with PCs canonicalised but this run can't canonicalise
 * (kallsyms unreadable, _text absent), or vice versa, the bucket
 * indices would silently disagree and the load is refused.  Files
 * written under v4 reject cleanly on the version mismatch, costing
 * one cold start at the format bump.
 *
 * Version 6 appends a per-syscall diag block after the v3 priors
 * blob: per_syscall_diag[MAX_NR_SYSCALL][2] serialised as packed
 * 16-byte records {u64 bucket_bits_real; u64 distinct_pcs;} with
 * the syscall slot as the outer index and the do32 arch dimension
 * as the inner index.  The previously-unused header pad slot is
 * repurposed as diag_crc32 over that block; in v5 files the same
 * slot is always written as zero by the save path and ignored by
 * the load path, so the on-disk header size is unchanged at 88 B
 * and v5 files load on a v6 binary as before -- they just lack
 * the appended diag block.  The block records true per-syscall
 * edge totals (the bucket_bits_real / distinct_pcs counters the
 * hot path already maintains) so offline tooling can rank
 * syscalls by actual edges discovered rather than only by the
 * v3 productive-call counts.
 *
 * Version 7 appends a per-strategy edge-counter block after the v6
 * diag block: pc_edge_calls_by_strategy[NR_STRATEGIES] followed by
 * pc_edge_count_by_strategy[NR_STRATEGIES], each as plain u64
 * little-endian, naturally aligned.  With NR_STRATEGIES == 3 today
 * (HEURISTIC, RANDOM, COVERAGE_FRONTIER -- see include/strategy.h)
 * the block is 6 x 8 = 48 bytes total.  Two new u32s are appended
 * to the header: strat_crc32 (CRC over the strat block) and a
 * reserved pad slot, growing the on-disk header from 88 B to 96 B.
 * v5/v6 files have only 88 B of header on disk; the load path
 * reads the v6-sized header prefix first, validates the version,
 * and reads the extra 8 B of trailer only when hdr.version >= 7,
 * so v5/v6 files continue to warm-load unchanged on a v7 binary.
 * The block records which selection strategy is producing fresh
 * edges across runs, so offline tooling can spot when (for
 * example) STRATEGY_COVERAGE_FRONTIER stops contributing new
 * edges as the bitmap saturates. */
#define KCOV_BITMAP_FILE_VERSION	7U
/* Oldest file-format version this binary will warm-load.  v4 stays
 * rejected (different header size, different PC basis); v5 loads
 * without the v6 diag block or v7 strat block; v6 loads with diag
 * but without strat; v7 loads all three. */
#define KCOV_BITMAP_FILE_MIN_LOAD_VERSION	5U

struct kcov_bitmap_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t num_edges;
	uint32_t num_buckets;
	uint64_t edges_found;
	uint64_t distinct_edges;
	uint32_t payload_crc32;
	uint32_t diag_crc32;       /* v6: CRC over the appended diag
				    * block.  v5: always zero (pad). */
	uint8_t  kallsyms_sha256[32];
	uint32_t max_nr_syscall;   /* MAX_NR_SYSCALL at save time */
	uint32_t priors_crc32;     /* CRC over both prior arrays */
	uint64_t kaslr_base;       /* Runtime _text base at save time.
				    * Zero means the writer could not
				    * resolve the base and the payload
				    * is hashed from raw PCs.  The load
				    * path rejects when (hdr.kaslr_base
				    * != 0) XOR (current kcov_kaslr_base
				    * != 0) -- a canonical-vs-raw mix
				    * would silently corrupt bucket
				    * lookups. */
	uint32_t strat_crc32;      /* v7: CRC over the appended strat
				    * block.  v5/v6 files lack this
				    * trailer; the loader leaves it
				    * implicit-zero in those cases. */
	uint32_t pad2;             /* v7: reserved for future use,
				    * always written as zero.  Kept so
				    * the on-disk header is u64-aligned
				    * (96 B) and a future block can
				    * repurpose this slot the way
				    * diag_crc32 / strat_crc32 did. */
};

/* On-disk size of the header as written by v5 and v6 binaries (no
 * trailing strat_crc32 / pad2).  The v7 load path reads this prefix
 * first, validates magic+version, then conditionally reads the
 * trailing 8 B only when the file is v7+. */
#define KCOV_BITMAP_HDR_V6_SIZE	88U

_Static_assert(offsetof(struct kcov_bitmap_file_header, strat_crc32) ==
		       KCOV_BITMAP_HDR_V6_SIZE,
	       "v7 trailer must begin exactly at the end of the v6 header");
_Static_assert(sizeof(struct kcov_bitmap_file_header) == 96,
	       "v7 on-disk header is 96 B (v6 prefix + strat_crc32 + pad2)");
/* NR_STRATEGIES is baked into the v7 strat block layout (6 x u64 = 48 B).
 * Bumping it requires a new on-disk format version. */
_Static_assert(NR_STRATEGIES == 3,
	       "v7 strat block layout assumes exactly 3 strategies");

/* On-disk record for a single per_syscall_diag[nr][dim] slot.
 * Packed pair of u64s, naturally aligned, little-endian.  16 B per
 * slot; MAX_NR_SYSCALL * 2 slots = 32 KiB.  Layout is the contract
 * for the external cache-stats reader, so do not reorder. */
struct kcov_per_syscall_diag_ondisk {
	uint64_t bucket_bits_real;
	uint64_t distinct_pcs;
};

/* On-disk strat block (v7), appended after the v6 diag block.  Six
 * contiguous u64s, naturally aligned, little-endian; total 48 B.
 * Field order (do NOT reorder -- the external cache-stats reader
 * matches this byte-for-byte):
 *
 *   bytes  0..7  : pc_edge_calls_by_strategy[0]   (STRATEGY_HEURISTIC)
 *   bytes  8..15 : pc_edge_calls_by_strategy[1]   (STRATEGY_RANDOM)
 *   bytes 16..23 : pc_edge_calls_by_strategy[2]   (STRATEGY_COVERAGE_FRONTIER)
 *   bytes 24..31 : pc_edge_count_by_strategy[0]   (STRATEGY_HEURISTIC)
 *   bytes 32..39 : pc_edge_count_by_strategy[1]   (STRATEGY_RANDOM)
 *   bytes 40..47 : pc_edge_count_by_strategy[2]   (STRATEGY_COVERAGE_FRONTIER)
 *
 * Both arrays carry the strategy_t value as the index.  The block is
 * covered by hdr.strat_crc32 at header offset 88. */
struct kcov_strat_ondisk {
	uint64_t calls[NR_STRATEGIES];
	uint64_t count[NR_STRATEGIES];
};

_Static_assert(sizeof(struct kcov_strat_ondisk) == 48,
	       "v7 strat block is 48 B (6 x u64)");

/*
 * Streaming SHA-256 implementation.  Trinity links no crypto library, so
 * we ship the algorithm here -- compact enough that the fingerprint code
 * doesn't pull in libcrypto for a single user.  Public-domain reference
 * implementation, FIPS 180-4 conformant; produces an identical digest to
 * `openssl dgst -sha256` for any byte stream.
 */
struct sha256_ctx {
	uint32_t state[8];
	uint64_t bitlen;
	uint8_t  buf[64];
	uint32_t buflen;
};

static const uint32_t sha256_k[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
	0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
	0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
	0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t sha256_rotr(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32U - n));
}

static void sha256_block(struct sha256_ctx *c, const uint8_t blk[64])
{
	uint32_t w[64];
	uint32_t a, b, d, e, f, g, h, t1, t2;
	uint32_t cc;
	unsigned int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)blk[i*4] << 24) |
		       ((uint32_t)blk[i*4+1] << 16) |
		       ((uint32_t)blk[i*4+2] << 8) |
			(uint32_t)blk[i*4+3];

	for (i = 16; i < 64; i++) {
		uint32_t s0 = sha256_rotr(w[i-15], 7) ^
			      sha256_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
		uint32_t s1 = sha256_rotr(w[i-2], 17) ^
			      sha256_rotr(w[i-2], 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
	e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];

	for (i = 0; i < 64; i++) {
		uint32_t S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
		uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);

		t1 = h + S1 + ch + sha256_k[i] + w[i];
		t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}

	c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
	c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha256_init(struct sha256_ctx *c)
{
	c->state[0] = 0x6a09e667U; c->state[1] = 0xbb67ae85U;
	c->state[2] = 0x3c6ef372U; c->state[3] = 0xa54ff53aU;
	c->state[4] = 0x510e527fU; c->state[5] = 0x9b05688cU;
	c->state[6] = 0x1f83d9abU; c->state[7] = 0x5be0cd19U;
	c->bitlen = 0;
	c->buflen = 0;
}

static void sha256_update(struct sha256_ctx *c, const void *data, size_t len)
{
	const uint8_t *p = data;

	c->bitlen += (uint64_t)len * 8U;
	while (len > 0) {
		size_t take = 64U - c->buflen;

		if (take > len)
			take = len;
		memcpy(c->buf + c->buflen, p, take);
		c->buflen += (uint32_t)take;
		p += take;
		len -= take;
		if (c->buflen == 64U) {
			sha256_block(c, c->buf);
			c->buflen = 0;
		}
	}
}

static void sha256_final(struct sha256_ctx *c, uint8_t out[32])
{
	uint64_t bitlen = c->bitlen;
	unsigned int i;

	c->buf[c->buflen++] = 0x80U;
	if (c->buflen > 56U) {
		memset(c->buf + c->buflen, 0, 64U - c->buflen);
		sha256_block(c, c->buf);
		c->buflen = 0;
	}
	memset(c->buf + c->buflen, 0, 56U - c->buflen);
	for (i = 0; i < 8; i++)
		c->buf[56U + i] = (uint8_t)(bitlen >> ((7U - i) * 8U));
	sha256_block(c, c->buf);

	for (i = 0; i < 8; i++) {
		out[i*4]     = (uint8_t)(c->state[i] >> 24);
		out[i*4 + 1] = (uint8_t)(c->state[i] >> 16);
		out[i*4 + 2] = (uint8_t)(c->state[i] >> 8);
		out[i*4 + 3] = (uint8_t)(c->state[i]);
	}
}

/*
 * Compute the kernel fingerprint by streaming /proc/kallsyms through
 * SHA-256, skipping the leading whitespace-delimited address token on
 * each line.  The address is what kptr_restrict zeroes for non-root
 * readers; everything past it (symbol type, name, optional module) is
 * stable.  Returns true and fills OUT[32] on success; false (with OUT
 * untouched) on any read or open failure.  Caller treats failure as
 * "warm-start disabled this run".
 */
static bool kcov_fingerprint_kernel(uint8_t out[32])
{
	struct sha256_ctx ctx;
	FILE *f;
	char line[4096];

	f = fopen("/proc/kallsyms", "r");
	if (f == NULL)
		return false;

	sha256_init(&ctx);
	while (fgets(line, sizeof(line), f) != NULL) {
		const char *p = line;
		const char *name;
		size_t len;

		/* Skip the address column (one whitespace-delimited token)
		 * and any whitespace that follows.  The remainder -- type,
		 * name, optional [module], trailing newline -- is what we
		 * would consider hashing.  A malformed all-whitespace line
		 * collapses to the empty string and is just skipped. */
		while (*p && *p != ' ' && *p != '\t')
			p++;
		while (*p == ' ' || *p == '\t')
			p++;

		/* Filter to static built-in kernel symbols only.  Trinity's
		 * own fuzzing of bpf(), kprobes, module loading, etc. adds
		 * runtime entries to /proc/kallsyms whose presence (and even
		 * whose names -- BPF JIT entries embed a per-load hash)
		 * differs across runs of the same kernel binary.  If we hash
		 * those, the fingerprint becomes a function of prior fuzz
		 * activity and the warm-start invariant ("same kernel ->
		 * same fingerprint") breaks. */

		/* Module symbols carry a "[module-name]" suffix; static
		 * built-in symbols never do. */
		if (strchr(p, '[') != NULL)
			continue;

		/* Locate the symbol name: skip the single type char and the
		 * whitespace separating it from the name. */
		if (*p == '\0')
			continue;
		name = p + 1;
		while (*name == ' ' || *name == '\t')
			name++;

		/* BPF JIT programs / trampolines appear as bpf_prog_<hash>
		 * and bpf_trampoline_<id>; both vary per load. */
		if (strncmp(name, "bpf_prog_", 9) == 0 ||
		    strncmp(name, "bpf_trampoline_", 15) == 0)
			continue;

		len = strlen(p);
		if (len > 0)
			sha256_update(&ctx, p, len);
	}

	if (ferror(f)) {
		(void)fclose(f);
		return false;
	}
	(void)fclose(f);

	sha256_final(&ctx, out);
	return true;
}

/*
 * Cached fingerprint for this run.  Computed lazily on first save/load
 * call and stashed so the second call doesn't re-stream /proc/kallsyms.
 * fp_valid stays false if the first computation failed; subsequent calls
 * try again (cheap path -- a missing /proc/kallsyms isn't going to come
 * back during the run, but the retry costs only an open() per attempt).
 */
static uint8_t kcov_kernel_fp[32];
static bool    kcov_kernel_fp_valid;

bool kcov_get_kernel_fp(uint8_t out[32])
{
	if (!kcov_kernel_fp_valid) {
		if (!kcov_fingerprint_kernel(kcov_kernel_fp)) {
			output(0, "kcov-bitmap: kcov_fingerprint_kernel failed (/proc/kallsyms unreadable?) -- cold start\n");
			return false;
		}
		kcov_kernel_fp_valid = true;
	}
	memcpy(out, kcov_kernel_fp, 32);
	return true;
}

/*
 * Dirty-bit proxy for kcov_bitmap_save_file().  edges_found increments
 * once per (edge, bucket) bit-flip in kcov_collect(); when it equals the
 * value at the last successful save, the bitmap contents are bit-for-bit
 * identical and the write would just re-serialise the same bytes.
 * Initialised to ULONG_MAX so the first save in a fresh process always
 * fires; subsequently advanced on every successful save and seeded by
 * the warm-start loader so a load-then-immediate-exit cycle skips its
 * end-of-run save.  Parent-private: the only callers of save_file are
 * the parent (end-of-run path in trinity.c and kcov_bitmap_maybe_snapshot
 * from main_loop / kcov_plateau_check).
 */
static unsigned long kcov_bitmap_edges_at_last_save = ULONG_MAX;

/*
 * Persist-side scribble guard.  bucket_seen[] bits are set-once and the
 * monotonic atomic kcov_shm->coverage.edges_found is bumped exactly once per
 * (edge, bucket) bit-flip after the OR has landed, so by construction
 *
 *     popcount(bucket_seen) >= edges_found       (at the OR-then-bump moment)
 *     popcount(bucket_seen) >= edges_warm_loaded (load floor never clears)
 *
 * Either inequality going the other way at save time is a clobber of the
 * shared bitmap (ASAN-blind: mmap'd shm, not malloc heap).  KCOV_BITMAP_
 * PERSIST_TOL absorbs the harmless case where the edges_found atomic was
 * sampled before the bucket_seen memcpy and a few sibling bumps land on
 * bytes the memcpy has already passed -- those are recount-HIGH and never
 * trip the guard; the tolerance is a defence-in-depth slack for direction
 * inversions that could in principle arise from torn loads of the atomic
 * itself, not for an actual loss of set bits.
 */
#define KCOV_BITMAP_PERSIST_TOL 128UL
/*
 * Persist-refusal is correct (it preserves prior on-disk state when the
 * live bitmap recount has regressed below its set-once warm-load floor),
 * but the underlying scribble does not heal on its own: every subsequent
 * save attempt recounts, refuses, and loops.  A long-lived run can burn
 * CPU for hours doing this.  Once we have refused this many times in a
 * row, request a clean shutdown via EXIT_SHM_CORRUPTION so the main loop
 * tears the run down instead of spinning forever.
 */
#define KCOV_BITMAP_PERSIST_REFUSAL_EXIT_CAP 1000UL
static unsigned long kcov_bitmap_persist_refused_corrupt;

/*
 * Recount the warm-cache edge counters from a bucket_seen[] blob.
 * The bitmap is the authoritative state: edges_found bumps once per
 * (edge, bucket) bit-flip and so equals the popcount of the whole
 * bitmap; distinct_edges bumps only on the all-zero -> first-bit
 * transition and so equals the count of nonzero bytes.  Bits in
 * bucket_seen[] never clear, so these identities hold by
 * construction at every instant in a single process.
 *
 * Used at save so the on-disk counters and the CRC'd bitmap payload
 * are a coherent pair, and at load so a header written without the
 * save-side recount cannot import a frozen skew.
 */
static void kcov_bitmap_recount(const unsigned char *bm, size_t n,
				unsigned long *edges,
				unsigned long *distinct)
{
	unsigned long e = 0;
	unsigned long d = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		unsigned char b = bm[i];

		if (b != 0) {
			e += (unsigned long)__builtin_popcount(b);
			d++;
		}
	}
	*edges = e;
	*distinct = d;
}

bool kcov_bitmap_save_file(const char *path)
{
	struct kcov_bitmap_file_header hdr;
	struct kcov_strat_ondisk strat_blob;
	unsigned long edges_now;
	unsigned long recount_edges;
	unsigned long recount_distinct;
	unsigned char *priors_blob;
	unsigned char *bucket_seen_blob;
	struct kcov_per_syscall_diag_ondisk *diag_blob;
	size_t priors_blob_size;
	size_t one_array_size;
	size_t diag_blob_size;
	char tmppath[PATH_MAX];
	unsigned int nr;
	unsigned int s;
	int fd;
	int ret;

	if (path == NULL || kcov_shm == NULL)
		return false;

	edges_now = __atomic_load_n(&kcov_shm->coverage.edges_found, __ATOMIC_RELAXED);
	if (edges_now == kcov_bitmap_edges_at_last_save) {
		output(0, "kcov-bitmap: snapshot skipped, no new edges since last save\n");
		return true;
	}

	one_array_size = (size_t)MAX_NR_SYSCALL * sizeof(unsigned long);
	priors_blob_size = 2 * one_array_size;
	priors_blob = malloc(priors_blob_size);
	if (priors_blob == NULL) {
		output(0, "kcov-bitmap: priors scratch alloc fail (%zu bytes) -- save aborted\n",
		       priors_blob_size);
		return false;
	}
	/* per_syscall_edges / per_syscall_calls are [nr][do32?1:0]; the
	 * on-disk priors format is still one MAX_NR_SYSCALL-long per-nr
	 * blob, so sum both arch dims into the serialised slot.  Loaders
	 * put the summed value into [nr][0] on warm-start; readers that
	 * use the priors go through per_syscall_edges_prior_total() /
	 * _calls_prior_total() and observe the same per-nr sum either
	 * way, so arch attribution is not persisted (nothing consumes it
	 * on the prior side today). */
	{
		unsigned long *p_edges = (unsigned long *)priors_blob;
		unsigned long *p_calls =
			(unsigned long *)(priors_blob + one_array_size);
		unsigned int i;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			p_edges[i] = kcov_shm->per_syscall.per_syscall_edges[i][0] +
				     kcov_shm->per_syscall.per_syscall_edges[i][1];
			p_calls[i] = kcov_shm->per_syscall.per_syscall_calls[i][0] +
				     kcov_shm->per_syscall.per_syscall_calls[i][1];
		}
	}

	/* v6 diag block: pack per_syscall_diag[nr][dim].{bucket_bits_real,
	 * distinct_pcs} into a contiguous 16-B-per-slot array, nr outer,
	 * dim inner.  Read each field with a relaxed atomic load because
	 * children are still bumping these in parallel from the snapshot
	 * path; a torn pair across (bucket_bits_real, distinct_pcs) of
	 * the same slot is harmless since the two are independent
	 * counters and the readers treat them as soft per-syscall
	 * totals. */
	diag_blob_size = (size_t)MAX_NR_SYSCALL * 2 *
			 sizeof(struct kcov_per_syscall_diag_ondisk);
	diag_blob = malloc(diag_blob_size);
	if (diag_blob == NULL) {
		output(0, "kcov-bitmap: diag scratch alloc fail (%zu bytes) -- save aborted\n",
		       diag_blob_size);
		free(priors_blob);
		return false;
	}
	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		unsigned int dim;

		for (dim = 0; dim < 2; dim++) {
			struct kcov_per_syscall_diag *d =
				&kcov_shm->per_syscall_diag[nr][dim];
			struct kcov_per_syscall_diag_ondisk *o =
				&diag_blob[nr * 2 + dim];

			o->bucket_bits_real = __atomic_load_n(
				&d->bucket_bits_real, __ATOMIC_RELAXED);
			o->distinct_pcs = __atomic_load_n(
				&d->distinct_pcs, __ATOMIC_RELAXED);
		}
	}

	/* v7 strat block: pack pc_edge_calls_by_strategy[] then
	 * pc_edge_count_by_strategy[] into a 48 B u64-LE array.  Same
	 * relaxed-atomic-load reasoning as the diag block above --
	 * children are bumping these in parallel from the snapshot
	 * path; the readers treat them as soft per-strategy totals
	 * so a torn pair is benign. */
	memset(&strat_blob, 0, sizeof(strat_blob));
	for (s = 0; s < NR_STRATEGIES; s++) {
		strat_blob.calls[s] = __atomic_load_n(
			&shm->pc_edge_calls_by_strategy[s],
			__ATOMIC_RELAXED);
		strat_blob.count[s] = __atomic_load_n(
			&shm->pc_edge_count_by_strategy[s],
			__ATOMIC_RELAXED);
	}

	/* Snapshot bucket_seen into a stable buffer so the CRC stamped in
	 * the header and the bytes later streamed to disk cover the
	 * identical payload.  Without this, a fuzzing child flipping a
	 * new-edge byte between the crc32() and write_all() calls below
	 * would leave the on-disk payload not matching its stored CRC,
	 * and the next warm-start load would reject it as a CRC mismatch
	 * and silently drop accumulated coverage.  The copy itself need
	 * not be atomic: coverage is additive, so a byte flipping mid-
	 * memcpy is harmless (we capture 0 or 1; the edge is recaptured
	 * on the next save).  The only invariant is that the CRC and the
	 * write reference the same bytes. */
	bucket_seen_blob = malloc(KCOV_NUM_EDGES);
	if (bucket_seen_blob == NULL) {
		output(0, "kcov-bitmap: bucket_seen scratch alloc fail (%zu bytes) -- save aborted\n",
		       (size_t)KCOV_NUM_EDGES);
		free(diag_blob);
		free(priors_blob);
		return false;
	}
	memcpy(bucket_seen_blob, kcov_shm->bucket_seen, KCOV_NUM_EDGES);

	memset(&hdr, 0, sizeof(hdr));
	if (!kcov_get_kernel_fp(hdr.kallsyms_sha256)) {
		free(bucket_seen_blob);
		free(diag_blob);
		free(priors_blob);
		return false;
	}

	hdr.magic = KCOV_BITMAP_FILE_MAGIC;
	hdr.version = KCOV_BITMAP_FILE_VERSION;
	hdr.num_edges = KCOV_NUM_EDGES;
	hdr.num_buckets = KCOV_NUM_BUCKETS;
	/* Stamp edges_found / distinct_edges from a recount over the
	 * bucket_seen snapshot rather than from the running atomics:
	 * sampling kcov_shm->{edges_found, distinct_edges} here would
	 * race the memcpy above and could leave the header pair one or
	 * more (edge, bucket) bit-flips out of step with the bytes the
	 * payload_crc32 below covers.  The recount makes the on-disk
	 * (counter, bitmap) pair coherent by construction. */
	kcov_bitmap_recount(bucket_seen_blob, KCOV_NUM_EDGES,
			    &recount_edges, &recount_distinct);

	/* Refuse to persist a recount that has regressed below the load
	 * floor (this run loaded MORE bits than its own bitmap can now
	 * account for) or that has fallen materially behind the monotonic
	 * atomic that should equal popcount(bucket_seen) by construction
	 * (a stray writer has cleared set bits in the shared bitmap).
	 * Either condition means the snapshot we are about to rename over
	 * the good on-disk cache is a clobbered view; persisting it would
	 * rewind the cache floor below the warm-load baseline and force
	 * the next run to re-discover edges this run already had.  Keep
	 * the prior on-disk file, log a loud canary, and bump a counter
	 * so the refusal rate is visible in run logs.  Runs into the same
	 * guard from both end-of-run and kcov_bitmap_maybe_snapshot(), so
	 * a mid-run scribble is caught at the first periodic save after
	 * it happens, not just at exit. */
	{
		unsigned long floor = __atomic_load_n(
			&kcov_shm->coverage.edges_warm_loaded, __ATOMIC_RELAXED);
		unsigned long distinct_floor = __atomic_load_n(
			&kcov_shm->coverage.distinct_edges_warm_loaded,
			__ATOMIC_RELAXED);
		bool below_floor = recount_edges < floor;
		bool below_atomic = (edges_now > recount_edges) &&
				    (edges_now - recount_edges >
				     KCOV_BITMAP_PERSIST_TOL);
		/* distinct_edges is bounded by KCOV_NUM_EDGES (much smaller
		 * than the bucket-transition counter), so torn-load slack is
		 * negligible and a strict regression below the set-once
		 * warm-load baseline is a real loss of a distinct edge bit
		 * -- no tolerance window needed.  Closes the hole where a
		 * scribble that page-clears a bucket_seen byte drops a
		 * distinct edge while staying inside edges-tolerance and the
		 * corrupt snapshot would otherwise persist. */
		bool below_distinct = recount_distinct < distinct_floor;

		if (below_floor || below_atomic || below_distinct) {
			kcov_bitmap_persist_refused_corrupt++;
			output(0, "kcov-bitmap: REFUSING persist -- bitmap recount %lu < floor %lu / atomic %lu, distinct recount %lu < distinct floor %lu (scribble?) -- keeping prior on-disk state (refused=%lu)\n",
			       recount_edges, floor, edges_now,
			       recount_distinct, distinct_floor,
			       kcov_bitmap_persist_refused_corrupt);
			if (kcov_bitmap_persist_refused_corrupt ==
			    KCOV_BITMAP_PERSIST_REFUSAL_EXIT_CAP) {
				output(0, "kcov-bitmap: %lu persist refusals -- bitmap corruption is not self-healing; requesting shutdown (EXIT_SHM_CORRUPTION)\n",
				       kcov_bitmap_persist_refused_corrupt);
				/* Don't clobber an exit already in progress
				 * (e.g. SIGINT, a prior shm-corruption bail
				 * from another check).  Race-tolerant: the
				 * canonical pattern across the tree is a
				 * RELAXED load+store guarded by the
				 * STILL_RUNNING sentinel. */
				if (__atomic_load_n(&shm->exit_reason,
						    __ATOMIC_RELAXED) ==
				    STILL_RUNNING)
					__atomic_store_n(&shm->exit_reason,
							 EXIT_SHM_CORRUPTION,
							 __ATOMIC_RELAXED);
			}
			free(bucket_seen_blob);
			free(diag_blob);
			free(priors_blob);
			return false;
		}
	}

	hdr.edges_found = recount_edges;
	hdr.distinct_edges = recount_distinct;
	hdr.payload_crc32 = crc32(bucket_seen_blob, KCOV_NUM_EDGES);
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	hdr.priors_crc32 = crc32(priors_blob, priors_blob_size);
	hdr.diag_crc32 = crc32(diag_blob, diag_blob_size);
	hdr.strat_crc32 = crc32(&strat_blob, sizeof(strat_blob));
	/* Stamp the canonicalisation mode so the loader can refuse a
	 * canonical-vs-raw mismatch.  Zero means the writer hashed PCs
	 * raw (kallsyms unreadable, _text absent); non-zero is the
	 * writer's runtime _text address and is informational past the
	 * non-zero check -- the loader only cares about the mode bit,
	 * not the specific base, because both sides canonicalise against
	 * their own local base before comparing bucket indices. */
	hdr.kaslr_base = kcov_kaslr_base;

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)mypid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		free(bucket_seen_blob);
		free(diag_blob);
		free(priors_blob);
		return false;
	}

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		free(bucket_seen_blob);
		free(diag_blob);
		free(priors_blob);
		return false;
	}

	/* Neutralise any fuzzer-installed umask so the save mode is 0644. */
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		free(bucket_seen_blob);
		free(diag_blob);
		free(priors_blob);
		return false;
	}

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (write_all(fd, bucket_seen_blob, KCOV_NUM_EDGES) < 0)
		goto fail;
	if (write_all(fd, priors_blob, priors_blob_size) < 0)
		goto fail;
	if (write_all(fd, diag_blob, diag_blob_size) < 0)
		goto fail;
	if (write_all(fd, &strat_blob, sizeof(strat_blob)) < 0)
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		free(bucket_seen_blob);
		free(diag_blob);
		free(priors_blob);
		return false;
	}
	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		free(bucket_seen_blob);
		free(diag_blob);
		free(priors_blob);
		return false;
	}
	free(bucket_seen_blob);
	free(diag_blob);
	free(priors_blob);
	kcov_bitmap_edges_at_last_save = edges_now;
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	free(bucket_seen_blob);
	free(diag_blob);
	free(priors_blob);
	return false;
}

bool kcov_bitmap_load_file(const char *path)
{
	struct kcov_bitmap_file_header hdr;
	uint8_t cur_fp[32];
	unsigned char *scratch;
	uint32_t want_crc;
	unsigned long recount_edges;
	unsigned long recount_distinct;
	ssize_t n;
	int fd;

	if (path == NULL || kcov_shm == NULL)
		return false;

	persist_sweep_stale_tmp(path);

	if (!kcov_get_kernel_fp(cur_fp)) {
		output(0, "kcov-bitmap: cannot fingerprint kernel (/proc/kallsyms unavailable) -- warm-start disabled this run\n");
		return false;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			output(0, "kcov-bitmap: no persisted state at %s -- cold start\n",
			       path);
		else
			output(0, "kcov-bitmap: open(%s) failed: %s -- cold start\n",
			       path, strerror(errno));
		return false;
	}

	/* Read only the v6-sized prefix first so a v5/v6 file (88 B
	 * header on disk) still passes the truncation check; the v7
	 * trailer (strat_crc32 + pad2) is read separately below once
	 * the version is known.  Zero the whole struct up front so the
	 * v7 trailer fields stay implicit-zero on v5/v6 files. */
	memset(&hdr, 0, sizeof(hdr));
	n = read_all(fd, &hdr, KCOV_BITMAP_HDR_V6_SIZE);
	if (n != (ssize_t)KCOV_BITMAP_HDR_V6_SIZE) {
		output(0, "kcov-bitmap: header truncated at %s (got %zd, want %u) -- cold start\n",
		       path, n, (unsigned int)KCOV_BITMAP_HDR_V6_SIZE);
		(void)close(fd);
		return false;
	}

	if (hdr.magic != KCOV_BITMAP_FILE_MAGIC) {
		output(0, "kcov-bitmap: file magic 0x%08x != expected 0x%08x at %s -- cold start\n",
		       hdr.magic, KCOV_BITMAP_FILE_MAGIC, path);
		(void)close(fd);
		return false;
	}
	if (hdr.version < KCOV_BITMAP_FILE_MIN_LOAD_VERSION ||
	    hdr.version > KCOV_BITMAP_FILE_VERSION) {
		output(0, "kcov-bitmap: file version %u outside accepted range [%u..%u] at %s -- cold start\n",
		       hdr.version,
		       (unsigned int)KCOV_BITMAP_FILE_MIN_LOAD_VERSION,
		       (unsigned int)KCOV_BITMAP_FILE_VERSION, path);
		(void)close(fd);
		return false;
	}
	/* v7 trailer: 8 B of {strat_crc32, pad2} that v5/v6 binaries
	 * did not write.  Only present (and only read) when the file
	 * itself is v7+; otherwise the prefix above already left both
	 * fields zero. */
	if (hdr.version >= 7U) {
		size_t tail_size = sizeof(hdr) - KCOV_BITMAP_HDR_V6_SIZE;

		n = read_all(fd, (unsigned char *)&hdr +
				 KCOV_BITMAP_HDR_V6_SIZE, tail_size);
		if (n != (ssize_t)tail_size) {
			output(0, "kcov-bitmap: v7 header trailer truncated at %s (got %zd, want %zu) -- cold start\n",
			       path, n, tail_size);
			(void)close(fd);
			return false;
		}
	}
	if (hdr.num_edges != KCOV_NUM_EDGES) {
		output(0, "kcov-bitmap: num_edges %u != expected %u at %s (file built with a different KCOV_NUM_EDGES) -- cold start\n",
		       hdr.num_edges, KCOV_NUM_EDGES, path);
		(void)close(fd);
		return false;
	}
	if (hdr.num_buckets != KCOV_NUM_BUCKETS) {
		output(0, "kcov-bitmap: num_buckets %u != expected %u at %s (file built with a different KCOV_NUM_BUCKETS) -- cold start\n",
		       hdr.num_buckets, KCOV_NUM_BUCKETS, path);
		(void)close(fd);
		return false;
	}
	if (memcmp(hdr.kallsyms_sha256, cur_fp, sizeof(cur_fp)) != 0) {
		output(0, "kcov-bitmap: kernel fingerprint mismatch at %s (kallsyms content differs from when the file was written) -- cold start\n",
		       path);
		(void)close(fd);
		return false;
	}
	/* The on-disk buckets are indexed by canonical PC (raw PC minus
	 * the writer's KASLR base) when hdr.kaslr_base != 0, and by raw
	 * PC otherwise.  This run's hot path applies the same transform
	 * against the local kcov_kaslr_base, so the two must agree on
	 * whether canonicalisation is in effect at all -- any XOR
	 * mismatch means one side is canonical and the other raw, and
	 * the bucket indices would silently disagree.  Both-canonical
	 * (regardless of which base each used) and both-raw are
	 * accepted; the indices line up because each side strips its
	 * own local base. */
	if ((hdr.kaslr_base != 0) != (kcov_kaslr_base != 0)) {
		output(0, "kcov-bitmap: canonicalisation mismatch at %s (file kaslr_base=0x%llx, current=0x%llx) -- refusing stale bitmap, cold start\n",
		       path,
		       (unsigned long long)hdr.kaslr_base,
		       (unsigned long long)kcov_kaslr_base);
		(void)close(fd);
		return false;
	}

	/* Stage into a scratch buffer so a CRC failure doesn't leave the
	 * shared bitmap half-overwritten with garbage. */
	scratch = malloc(KCOV_NUM_EDGES);
	if (scratch == NULL) {
		output(0, "kcov-bitmap: scratch alloc fail (%zu bytes) -- cold start\n",
		       (size_t)KCOV_NUM_EDGES);
		(void)close(fd);
		return false;
	}
	n = read_all(fd, scratch, KCOV_NUM_EDGES);
	if (n != (ssize_t)KCOV_NUM_EDGES) {
		output(0, "kcov-bitmap: payload truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, (size_t)KCOV_NUM_EDGES);
		free(scratch);
		(void)close(fd);
		return false;
	}

	want_crc = crc32(scratch, KCOV_NUM_EDGES);
	if (want_crc != hdr.payload_crc32) {
		output(0, "kcov-bitmap: skipping warm-start of %s -- CRC mismatch\n",
		       path);
		free(scratch);
		(void)close(fd);
		return false;
	}

	memcpy(kcov_shm->bucket_seen, scratch, KCOV_NUM_EDGES);
	free(scratch);

	/* Bitmap warm-start has succeeded by this point.  The priors blob
	 * is a soft signal -- any failure mode below logs and falls through
	 * with priors zeroed, but must not invalidate the bitmap load. */
	if (hdr.max_nr_syscall != MAX_NR_SYSCALL) {
		output(0, "kcov-bitmap: priors disabled, max_nr_syscall %u != %u\n",
		       hdr.max_nr_syscall, (unsigned int)MAX_NR_SYSCALL);
	} else {
		size_t one_array_size = (size_t)MAX_NR_SYSCALL *
					sizeof(unsigned long);
		size_t priors_blob_size = 2 * one_array_size;
		unsigned char *priors_blob = malloc(priors_blob_size);

		if (priors_blob == NULL) {
			output(0, "kcov-bitmap: priors scratch alloc fail (%zu bytes) -- priors skipped\n",
			       priors_blob_size);
		} else {
			n = read_all(fd, priors_blob,
						 priors_blob_size);
			if (n != (ssize_t)priors_blob_size) {
				output(0, "kcov-bitmap: priors truncated at %s (got %zd, want %zu) -- priors skipped\n",
				       path, n, priors_blob_size);
			} else {
				uint32_t got_crc;

				got_crc = crc32(priors_blob,
							    priors_blob_size);
				if (got_crc != hdr.priors_crc32) {
					output(0, "kcov-bitmap: priors CRC mismatch at %s -- priors skipped\n",
					       path);
				} else {
					/* On-disk priors are still one long
					 * per-nr; the in-shm _prior arrays are
					 * [nr][do32?1:0].  Load into the [nr][0]
					 * slot and leave [nr][1] at its calloc'd
					 * zero; readers that use the priors sum
					 * both dims via the _total helpers, so
					 * the missing arch attribution is a
					 * harmless zero addend. */
					unsigned long *p_edges =
						(unsigned long *)priors_blob;
					unsigned long *p_calls =
						(unsigned long *)(priors_blob +
								  one_array_size);
					unsigned int i;

					for (i = 0; i < MAX_NR_SYSCALL; i++) {
						kcov_shm->per_syscall.per_syscall_edges_prior[i][0] =
							p_edges[i];
						kcov_shm->per_syscall.per_syscall_calls_prior[i][0] =
							p_calls[i];
					}
				}
			}
			free(priors_blob);
		}
	}

	/* v6 diag block: per_syscall_diag[nr][dim].{bucket_bits_real,
	 * distinct_pcs} packed as 16 B per slot, nr outer, dim inner.
	 * Soft signal like the priors above -- any failure mode here
	 * logs and falls through with the diag counters left at zero,
	 * but must not invalidate the bitmap load already committed.
	 * v5 (and below) files lack the block; skip on those without
	 * complaint. */
	if (hdr.version >= 6U && hdr.max_nr_syscall == MAX_NR_SYSCALL) {
		size_t diag_blob_size = (size_t)MAX_NR_SYSCALL * 2 *
			sizeof(struct kcov_per_syscall_diag_ondisk);
		struct kcov_per_syscall_diag_ondisk *diag_blob =
			malloc(diag_blob_size);

		if (diag_blob == NULL) {
			output(0, "kcov-bitmap: diag scratch alloc fail (%zu bytes) -- diag skipped\n",
			       diag_blob_size);
		} else {
			n = read_all(fd, diag_blob, diag_blob_size);
			if (n != (ssize_t)diag_blob_size) {
				output(0, "kcov-bitmap: diag truncated at %s (got %zd, want %zu) -- diag skipped\n",
				       path, n, diag_blob_size);
			} else {
				uint32_t got_crc = crc32(diag_blob,
							 diag_blob_size);

				if (got_crc != hdr.diag_crc32) {
					output(0, "kcov-bitmap: diag CRC mismatch at %s -- diag skipped\n",
					       path);
				} else {
					unsigned int nr;

					for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
						unsigned int dim;

						for (dim = 0; dim < 2; dim++) {
							struct kcov_per_syscall_diag_ondisk *o =
								&diag_blob[nr * 2 + dim];
							struct kcov_per_syscall_diag *d =
								&kcov_shm->per_syscall_diag[nr][dim];

							__atomic_store_n(&d->bucket_bits_real,
									 o->bucket_bits_real,
									 __ATOMIC_RELAXED);
							__atomic_store_n(&d->distinct_pcs,
									 o->distinct_pcs,
									 __ATOMIC_RELAXED);
						}
					}
					output(0, "kcov-bitmap: loaded v6 diag block from %s (CRC OK)\n",
					       path);
				}
			}
			free(diag_blob);
		}
	}

	/* v7 strat block: pc_edge_calls_by_strategy[NR_STRATEGIES]
	 * then pc_edge_count_by_strategy[NR_STRATEGIES], each as
	 * u64 LE -- 48 B total today (NR_STRATEGIES == 3).  Soft
	 * signal like the diag/priors blocks above: a short read or
	 * CRC mismatch logs and falls through with the per-strategy
	 * counters left at whatever they currently hold (typically
	 * zero on a fresh shm), and the bitmap warm-load stays
	 * committed.  v5/v6 files lack the block; skip them quietly. */
	if (hdr.version >= 7U) {
		struct kcov_strat_ondisk strat_blob;

		memset(&strat_blob, 0, sizeof(strat_blob));
		n = read_all(fd, &strat_blob, sizeof(strat_blob));
		if (n != (ssize_t)sizeof(strat_blob)) {
			output(0, "kcov-bitmap: strat truncated at %s (got %zd, want %zu) -- strat skipped\n",
			       path, n, sizeof(strat_blob));
		} else {
			uint32_t got_crc = crc32(&strat_blob,
						 sizeof(strat_blob));

			if (got_crc != hdr.strat_crc32) {
				output(0, "kcov-bitmap: strat CRC mismatch at %s -- strat skipped\n",
				       path);
			} else {
				unsigned int s;

				for (s = 0; s < NR_STRATEGIES; s++) {
					__atomic_store_n(
						&shm->pc_edge_calls_by_strategy[s],
						strat_blob.calls[s],
						__ATOMIC_RELAXED);
					__atomic_store_n(
						&shm->pc_edge_count_by_strategy[s],
						strat_blob.count[s],
						__ATOMIC_RELAXED);
				}
				output(0, "kcov-bitmap: loaded v7 strat block from %s (CRC OK)\n",
				       path);
			}
		}
	}

	(void)close(fd);
	/* Recount counters from the just-loaded bitmap instead of
	 * trusting the header values verbatim.  Headers written without
	 * the save-side recount can carry a skewed pair (counters were
	 * sampled at a different instant than the bitmap snapshot they
	 * summarise); restoring those values straight into the running
	 * atomics would import the skew and round-trip it across every
	 * subsequent save/load cycle.  The bitmap is authoritative --
	 * popcount and nonzero-byte count are the by-construction
	 * definitions of these two counters. */
	kcov_bitmap_recount(kcov_shm->bucket_seen, KCOV_NUM_EDGES,
			    &recount_edges, &recount_distinct);
	if (recount_edges != hdr.edges_found ||
	    recount_distinct != hdr.distinct_edges) {
		output(0, "kcov-bitmap: header counters {edges=%lu, distinct=%lu} disagree with bitmap recount {edges=%lu, distinct=%lu} at %s -- using recount\n",
		       (unsigned long)hdr.edges_found,
		       (unsigned long)hdr.distinct_edges,
		       recount_edges, recount_distinct, path);
	}
	__atomic_store_n(&kcov_shm->coverage.edges_found, recount_edges,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->coverage.distinct_edges, recount_distinct,
			 __ATOMIC_RELAXED);
	/* Snapshot the warm-loaded count so print_stats() can split
	 * displayed coverage into the warm-vs-cold contribution.  Set
	 * exactly here -- after the bitmap is in place and before any
	 * child has had a chance to discover new coverage -- so a later
	 * (edges_found - edges_warm_loaded) subtraction is the count of
	 * edges this run actually discovered itself. */
	__atomic_store_n(&kcov_shm->coverage.edges_warm_loaded, recount_edges,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->coverage.distinct_edges_warm_loaded,
			 recount_distinct, __ATOMIC_RELAXED);
	/* Seed the dirty-bit baseline so a load-then-immediate-exit cycle
	 * skips the redundant end-of-run save. */
	kcov_bitmap_edges_at_last_save = recount_edges;
	output(0, "kcov-bitmap: loaded %lu edges (%lu distinct) from %s\n",
	       recount_edges, recount_distinct, path);
	return true;
}

const char *kcov_bitmap_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	const char *arch;
	char release[256];
	int ret;
	int rfd;
	ssize_t rn;
	char *nl;

#if defined(__x86_64__)
	arch = "x86_64";
#elif defined(__i386__)
	arch = "i386";
#elif defined(__aarch64__)
	arch = "aarch64";
#elif defined(__arm__)
	arch = "arm";
#else
	arch = "unknown";
#endif

	rfd = open("/proc/sys/kernel/osrelease", O_RDONLY);
	if (rfd < 0)
		return NULL;
	rn = read(rfd, release, sizeof(release) - 1);
	(void)close(rfd);
	if (rn <= 0)
		return NULL;
	release[rn] = '\0';
	nl = strchr(release, '\n');
	if (nl != NULL)
		*nl = '\0';
	/* Sanitise: '/' would split the path; replace in place. */
	for (nl = release; *nl; nl++) {
		if (*nl == '/')
			*nl = '_';
	}

	if (xdg && xdg[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			       "%s/trinity/kcov-bitmap", xdg);
	else if (home && home[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			       "%s/.cache/trinity/kcov-bitmap", home);
	else
		return NULL;
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

	{
		char *p;

		for (p = dir + 1; *p; p++) {
			if (*p == '/') {
				*p = '\0';
				if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
					*p = '/';
					return NULL;
				}
				*p = '/';
			}
		}
		if (mkdir(dir, 0755) != 0 && errno != EEXIST)
			return NULL;
	}

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s",
		       dir, arch, release);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Periodic mid-run snapshot trigger.  Called only from parent context
 * (main_loop's stats tick and kcov_plateau_check's plateau-entry
 * branch), so the snapshot state lives in parent-private statics --
 * no CAS race with children to worry about.
 */
static char kcov_bitmap_snapshot_path[PATH_MAX];
static bool kcov_bitmap_snapshot_enabled;
static unsigned long kcov_bitmap_edges_at_last_snapshot;
static time_t kcov_bitmap_last_snapshot_time;

void kcov_bitmap_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(kcov_bitmap_snapshot_path))
		return;
	memcpy(kcov_bitmap_snapshot_path, path, len + 1);
	kcov_bitmap_snapshot_enabled = true;
	/* CLOCK_MONOTONIC seconds: the maybe-snapshot cadence compares this
	 * against a monotonic `now`, so a wall-clock backward step cannot
	 * starve the cadence and a forward step cannot fire a burst. */
	kcov_bitmap_last_snapshot_time =
		(time_t)(mono_ns() / 1000000000ULL);
}

void kcov_bitmap_maybe_snapshot(void)
{
	unsigned long edges_now;
	time_t now;

	if (!kcov_bitmap_snapshot_enabled || kcov_shm == NULL)
		return;

	edges_now = __atomic_load_n(&kcov_shm->coverage.edges_found, __ATOMIC_RELAXED);
	now = (time_t)(mono_ns() / 1000000000ULL);

	if (edges_now < kcov_bitmap_edges_at_last_snapshot
			+ KCOV_BITMAP_SNAPSHOT_EDGES &&
	    now < kcov_bitmap_last_snapshot_time
			+ (time_t)KCOV_BITMAP_SNAPSHOT_INTERVAL_SEC)
		return;

	if (kcov_bitmap_save_file(kcov_bitmap_snapshot_path)) {
		kcov_bitmap_edges_at_last_snapshot = edges_now;
		kcov_bitmap_last_snapshot_time = now;
	}
}

/*
 * Self-rate-limited timestamp for kcov_bitmap_canary_check().  Stamped
 * from CLOCK_MONOTONIC so an NTP step backwards can't suppress an
 * otherwise-due check (the dual to the kcov_plateau_check clock
 * audit -- both share the codebase's "elapsed time uses MONOTONIC,
 * never time()/REALTIME" invariant).  Parent-only state; never read
 * from a child.
 */
static time_t kcov_bitmap_canary_last_check_mono;

void kcov_bitmap_canary_check(void)
{
	struct timespec ts;
	time_t now;
	unsigned long edges_before;
	unsigned long popcount;
	unsigned long ignored_distinct;
	unsigned long deficit;

	if (kcov_shm == NULL)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	/*
	 * First call seeds the gate without scanning -- there's nothing
	 * to compare against yet and the operator-visible 0/0 ratio
	 * carries no signal.  Subsequent calls scan no more than once
	 * per KCOV_BITMAP_CANARY_INTERVAL_SEC.
	 */
	if (kcov_bitmap_canary_last_check_mono == 0) {
		kcov_bitmap_canary_last_check_mono = now;
		return;
	}
	if ((unsigned long)(now - kcov_bitmap_canary_last_check_mono) <
	    KCOV_BITMAP_CANARY_INTERVAL_SEC)
		return;
	kcov_bitmap_canary_last_check_mono = now;

	/*
	 * Sample edges_found BEFORE the popcount so any bits set after
	 * the sample are excluded from the deficit math: edges_before
	 * counts bit-flips committed strictly before the load, and
	 * every one of those flips set a bucket_seen byte that bits-
	 * never-clear keeps set forever.  popcount < edges_before is
	 * therefore strict evidence of cleared bits, modulo the
	 * KCOV_BITMAP_CANARY_DEFICIT memory-ordering tolerance below.
	 *
	 * popcount > edges_before is fine and expected on a busy run
	 * (new bits set during the scan show up in the count); the
	 * canary only treats the deficit direction as an alarm.
	 */
	edges_before = __atomic_load_n(&kcov_shm->coverage.edges_found,
				       __ATOMIC_RELAXED);

	kcov_bitmap_recount(kcov_shm->bucket_seen, KCOV_NUM_EDGES,
			    &popcount, &ignored_distinct);
	(void)ignored_distinct;

	__atomic_fetch_add(&shm->stats.plateau.bucket_canary_checks, 1,
			   __ATOMIC_RELAXED);

	if (popcount >= edges_before)
		return;

	deficit = edges_before - popcount;
	if (deficit <= KCOV_BITMAP_CANARY_DEFICIT)
		return;

	__atomic_fetch_add(&shm->stats.plateau.bucket_canary_deficits, 1,
			   __ATOMIC_RELAXED);
	stats_log_write("CANARY: kcov bucket_seen deficit=%lu (popcount=%lu, edges_before=%lu, threshold=%lu) -- bits cleared since last check, wild writer in shm\n",
			deficit, popcount, edges_before,
			KCOV_BITMAP_CANARY_DEFICIT);
}
