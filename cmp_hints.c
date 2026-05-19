/*
 * KCOV comparison operand collection and hint pool management.
 *
 * Parses KCOV_TRACE_CMP trace buffers to extract constants that the
 * kernel compared syscall-derived values against. These constants
 * are stored in per-syscall in-memory pools and used during argument
 * generation to produce values more likely to pass kernel validation.
 *
 * Buffer format (each record is 4 x u64):
 *   [0] type  - KCOV_CMP_CONST | KCOV_CMP_SIZE(n)
 *   [1] arg1  - first comparison operand
 *   [2] arg2  - second comparison operand
 *   [3] ip    - instruction pointer of the comparison
 *
 * Pool entries are keyed by (cmp_ip, value, size).  Distinguishing on
 * cmp_ip means the same constant compared at two different kernel
 * sites occupies two slots rather than colliding -- the precision
 * matters once a downstream consumer wants to attribute which site a
 * hint came from.  When a pool fills, the entry with the lowest
 * last_used generation is evicted (least-recently-inserted), so a
 * fresh constant displaces stale long-tail noise instead of stomping
 * a slot at random.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "random.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

/* From uapi/linux/kcov.h.  KCOV_CMP_SIZE(n) packs the operand-width
 * index n in {0,1,2,3} into bits 1..2 of the type word; the actual
 * operand width in bytes is (1U << n). */
#define KCOV_CMP_CONST		(1U << 0)
#define KCOV_CMP_SIZE_SHIFT	1
#define KCOV_CMP_SIZE_MASK	3U

/* Words per comparison record in the trace buffer. */
#define WORDS_PER_CMP 4

struct cmp_hints_shared *cmp_hints_shm = NULL;

void cmp_hints_init(void)
{
	if (kcov_shm == NULL)
		return;

	/*
	 * Wild-write risk: a child syscall whose user-buffer arg aliases
	 * into a pool could let the kernel scribble into pool->entries[]
	 * (worst case: a duplicate slips past the linear-scan dedup, or a
	 * stale value is handed back as a hint -- not a crash) or into the
	 * lock byte (a stuck lock would deadlock subsequent
	 * cmp_hints_collect callers in that one syscall slot).
	 * Diagnostic-grade only.
	 */
	cmp_hints_shm = alloc_shared(sizeof(struct cmp_hints_shared));
	memset(cmp_hints_shm, 0, sizeof(struct cmp_hints_shared));
	output(0, "KCOV: CMP hint pool allocated (%lu KB)\n",
		(unsigned long) sizeof(struct cmp_hints_shared) / 1024);
}

static void pool_lock(struct cmp_hint_pool *pool)
{
	lock(&pool->lock);
}

static void pool_unlock(struct cmp_hint_pool *pool)
{
	unlock(&pool->lock);
}

/*
 * Insert (cmp_ip, val, size) into the entries[] array.  Dedups via linear
 * scan on the full (cmp_ip, value, size) key.  When the pool is full,
 * evicts the entry with the smallest last_used (least-recently-inserted)
 * to make room.  Duplicate hits refresh last_used so an actively-observed
 * constant doesn't get evicted by transient long-tail noise.  Caller must
 * hold pool->lock.
 */
static void pool_add_locked(struct cmp_hint_pool *pool,
			    unsigned long cmp_ip,
			    unsigned long val,
			    unsigned int size)
{
	unsigned int i, count = pool->count;
	unsigned int stamp = ++pool->generation;
	unsigned int victim;
	unsigned int oldest;

	for (i = 0; i < count; i++) {
		struct cmp_hint_entry *e = &pool->entries[i];

		if (e->value == val && e->cmp_ip == cmp_ip && e->size == size) {
			e->last_used = stamp;
			return;
		}
	}

	if (count < CMP_HINTS_PER_SYSCALL) {
		struct cmp_hint_entry *e = &pool->entries[count];

		e->value = val;
		e->cmp_ip = cmp_ip;
		e->size = size;
		e->last_used = stamp;
		/*
		 * RELEASE-store count so a lockless reader in cmp_hints_try_get
		 * that observes the new count is guaranteed to also see the
		 * entries[] store above.
		 */
		__atomic_store_n(&pool->count, count + 1, __ATOMIC_RELEASE);
		return;
	}

	victim = 0;
	oldest = pool->entries[0].last_used;
	for (i = 1; i < CMP_HINTS_PER_SYSCALL; i++) {
		if (pool->entries[i].last_used < oldest) {
			oldest = pool->entries[i].last_used;
			victim = i;
		}
	}
	pool->entries[victim].value = val;
	pool->entries[victim].cmp_ip = cmp_ip;
	pool->entries[victim].size = size;
	pool->entries[victim].last_used = stamp;
}

/*
 * Per-child seen-bloom hashes over the (cmp_ip, val, size) tuple.  Two
 * independent splitmix64-style mixes -- the same shape the cmp_novelty
 * bloom in strategy.c uses, kept local so the two hash families are
 * free to drift if one turns out to need a different mixing constant
 * for the load it actually sees.  Indices are masked to
 * CMP_HINTS_BLOOM_MASK so the bloom width can change without touching
 * the hashes.
 */
static inline uint32_t cmp_hints_bloom_h1(unsigned long ip, unsigned long val,
					  unsigned int size)
{
	uint64_t x = (uint64_t)ip
		   ^ ((uint64_t)val * 0x9e3779b97f4a7c15ULL)
		   ^ ((uint64_t)size << 13);

	x ^= x >> 32;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	return (uint32_t)(x & CMP_HINTS_BLOOM_MASK);
}

static inline uint32_t cmp_hints_bloom_h2(unsigned long ip, unsigned long val,
					  unsigned int size)
{
	uint64_t x = (uint64_t)val
		   ^ ((uint64_t)ip * 0x94d049bb133111ebULL)
		   ^ ((uint64_t)size * 0xff51afd7ed558ccdULL);

	x ^= x >> 30;
	x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 31;
	return (uint32_t)(x & CMP_HINTS_BLOOM_MASK);
}

/*
 * Test-and-set both bloom bits for the tuple.  Returns true when both
 * bits were already set -- the tuple has been seen within the current
 * bloom window, so the caller can skip pool_add_locked.  A miss on
 * either bit returns false AND leaves both bits set, so the next
 * encounter with the same tuple hits.
 */
static bool cmp_hints_bloom_check_and_set(struct cmp_hints_bloom *b,
					  unsigned long ip,
					  unsigned long val,
					  unsigned int size)
{
	uint32_t i1 = cmp_hints_bloom_h1(ip, val, size);
	uint32_t i2 = cmp_hints_bloom_h2(ip, val, size);
	uint8_t m1 = (uint8_t)(1U << (i1 & 7));
	uint8_t m2 = (uint8_t)(1U << (i2 & 7));
	uint8_t *p1 = &b->bits[i1 >> 3];
	uint8_t *p2 = &b->bits[i2 >> 3];
	bool seen = ((*p1 & m1) != 0) && ((*p2 & m2) != 0);

	*p1 |= m1;
	*p2 |= m2;
	return seen;
}

void cmp_hints_collect(unsigned long *trace_buf, unsigned int nr)
{
	unsigned long count;
	unsigned long i;
	unsigned long skipped = 0;
	struct cmp_hint_pool *pool;
	struct cmp_hints_bloom *bloom = NULL;
	struct childdata *child;

	if (cmp_hints_shm == NULL || trace_buf == NULL)
		return;

	if (nr >= MAX_NR_SYSCALL)
		return;

	pool = &cmp_hints_shm->pools[nr];

	count = __atomic_load_n(&trace_buf[0], __ATOMIC_RELAXED);

	/* Buffer is the per-child KCOV_TRACE_CMP mmap, sized off
	 * KCOV_CMP_BUFFER_SIZE u64 entries.  Truncation accounting lives
	 * in kcov_collect_cmp(); here we just clamp to be defensive. */
	if (count > KCOV_CMP_RECORDS_MAX)
		count = KCOV_CMP_RECORDS_MAX;

	if (count == 0)
		return;

	/* The bloom is per-child storage in struct childdata.  Parent-context
	 * callers (this_child() == NULL) bypass the bloom entirely and fall
	 * back to the original pool-only path; cmp_hints_collect() is only
	 * meant to be driven from kcov_collect_cmp() in the child, so the
	 * fallback is just belt-and-braces. */
	child = this_child();
	if (child != NULL) {
		bloom = &child->cmp_hints_seen;
		if (++bloom->calls >= CMP_HINTS_BLOOM_RESET) {
			memset(bloom->bits, 0, sizeof(bloom->bits));
			bloom->calls = 0;
		}
	}

	pool_lock(pool);
	for (i = 0; i < count; i++) {
		unsigned long *rec = &trace_buf[1 + i * WORDS_PER_CMP];
		unsigned long type = rec[0];
		unsigned long arg1 = rec[1];
		unsigned long arg2 = rec[2];
		unsigned long ip   = rec[3];
		unsigned int size  = 1U << ((type >> KCOV_CMP_SIZE_SHIFT)
					    & KCOV_CMP_SIZE_MASK);

		/* We only care about comparisons where one side is a
		 * compile-time constant — those reveal what the kernel
		 * actually checks for. */
		if (!(type & KCOV_CMP_CONST))
			continue;

		/*
		 * Filter out uninteresting comparison operands inline so the
		 * compiler can fold the per-record check to a couple of
		 * branches: skip 0/1/2/3 (caught by the ~3UL mask going to 0)
		 * and the all-ones sentinel.
		 */
		if (((arg1 & ~3UL) != 0) && (arg1 != (unsigned long) -1)) {
			if (bloom != NULL &&
			    cmp_hints_bloom_check_and_set(bloom, ip, arg1, size))
				skipped++;
			else
				pool_add_locked(pool, ip, arg1, size);
		}
		if (((arg2 & ~3UL) != 0) && (arg2 != (unsigned long) -1)) {
			if (bloom != NULL &&
			    cmp_hints_bloom_check_and_set(bloom, ip, arg2, size))
				skipped++;
			else
				pool_add_locked(pool, ip, arg2, size);
		}
	}
	pool_unlock(pool);

	if (skipped != 0 && kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hints_bloom_skipped, skipped,
				   __ATOMIC_RELAXED);
}

bool cmp_hints_try_get(unsigned int nr, unsigned long *out)
{
	struct cmp_hint_pool *pool;
	unsigned int count;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	pool = &cmp_hints_shm->pools[nr];

	/*
	 * Lockless read.  Multiple children fuzzing the same syscall would
	 * otherwise serialize on pool->lock just to grab one hint.
	 *
	 * Tolerated race: a stale count snapshot still indexes a populated
	 * slot — count is monotonic up to the CMP_HINTS_PER_SYSCALL cap, and
	 * once full it stops moving (full-pool eviction overwrites in place).
	 * The per-entry .value field is a naturally-aligned unsigned long, so
	 * a concurrent eviction yields either the pre- or post-overwrite
	 * value at the hardware level; both are valid hints that lived in
	 * the pool.
	 *
	 * For fuzzer hints this is benign — values are direct unsigned longs
	 * substituted as syscall args, never dereferenced.  We do not refresh
	 * the entry's last_used field on lookup: the LRU stamp tracks
	 * insertion freshness from cmp_hints_collect(), which is what the
	 * dedup-vs-eviction policy is built around.
	 */
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0)
		return false;

	*out = pool->entries[rand() % count].value;
	return true;
}

/*
 * Warm-start persistence.
 *
 * CMP records are expensive to gather -- each one requires the kernel
 * to actually execute a comparison against a syscall-derived input, so
 * the pool grows orders of magnitude slower than the kcov bitmap.  A
 * cold start throws away every learned constant and the first windows
 * after restart inject no hints at all.  Persisting the pool across
 * runs lets a long-running fuzz session reach steady state immediately
 * on restart instead of re-paying the warm-up cost every time.
 *
 * On-disk layout mirrors the in-memory shape: a fixed-size header
 * followed by MAX_NR_SYSCALL pool records, each a count + generation
 * + a fixed CMP_HINTS_PER_SYSCALL slice of explicitly-sized entries
 * (uint64 value, uint64 cmp_ip, uint32 size, uint32 last_used).
 * Fixed layout keeps the load path a single contiguous read and the
 * CRC computation a single contiguous range, at the cost of some
 * zero-padded slots in syscalls whose pools are not full.
 *
 * Validity is gated on the kallsyms-sha256 fingerprint computed by
 * kcov_get_kernel_fp() -- the same fingerprint the kcov bitmap uses,
 * so a rebuilt kernel invalidates both files in lock-step.  IP-keyed
 * hints would otherwise be meaningless against a binary with a
 * different function layout.
 */
#define CMP_HINTS_FILE_MAGIC	0x4348505FU	/* "CHP_" */
/* Bumped to 2 when CMP_HINTS_PER_SYSCALL halved from 32 to 16: the on-
 * disk pool slice is a fixed CMP_HINTS_PER_SYSCALL-wide array, so the
 * payload layout is not backward-compatible.  The per_syscall mismatch
 * gate in cmp_hints_load_file would also catch this on its own, but a
 * version-level guard makes the cold-start reason explicit in the log
 * and leaves a hook for any future schema changes that don't ride on
 * top of a constant change. */
#define CMP_HINTS_FILE_VERSION	2U

struct cmp_hints_entry_ondisk {
	uint64_t value;
	uint64_t cmp_ip;
	uint32_t size;
	uint32_t last_used;
};

struct cmp_hints_pool_ondisk {
	uint32_t count;
	uint32_t generation;
	struct cmp_hints_entry_ondisk entries[CMP_HINTS_PER_SYSCALL];
};

struct cmp_hints_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t max_syscall;		/* MAX_NR_SYSCALL at file-build time */
	uint32_t per_syscall;		/* CMP_HINTS_PER_SYSCALL at file-build time */
	uint32_t entry_size;		/* sizeof(struct cmp_hints_entry_ondisk) */
	uint32_t payload_crc32;
	uint64_t payload_bytes;		/* sizeof(struct cmp_hints_pool_ondisk) * max_syscall */
	uint8_t  kallsyms_sha256[32];
};

unsigned long cmp_hints_load_rejected_entries;

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Same algorithm
 * kcov-bitmap / minicorpus / healer use; kept local so a future
 * divergence in any one persistence format's checksum doesn't ripple
 * across the others. */
static uint32_t cmp_hints_crc32(const void *buf, size_t len)
{
	static uint32_t table[256];
	static bool table_built;
	const uint8_t *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;

	if (!table_built) {
		uint32_t c;
		unsigned int n, k;

		for (n = 0; n < 256; n++) {
			c = n;
			for (k = 0; k < 8; k++)
				c = (c & 1) ? (0xedb88320U ^ (c >> 1)) : (c >> 1);
			table[n] = c;
		}
		table_built = true;
	}

	for (i = 0; i < len; i++)
		crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);

	return crc ^ 0xffffffffU;
}

static ssize_t cmp_hints_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = write(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		left -= n;
	}
	return (ssize_t)len;
}

static ssize_t cmp_hints_read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = read(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		p += n;
		left -= n;
	}
	return (ssize_t)(len - left);
}

/* Parent-private scratch buffer for the per-pool snapshot phase of
 * cmp_hints_serialise().  cmp_hints_save_file (the sole caller) only
 * runs in parent context -- from cmp_hints_maybe_snapshot()'s stats-tick
 * path and from the trinity.c shutdown save -- so a single static
 * buffer is safe and avoids a per-pool malloc on the snapshot path. */
static struct cmp_hint_pool cmp_hints_pool_scratch;

/* Serialise the live shm pools[] into a heap-allocated on-disk buffer.
 *
 * Per pool: lock, memcpy the raw struct into a parent-private scratch
 * copy, unlock, then do the on-disk format translation from the scratch
 * without any lock held.  Holding pool->lock only for the duration of a
 * fixed-size struct copy bounds the critical section to O(sizeof(pool))
 * memory traffic regardless of how full the pool is, instead of the old
 * O(count) field-by-field translation loop.
 *
 * Why this matters: if a child SIGSEGV/SIGABRTs while holding pool->lock
 * during cmp_hints_collect, the parent's snapshot path has to acquire
 * that lock -- and shorter windows mean exponentially fewer crash sites
 * land inside the locked region.  Does not eliminate the leaked-lock
 * race; the broader fix is a pid-owned-lock pattern landing separately. */
static struct cmp_hints_pool_ondisk *cmp_hints_serialise(void)
{
	struct cmp_hints_pool_ondisk *out;
	unsigned int i, j;

	out = calloc(MAX_NR_SYSCALL, sizeof(*out));
	if (out == NULL)
		return NULL;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		struct cmp_hint_pool *pool = &cmp_hints_shm->pools[i];
		unsigned int count;

		pool_lock(pool);
		memcpy(&cmp_hints_pool_scratch, pool, sizeof(*pool));
		pool_unlock(pool);

		count = cmp_hints_pool_scratch.count;
		if (count > CMP_HINTS_PER_SYSCALL)
			count = CMP_HINTS_PER_SYSCALL;
		out[i].count = count;
		out[i].generation = cmp_hints_pool_scratch.generation;
		for (j = 0; j < count; j++) {
			out[i].entries[j].value     = cmp_hints_pool_scratch.entries[j].value;
			out[i].entries[j].cmp_ip    = cmp_hints_pool_scratch.entries[j].cmp_ip;
			out[i].entries[j].size      = cmp_hints_pool_scratch.entries[j].size;
			out[i].entries[j].last_used = cmp_hints_pool_scratch.entries[j].last_used;
		}
	}
	return out;
}

static unsigned long cmp_hints_total_generation(void);

/*
 * Dirty-bit proxy for cmp_hints_save_file().  cmp_hints_total_generation()
 * is the sum of pool->generation across all MAX_NR_SYSCALL pools;
 * pool->generation increments once per pool_add_locked() call (insert OR
 * duplicate-refresh), so the sum is monotonic and changes whenever any
 * pool absorbs a comparison record.  When it equals the value at the last
 * successful save, no pool has been touched and the on-disk image is
 * bit-for-bit identical to what we would write.
 *
 * Initialised to ULONG_MAX so the first save in a process always fires;
 * advanced on every successful save and seeded by the warm-start loader
 * (which restores pool->generation from disk) so the
 * load-then-immediate-exit cycle skips its end-of-run save.
 *
 * Parent-private: cmp_hints_maybe_snapshot() and the trinity.c shutdown
 * save are both parent-context callers; no race with children.
 */
static unsigned long cmp_hints_generation_at_last_save = ULONG_MAX;

bool cmp_hints_save_file(const char *path)
{
	struct cmp_hints_file_header hdr;
	struct cmp_hints_pool_ondisk *payload;
	char tmppath[PATH_MAX];
	size_t payload_bytes;
	unsigned long gen_now;
	unsigned long saved_entries;
	unsigned int populated_pools;
	unsigned int i;
	int fd;
	int ret;

	if (path == NULL || cmp_hints_shm == NULL)
		return false;

	gen_now = cmp_hints_total_generation();
	if (gen_now == cmp_hints_generation_at_last_save) {
		output(0, "cmp-hints: snapshot skipped, no pool changes since last save\n");
		return true;
	}

	memset(&hdr, 0, sizeof(hdr));
	if (!kcov_get_kernel_fp(hdr.kallsyms_sha256))
		return false;

	payload = cmp_hints_serialise();
	if (payload == NULL)
		return false;

	/* Counted off the on-disk image so the success log mirrors what
	 * the warm-start loader will print on the next run.  Cheap relative
	 * to the fsync that follows. */
	saved_entries = 0;
	populated_pools = 0;
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		if (payload[i].count > 0) {
			saved_entries += payload[i].count;
			populated_pools++;
		}
	}

	payload_bytes = (size_t)MAX_NR_SYSCALL * sizeof(*payload);

	hdr.magic = CMP_HINTS_FILE_MAGIC;
	hdr.version = CMP_HINTS_FILE_VERSION;
	hdr.max_syscall = MAX_NR_SYSCALL;
	hdr.per_syscall = CMP_HINTS_PER_SYSCALL;
	hdr.entry_size = (uint32_t)sizeof(struct cmp_hints_entry_ondisk);
	hdr.payload_bytes = payload_bytes;
	hdr.payload_crc32 = cmp_hints_crc32(payload, payload_bytes);

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		free(payload);
		return false;
	}

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		free(payload);
		return false;
	}

	/* Neutralise any fuzzer-installed umask so the save mode is 0644. */
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		free(payload);
		return false;
	}

	if (cmp_hints_write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (cmp_hints_write_all(fd, payload, payload_bytes) < 0)
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		free(payload);
		return false;
	}
	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		free(payload);
		return false;
	}
	free(payload);
	cmp_hints_generation_at_last_save = gen_now;
	output(0, "cmp-hints: snapshot saved (%lu entries across %u syscalls) to %s\n",
	       saved_entries, populated_pools, path);
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	free(payload);
	return false;
}

/* Per-entry sanity: a valid record has size in {1,2,4,8}, a non-zero
 * IP that looks like a kernel address (high bit set on the archs we
 * care about), and no all-ones sentinel value.  An invalid slot is
 * dropped and bumps cmp_hints_load_rejected_entries; the surrounding
 * pool keeps loading.  cmp_ip is permitted to be zero only at offsets
 * past the persisted count (i.e. the zero-padded tail of the slice). */
static bool cmp_hints_entry_valid(const struct cmp_hints_entry_ondisk *e)
{
	if (e->size != 1 && e->size != 2 && e->size != 4 && e->size != 8)
		return false;
	if (e->cmp_ip == 0 || e->cmp_ip == (uint64_t)-1)
		return false;
	if (e->value == (uint64_t)-1)
		return false;
	return true;
}

bool cmp_hints_load_file(const char *path)
{
	struct cmp_hints_file_header hdr;
	struct cmp_hints_pool_ondisk *payload = NULL;
	uint8_t cur_fp[32];
	size_t payload_bytes;
	uint32_t want_crc;
	unsigned long rejected = 0;
	unsigned long loaded_entries = 0;
	unsigned int populated_pools = 0;
	unsigned int i, j;
	ssize_t n;
	int fd;

	if (path == NULL || cmp_hints_shm == NULL)
		return false;

	if (!kcov_get_kernel_fp(cur_fp)) {
		output(0, "cmp-hints: cannot fingerprint kernel (/proc/kallsyms unavailable) -- warm-start disabled this run\n");
		return false;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			output(0, "cmp-hints: no persisted state at %s -- cold start\n",
			       path);
		else
			output(0, "cmp-hints: open(%s) failed: %s -- cold start\n",
			       path, strerror(errno));
		return false;
	}

	n = cmp_hints_read_all(fd, &hdr, sizeof(hdr));
	if (n != (ssize_t)sizeof(hdr)) {
		output(0, "cmp-hints: header truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, sizeof(hdr));
		(void)close(fd);
		return false;
	}

	if (hdr.magic != CMP_HINTS_FILE_MAGIC) {
		output(0, "cmp-hints: file magic 0x%08x != expected 0x%08x at %s -- cold start\n",
		       hdr.magic, CMP_HINTS_FILE_MAGIC, path);
		(void)close(fd);
		return false;
	}
	if (hdr.version != CMP_HINTS_FILE_VERSION) {
		output(0, "cmp-hints: file version %u != expected %u at %s -- cold start\n",
		       hdr.version, CMP_HINTS_FILE_VERSION, path);
		(void)close(fd);
		return false;
	}
	if (hdr.max_syscall != MAX_NR_SYSCALL) {
		output(0, "cmp-hints: max_syscall %u != expected %u at %s (file built with a different MAX_NR_SYSCALL) -- cold start\n",
		       hdr.max_syscall, MAX_NR_SYSCALL, path);
		(void)close(fd);
		return false;
	}
	if (hdr.per_syscall != CMP_HINTS_PER_SYSCALL) {
		output(0, "cmp-hints: per_syscall %u != expected %u at %s (file built with a different CMP_HINTS_PER_SYSCALL) -- cold start\n",
		       hdr.per_syscall, CMP_HINTS_PER_SYSCALL, path);
		(void)close(fd);
		return false;
	}
	if (hdr.entry_size != (uint32_t)sizeof(struct cmp_hints_entry_ondisk)) {
		output(0, "cmp-hints: entry_size %u != expected %zu at %s (file built with a different on-disk record layout) -- cold start\n",
		       hdr.entry_size,
		       sizeof(struct cmp_hints_entry_ondisk), path);
		(void)close(fd);
		return false;
	}
	payload_bytes = (size_t)MAX_NR_SYSCALL * sizeof(*payload);
	if (hdr.payload_bytes != payload_bytes) {
		output(0, "cmp-hints: payload_bytes %llu != expected %zu at %s -- cold start\n",
		       (unsigned long long)hdr.payload_bytes, payload_bytes,
		       path);
		(void)close(fd);
		return false;
	}
	if (memcmp(hdr.kallsyms_sha256, cur_fp, sizeof(cur_fp)) != 0) {
		output(0, "cmp-hints: kernel fingerprint mismatch at %s (kallsyms content differs from when the file was written) -- cold start\n",
		       path);
		(void)close(fd);
		return false;
	}

	payload = malloc(payload_bytes);
	if (payload == NULL) {
		output(0, "cmp-hints: payload alloc fail (%zu bytes) -- cold start\n",
		       payload_bytes);
		(void)close(fd);
		return false;
	}
	n = cmp_hints_read_all(fd, payload, payload_bytes);
	if (n != (ssize_t)payload_bytes) {
		output(0, "cmp-hints: payload truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, payload_bytes);
		free(payload);
		(void)close(fd);
		return false;
	}
	(void)close(fd);

	want_crc = cmp_hints_crc32(payload, payload_bytes);
	if (want_crc != hdr.payload_crc32) {
		output(0, "cmp-hints: skipping warm-start of %s -- CRC mismatch\n",
		       path);
		free(payload);
		return false;
	}

	/* Past the header / fingerprint / CRC gates the payload is
	 * considered authoritative against the running kernel; copy into
	 * the shm pools, skipping any individual slot that fails the
	 * per-entry bounds check so a single bit-rotted record doesn't
	 * sink the whole warm-start. */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		struct cmp_hint_pool *pool = &cmp_hints_shm->pools[i];
		struct cmp_hints_pool_ondisk *src = &payload[i];
		unsigned int src_count = src->count;
		unsigned int dst_count = 0;

		if (src_count > CMP_HINTS_PER_SYSCALL) {
			rejected += src_count;
			continue;
		}
		if (src_count == 0)
			continue;

		pool_lock(pool);
		for (j = 0; j < src_count; j++) {
			if (!cmp_hints_entry_valid(&src->entries[j])) {
				rejected++;
				continue;
			}
			pool->entries[dst_count].value     = src->entries[j].value;
			pool->entries[dst_count].cmp_ip    = src->entries[j].cmp_ip;
			pool->entries[dst_count].size      = src->entries[j].size;
			pool->entries[dst_count].last_used = src->entries[j].last_used;
			dst_count++;
		}
		pool->generation = src->generation;
		__atomic_store_n(&pool->count, dst_count, __ATOMIC_RELEASE);
		pool_unlock(pool);

		if (dst_count > 0) {
			loaded_entries += dst_count;
			populated_pools++;
		}
	}

	free(payload);
	cmp_hints_load_rejected_entries = rejected;
	/* Seed the dirty-bit baseline so a load-then-immediate-exit cycle
	 * skips the redundant end-of-run save.  The load loop already restored
	 * each pool->generation from disk, so the current sum exactly reflects
	 * the just-loaded state. */
	cmp_hints_generation_at_last_save = cmp_hints_total_generation();
	output(0, "cmp-hints: loaded %lu entries across %u syscalls from %s%s\n",
	       loaded_entries, populated_pools, path,
	       rejected ? " (rejected entries on warm-start: see counter)" : "");
	if (rejected != 0)
		output(0, "cmp-hints: %lu on-disk entries rejected by per-slot validation\n",
		       rejected);
	return true;
}

const char *cmp_hints_default_path(void)
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
#elif defined(__powerpc64__)
	arch = "ppc64";
#elif defined(__powerpc__)
	arch = "ppc";
#elif defined(__s390x__)
	arch = "s390x";
#elif defined(__mips__)
	arch = "mips";
#elif defined(__sparc__)
	arch = "sparc";
#elif defined(__riscv) || defined(__riscv__)
	arch = "riscv64";
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
	for (nl = release; *nl; nl++) {
		if (*nl == '/')
			*nl = '_';
	}

	if (xdg && xdg[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			       "%s/trinity/cmp-hints", xdg);
	else if (home && home[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			       "%s/.cache/trinity/cmp-hints", home);
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
 * (main_loop's stats tick), so the snapshot state lives in parent-
 * private statics -- no CAS race with children to worry about.
 *
 * Cadence is driven off the sum of pool->generation across all
 * MAX_NR_SYSCALL pools.  generation increments on every insertion or
 * duplicate-refresh under pool->lock; summing it gives a cheap
 * monotonically-non-decreasing proxy for "how many CMP records did the
 * children fold into the pool since we last snapshotted".  Recomputing
 * the sum on every tick is O(MAX_NR_SYSCALL) of plain unsigned-int
 * reads, well below the tick budget.
 */
static char cmp_hints_snapshot_path[PATH_MAX];
static bool cmp_hints_snapshot_enabled;
static unsigned long cmp_hints_generation_at_last_snapshot;
static time_t cmp_hints_last_snapshot_time;

static unsigned long cmp_hints_total_generation(void)
{
	unsigned long sum = 0;
	unsigned int i;

	if (cmp_hints_shm == NULL)
		return 0;
	for (i = 0; i < MAX_NR_SYSCALL; i++)
		sum += cmp_hints_shm->pools[i].generation;
	return sum;
}

void cmp_hints_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(cmp_hints_snapshot_path))
		return;
	memcpy(cmp_hints_snapshot_path, path, len + 1);
	cmp_hints_snapshot_enabled = true;
	cmp_hints_last_snapshot_time = time(NULL);
	cmp_hints_generation_at_last_snapshot = cmp_hints_total_generation();
}

void cmp_hints_maybe_snapshot(void)
{
	unsigned long gen_now;
	time_t now;

	if (!cmp_hints_snapshot_enabled || cmp_hints_shm == NULL)
		return;

	gen_now = cmp_hints_total_generation();
	now = time(NULL);

	if (gen_now < cmp_hints_generation_at_last_snapshot
			+ CMP_HINTS_SNAPSHOT_NEW &&
	    now < cmp_hints_last_snapshot_time
			+ (time_t)CMP_HINTS_SNAPSHOT_INTERVAL_SEC)
		return;

	if (cmp_hints_save_file(cmp_hints_snapshot_path)) {
		cmp_hints_generation_at_last_snapshot = gen_now;
		cmp_hints_last_snapshot_time = now;
	}
}
