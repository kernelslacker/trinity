/*
 * Warm-start persistence for the cmp-hints pool.
 *
 * CMP records grow slowly (each one requires a kernel-side comparison
 * against a syscall-derived input), so a cold start throws away every
 * learned constant and the first windows after restart inject none.
 * Persisting the pool across runs lets a long-running fuzz session
 * reach steady state immediately on restart.  The on-disk layout is
 * fixed-size (header + MAX_NR_SYSCALL * 2 pool records) so the load
 * path is one contiguous read and the CRC is one contiguous range.
 * Validity is gated on the kallsyms-sha256 fingerprint and the writer's
 * kaslr_base so a rebuilt or shifted kernel forces a cold start rather
 * than serving stale IP-keyed hints.
 *
 * cmp_hints_maybe_snapshot() is the parent-tick mid-run hook; the
 * generation-at-last-save and snapshot-cadence statics live here so
 * only this TU can advance the dirty-bit baseline.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "kcov.h"
#include "persist-util.h"
#include "pids.h"
#include "shm.h"
#include "tables.h"
#include "utils.h"


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
 * (uint64 value, uint64 cmp_ip, uint32 size, uint32 pad, uint64 last_used).
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
/* Bumped to 3 (2026-05-26): the per-entry last_used field widened
 * from uint32_t to uint64_t to match the in-memory pool clock that
 * no longer wraps on long-running fuzz sessions.  The on-disk struct
 * grew by 4 bytes, so the payload layout is not backward-compatible;
 * older snapshots are rejected via this version gate and trigger a
 * cold start (which the warm-start path treats as benign). */
/* Bumped to 4 (2026-05-30): the pool array gained an arch dimension
 * (pools[MAX_NR_SYSCALL][2]), so the payload now carries 2 * MAX_NR_SYSCALL
 * pool slots laid out as the natural interleaving of the 2D array
 * (pools[i][0] followed by pools[i][1] for each i).  Existing v3
 * snapshots are uniarch-shaped and are rejected via this version
 * gate; cold start is treated as benign by the warm-start path. */
/* Bumped to 5: per-entry cmp_ip is now canonicalised against the
 * runtime KASLR base (kcov_canon_cmp_ip) before pool insert, and the
 * header carries the writer's kcov_kaslr_base so the load path can
 * reject a canonical-vs-raw mismatch the way the kcov-bitmap header
 * does.  v4 files were keyed by raw PCs; warm-loading them against a
 * v5 binary would either read raw cmp_ip into a canonical pool or
 * vice versa, silently aliasing every learned constant.  The header
 * grew by 8 bytes (kaslr_base appended after kallsyms_sha256); the
 * payload layout (cmp_hints_pool_ondisk / cmp_hints_entry_ondisk) is
 * unchanged. */
#define CMP_HINTS_FILE_VERSION	5U

struct cmp_hints_entry_ondisk {
	uint64_t value;
	uint64_t cmp_ip;
	uint32_t size;
	uint32_t pad;
	uint64_t last_used;
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
	uint64_t kaslr_base;		/* v5: runtime _text base at save time.
					 * Zero means the writer could not resolve
					 * the base and the persisted cmp_ip values
					 * are raw runtime PCs.  The load path
					 * rejects when (hdr.kaslr_base != 0) XOR
					 * (current kcov_kaslr_base != 0) -- a
					 * canonical-vs-raw mix would silently
					 * alias the warm-loaded (cmp_ip, value,
					 * size) keys against the live pool. */
};

unsigned long cmp_hints_load_rejected_entries;

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
	unsigned int i, a, j;

	/* Flat array of 2 * MAX_NR_SYSCALL slots indexed [i * 2 + a],
	 * matching the natural memory layout of pools[i][a]. */
	out = calloc((size_t)MAX_NR_SYSCALL * 2, sizeof(*out));
	if (out == NULL)
		return NULL;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		for (a = 0; a < 2; a++) {
			struct cmp_hint_pool *pool = &cmp_hints_shm->pools[i][a];
			struct cmp_hints_pool_ondisk *slot = &out[i * 2 + a];
			unsigned int count;

			pool_lock(pool);
			memcpy(&cmp_hints_pool_scratch, pool, sizeof(*pool));
			pool_unlock(pool);

			count = cmp_hints_pool_scratch.count;
			/* Route the count check through the gate so a stomped
			 * pool observed for the first time from the save path
			 * still records the channel (count_oob + canary
			 * counters) and latches pool->corrupted -- otherwise a
			 * stomp landing inside a save window leaves no trace
			 * and the bogus entries get serialised behind a count
			 * clamped down to the cap, surviving the loader's
			 * per-entry validator and reappearing on next start. */
			if (cmp_hints_pool_corrupted(pool, count)) {
				slot->count = 0;
				slot->generation = 0;
				continue;
			}
			slot->count = count;
			slot->generation = cmp_hints_pool_scratch.generation;
			for (j = 0; j < count; j++) {
				slot->entries[j].value     = cmp_hints_pool_scratch.entries[j].value;
				slot->entries[j].cmp_ip    = cmp_hints_pool_scratch.entries[j].cmp_ip;
				slot->entries[j].size      = cmp_hints_pool_scratch.entries[j].size;
				slot->entries[j].last_used = cmp_hints_pool_scratch.entries[j].last_used;
			}
		}
	}
	return out;
}

static unsigned long cmp_hints_total_generation(void);

/*
 * Dirty-bit proxy for cmp_hints_save_file().  cmp_hints_total_generation()
 * is the sum of pool->generation across all MAX_NR_SYSCALL pools;
 * pool->generation increments only when pool content actually changes
 * (fresh insert or evict-replace), NOT on a dedup-refresh that only
 * bumps an existing entry's last_used stamp.  The sum is therefore
 * monotonic and changes precisely when the on-disk payload would
 * differ from what was last written; when it equals the value at the
 * last successful save, no pool has been touched and the snapshot can
 * be skipped.
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
	 * to the fsync that follows.  Walk the full 2 * MAX_NR_SYSCALL slot
	 * count so the per-arch populated slots are surfaced individually
	 * rather than collapsed back to per-nr. */
	saved_entries = 0;
	populated_pools = 0;
	for (i = 0; i < MAX_NR_SYSCALL * 2; i++) {
		if (payload[i].count > 0) {
			saved_entries += payload[i].count;
			populated_pools++;
		}
	}

	payload_bytes = (size_t)MAX_NR_SYSCALL * 2 * sizeof(*payload);

	hdr.magic = CMP_HINTS_FILE_MAGIC;
	hdr.version = CMP_HINTS_FILE_VERSION;
	hdr.max_syscall = MAX_NR_SYSCALL;
	hdr.per_syscall = CMP_HINTS_PER_SYSCALL;
	hdr.entry_size = (uint32_t)sizeof(struct cmp_hints_entry_ondisk);
	hdr.payload_bytes = payload_bytes;
	hdr.payload_crc32 = crc32(payload, payload_bytes);
	/* Mirror the kcov-bitmap header's kaslr_base contract.  Zero is the
	 * "raw cmp_ip values, KASLR base lookup failed at save time" sentinel;
	 * the load path uses the (!= 0) XOR check below to refuse a cross-
	 * mode warm-load.  Stamping the value (not just a flag) leaves the
	 * door open for an offline tool to spot a base shift even between
	 * two canonical-mode runs. */
	hdr.kaslr_base = kcov_kaslr_base_value();

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)mypid());
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

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (write_all(fd, payload, payload_bytes) < 0)
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
 * non-sentinel cmp_ip, and no all-ones sentinel value.  An invalid
 * slot is dropped and bumps cmp_hints_load_rejected_entries; the
 * surrounding pool keeps loading.  cmp_ip is permitted to be zero
 * only at offsets past the persisted count (i.e. the zero-padded
 * tail of the slice).  Under canonical mode (kcov_kaslr_base != 0
 * at save time) the on-disk cmp_ip is a small offset from the
 * runtime _text base, not a high-half kernel address; the zero /
 * all-ones gates here stay correct in either mode because they
 * reject the same two sentinels. */
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

/*
 * Phase 1 of cmp_hints_load_file(): the open + header-validation
 * gauntlet.  Performs the cheap preflight (null guards, stale-tmp
 * sweep, kallsyms fingerprint capture), opens the persisted state
 * file, reads the on-disk header, and checks every field against
 * the running build (magic, version, max_syscall, per_syscall,
 * entry_size, payload_bytes, and finally the SHA-256 of
 * /proc/kallsyms).  Each rejection emits the same diagnostic line
 * as the original inline code and trips a cold start.
 *
 * On success returns true with *hdr filled and *fd_out holding an
 * open file descriptor positioned just past the header (the caller
 * owns the fd and must close it as part of the payload phase).
 * On failure returns false with no resources held by the caller --
 * if the fd was opened the helper closed it before returning.
 */
static bool cmp_hints_load_file_header(const char *path,
				       struct cmp_hints_file_header *hdr,
				       int *fd_out)
{
	uint8_t cur_fp[32];
	size_t payload_bytes;
	ssize_t n;
	int fd;

	if (path == NULL || cmp_hints_shm == NULL)
		return false;

	persist_sweep_stale_tmp(path);

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

	n = read_all(fd, hdr, sizeof(*hdr));
	if (n != (ssize_t)sizeof(*hdr)) {
		output(0, "cmp-hints: header truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, sizeof(*hdr));
		(void)close(fd);
		return false;
	}

	if (hdr->magic != CMP_HINTS_FILE_MAGIC) {
		output(0, "cmp-hints: file magic 0x%08x != expected 0x%08x at %s -- cold start\n",
		       hdr->magic, CMP_HINTS_FILE_MAGIC, path);
		(void)close(fd);
		return false;
	}
	if (hdr->version != CMP_HINTS_FILE_VERSION) {
		output(0, "cmp-hints: file version %u != expected %u at %s -- cold start\n",
		       hdr->version, CMP_HINTS_FILE_VERSION, path);
		(void)close(fd);
		return false;
	}
	if (hdr->max_syscall != MAX_NR_SYSCALL) {
		output(0, "cmp-hints: max_syscall %u != expected %u at %s (file built with a different MAX_NR_SYSCALL) -- cold start\n",
		       hdr->max_syscall, MAX_NR_SYSCALL, path);
		(void)close(fd);
		return false;
	}
	if (hdr->per_syscall != CMP_HINTS_PER_SYSCALL) {
		output(0, "cmp-hints: per_syscall %u != expected %u at %s (file built with a different CMP_HINTS_PER_SYSCALL) -- cold start\n",
		       hdr->per_syscall, CMP_HINTS_PER_SYSCALL, path);
		(void)close(fd);
		return false;
	}
	if (hdr->entry_size != (uint32_t)sizeof(struct cmp_hints_entry_ondisk)) {
		output(0, "cmp-hints: entry_size %u != expected %zu at %s (file built with a different on-disk record layout) -- cold start\n",
		       hdr->entry_size,
		       sizeof(struct cmp_hints_entry_ondisk), path);
		(void)close(fd);
		return false;
	}
	payload_bytes = (size_t)MAX_NR_SYSCALL * 2 *
			sizeof(struct cmp_hints_pool_ondisk);
	if (hdr->payload_bytes != payload_bytes) {
		output(0, "cmp-hints: payload_bytes %llu != expected %zu at %s -- cold start\n",
		       (unsigned long long)hdr->payload_bytes, payload_bytes,
		       path);
		(void)close(fd);
		return false;
	}
	if (memcmp(hdr->kallsyms_sha256, cur_fp, sizeof(cur_fp)) != 0) {
		output(0, "cmp-hints: kernel fingerprint mismatch at %s (kallsyms content differs from when the file was written) -- cold start\n",
		       path);
		(void)close(fd);
		return false;
	}
	/* Pool entries are keyed by canonical cmp_ip (raw runtime PC minus
	 * the writer's KASLR base) when hdr->kaslr_base != 0, and by raw
	 * PC otherwise.  This run's collector applies the same transform
	 * against the local kcov_kaslr_base, so the two must agree on
	 * whether canonicalisation is in effect at all -- any XOR mismatch
	 * means one side is canonical and the other raw, and the
	 * (cmp_ip, value, size) keys would silently disagree.  Both-
	 * canonical (regardless of which base each used) and both-raw are
	 * accepted; the cmp_ip keys line up because each side strips its
	 * own local base.  Mirrors the kcov-bitmap warm-start guard. */
	if ((hdr->kaslr_base != 0) != (kcov_kaslr_base_value() != 0)) {
		output(0, "cmp-hints: canonicalisation mismatch at %s (file kaslr_base=0x%llx, current=0x%llx) -- refusing stale pool, cold start\n",
		       path,
		       (unsigned long long)hdr->kaslr_base,
		       (unsigned long long)kcov_kaslr_base_value());
		(void)close(fd);
		return false;
	}

	*fd_out = fd;
	return true;
}

/*
 * Phase 2 of cmp_hints_load_file(): the payload allocation, read,
 * and CRC verification.  Takes ownership of the fd handed off by
 * cmp_hints_load_file_header() -- on every exit path the fd is
 * closed exactly once, matching the original inline lifecycle
 * (close after a successful read_all, close after the alloc-fail
 * / read-fail branches).  payload_bytes is recomputed locally
 * from MAX_NR_SYSCALL and the on-disk record size; the header
 * phase already validated hdr->payload_bytes against that same
 * expression, so the two values are equal by construction.
 *
 * On success returns true with *payload_out pointing at a
 * freshly malloc'd buffer the caller owns and must free.  On
 * failure returns false with no resources held by the caller --
 * any allocation made by the helper has already been free()d and
 * the fd is closed.
 */
static bool cmp_hints_load_file_payload(const char *path, int fd,
					const struct cmp_hints_file_header *hdr,
					struct cmp_hints_pool_ondisk **payload_out)
{
	struct cmp_hints_pool_ondisk *payload;
	size_t payload_bytes;
	uint32_t want_crc;
	ssize_t n;

	payload_bytes = (size_t)MAX_NR_SYSCALL * 2 * sizeof(*payload);
	payload = malloc(payload_bytes);
	if (payload == NULL) {
		output(0, "cmp-hints: payload alloc fail (%zu bytes) -- cold start\n",
		       payload_bytes);
		(void)close(fd);
		return false;
	}
	n = read_all(fd, payload, payload_bytes);
	if (n != (ssize_t)payload_bytes) {
		output(0, "cmp-hints: payload truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, payload_bytes);
		free(payload);
		(void)close(fd);
		return false;
	}
	(void)close(fd);

	want_crc = crc32(payload, payload_bytes);
	if (want_crc != hdr->payload_crc32) {
		output(0, "cmp-hints: skipping warm-start of %s -- CRC mismatch\n",
		       path);
		free(payload);
		return false;
	}

	*payload_out = payload;
	return true;
}

/*
 * Phase 3 of cmp_hints_load_file(): copy the validated payload
 * into the in-memory shm pools.  Past the header / fingerprint /
 * CRC gates the payload is considered authoritative against the
 * running kernel; this loop still skips any individual slot that
 * fails the per-entry bounds check so a single bit-rotted record
 * doesn't sink the whole warm-start.  The payload is a flat
 * array of 2 * MAX_NR_SYSCALL slots laid out as [i * 2 + a]
 * matching the memory layout of pools[i][a]; the inner do32
 * dimension is folded into a flat walk here for symmetry with
 * the serialise path.
 *
 * Counters are returned via out-params: loaded_entries is the
 * sum of successfully copied slots, populated_pools is the
 * number of pools that received at least one entry, and rejected
 * accumulates both whole-pool drops (src_count past the cap) and
 * per-slot validation failures.
 */
static void cmp_hints_load_file_restore_pools(const struct cmp_hints_pool_ondisk *payload,
					      unsigned long *loaded_entries_out,
					      unsigned int *populated_pools_out,
					      unsigned long *rejected_out)
{
	unsigned long loaded_entries = 0;
	unsigned long rejected = 0;
	unsigned int populated_pools = 0;
	unsigned int i, j;

	for (i = 0; i < MAX_NR_SYSCALL * 2; i++) {
		unsigned int nr = i / 2;
		unsigned int a = i & 1;
		struct cmp_hint_pool *pool = &cmp_hints_shm->pools[nr][a];
		const struct cmp_hints_pool_ondisk *src = &payload[i];
		unsigned int src_count = src->count;
		unsigned int dst_count = 0;
		uint64_t max_stamp = 0;

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
			if (src->entries[j].last_used > max_stamp)
				max_stamp = src->entries[j].last_used;
			dst_count++;
		}
		__atomic_store_n(&pool->generation, src->generation,
				 __ATOMIC_RELAXED);
		/* Seed the per-pool LRU clock to the max last_used we just loaded
		 * so fresh inserts after warm-start get strictly larger stamps
		 * and don't appear LRU-older than the warm-started entries (which
		 * would invert the eviction order and let new traffic immediately
		 * evict the just-loaded pool). */
		pool->last_used_stamp = max_stamp;
		__atomic_store_n(&pool->count, dst_count, __ATOMIC_RELEASE);
		pool_unlock(pool);

		if (dst_count > 0) {
			loaded_entries += dst_count;
			populated_pools++;
		}
	}

	*loaded_entries_out = loaded_entries;
	*populated_pools_out = populated_pools;
	*rejected_out = rejected;
}

/*
 * Phase 4 of cmp_hints_load_file(): post-restore bookkeeping and
 * the operator-facing summary lines.  Stamps the global
 * rejected-entries counter with whatever the restore loop
 * accumulated, seeds the dirty-bit baseline so a
 * load-then-immediate-exit cycle skips the redundant end-of-run
 * save (the restore loop already populated each
 * pool->generation from disk, so the live sum exactly reflects
 * the just-loaded state), and emits the one-line summary plus
 * the optional second line that fires only when at least one
 * record was rejected.  The payload buffer is freed by the
 * orchestrator before this helper runs so the success path
 * holds no transient allocations during the output() calls.
 */
static void cmp_hints_load_file_finalize(const char *path,
					 unsigned long loaded_entries,
					 unsigned int populated_pools,
					 unsigned long rejected)
{
	cmp_hints_load_rejected_entries = rejected;
	cmp_hints_generation_at_last_save = cmp_hints_total_generation();
	output(0, "cmp-hints: loaded %lu entries across %u syscalls from %s%s\n",
	       loaded_entries, populated_pools, path,
	       rejected ? " (rejected entries on warm-start: see counter)" : "");
	if (rejected != 0)
		output(0, "cmp-hints: %lu on-disk entries rejected by per-slot validation\n",
		       rejected);
}

bool cmp_hints_load_file(const char *path)
{
	struct cmp_hints_file_header hdr;
	struct cmp_hints_pool_ondisk *payload = NULL;
	unsigned long rejected = 0;
	unsigned long loaded_entries = 0;
	unsigned int populated_pools = 0;
	int fd;

	if (!cmp_hints_load_file_header(path, &hdr, &fd))
		return false;

	if (!cmp_hints_load_file_payload(path, fd, &hdr, &payload))
		return false;

	cmp_hints_load_file_restore_pools(payload, &loaded_entries,
					  &populated_pools, &rejected);

	free(payload);
	/* Union the just-restored per-nr pool entries into the fleet-
	 * wide shared cmp_ip tier so a follow-up cold per-nr lookup can
	 * warm-start from constants that ANY sibling syscall learned in
	 * the previous run.  Runs after the per-nr restore so every
	 * loaded entry is visible via pool->entries[]; the tier's dedup
	 * collapses cross-nr duplicates so a hot entry-path IP shared
	 * across many syscalls lands in ONE bucket. */
	cmp_shared_tier_populate_from_pools();
	cmp_hints_load_file_finalize(path, loaded_entries, populated_pools,
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
 * MAX_NR_SYSCALL pools.  generation increments only on real pool
 * content changes (insert or evict-replace) under pool->lock; summing
 * it gives a cheap monotonically-non-decreasing proxy for "how many
 * novel CMP records did the children fold into the pool since we last
 * snapshotted".  Recomputing the sum on every tick is
 * O(MAX_NR_SYSCALL) of plain unsigned-int reads, well below the tick
 * budget.
 */
static char cmp_hints_snapshot_path[PATH_MAX];
static bool cmp_hints_snapshot_enabled;
static unsigned long cmp_hints_generation_at_last_snapshot;
static time_t cmp_hints_last_snapshot_time;

static unsigned long cmp_hints_total_generation(void)
{
	unsigned long sum = 0;
	unsigned int i, a;

	if (cmp_hints_shm == NULL)
		return 0;
	for (i = 0; i < MAX_NR_SYSCALL; i++)
		for (a = 0; a < 2; a++)
			sum += __atomic_load_n(&cmp_hints_shm->pools[i][a].generation,
					       __ATOMIC_RELAXED);
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
	/* CLOCK_MONOTONIC seconds: the maybe-snapshot cadence compares this
	 * against a monotonic `now`, so a wall-clock backward step cannot
	 * starve the time gate and a forward step cannot fire a burst. */
	cmp_hints_last_snapshot_time =
		(time_t)(mono_ns() / 1000000000ULL);
	cmp_hints_generation_at_last_snapshot = cmp_hints_total_generation();
}

void cmp_hints_maybe_snapshot(void)
{
	unsigned long gen_now;
	time_t now;

	if (!cmp_hints_snapshot_enabled || cmp_hints_shm == NULL)
		return;

	gen_now = cmp_hints_total_generation();
	now = (time_t)(mono_ns() / 1000000000ULL);

	/* Both gates must expire before a snapshot fires: enough generations
	 * (so we don't write a near-identical payload to disk) AND enough
	 * wall time (so a high-churn period doesn't trigger one save per
	 * second).  The original && meant either gate alone could fire;
	 * with generation now advancing only on real content changes the
	 * generation gate stays quiet once the pools saturate, but during
	 * the initial fill it would still over-fire without the time gate. */
	if (gen_now < cmp_hints_generation_at_last_snapshot
			+ CMP_HINTS_SNAPSHOT_NEW ||
	    now < cmp_hints_last_snapshot_time
			+ (time_t)CMP_HINTS_SNAPSHOT_INTERVAL_SEC)
		return;

	if (cmp_hints_save_file(cmp_hints_snapshot_path)) {
		cmp_hints_generation_at_last_snapshot = gen_now;
		cmp_hints_last_snapshot_time = now;
	}
}
