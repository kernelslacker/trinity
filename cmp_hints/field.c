/*
 * Field-scoped CMP-hint attribution.
 *
 * The per-syscall pools attribute a kernel CMP constant to a syscall
 * slot but not to a specific struct field, so a value the kernel
 * compared against (say) clone_args::flags is sprayed back into any
 * broad scalar slot of the same syscall.  This cluster owns the
 * field-scoped pool: hash + probe + insert on the recording side, the
 * cataloged-struct field walker that scans a CMP record against every
 * field-eligible arg, and the init-time end-to-end self-check.
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#include "child-api.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "debug.h"
#include "deferred-free.h"
#include "kcov.h"
#include "locks.h"
#include "random.h"
#include "shm.h"
#include "struct_catalog.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * Field-pool table lookup.  splitmix64-style mix over the key tuple so
 * (nr, do32, arg_idx, field_idx, size) variations spread evenly across
 * buckets and the desc pointer's low bits don't dominate the index.  The
 * result is masked to CMP_FIELD_POOL_BUCKETS so the bucket count can
 * change without touching the hash.
 */
uint32_t cmp_field_pool_hash(const struct struct_desc *desc,
			     unsigned int nr, unsigned int do32,
			     unsigned int arg_idx,
			     unsigned int field_idx,
			     unsigned int size)
{
	uint64_t x = (uint64_t)(uintptr_t) desc;

	x ^= ((uint64_t) nr * 0x9e3779b97f4a7c15ULL);
	x ^= ((uint64_t) arg_idx << 17);
	x ^= ((uint64_t) field_idx * 0xbf58476d1ce4e5b9ULL);
	x ^= ((uint64_t) size << 41);
	x ^= ((uint64_t) do32 << 53);
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	return (uint32_t)(x & (CMP_FIELD_POOL_BUCKETS - 1U));
}

/* Same wild-write gate as cmp_hints_pool_corrupted() but for field pools.
 * Independent latch + counter bumps so a stomp on a field pool is not
 * folded into the per-syscall pool's corruption rate (the two paths
 * write to different parts of cmp_hints_shm and pinpointing which one
 * tripped narrows root-causing wild-write reports). */
bool cmp_field_pool_corrupted(struct cmp_field_pool *pool,
			      unsigned int observed_count)
{
	if (__atomic_load_n(&pool->corrupted, __ATOMIC_RELAXED))
		return true;
	if (observed_count <= CMP_HINTS_PER_SYSCALL)
		return false;
	if (kcov_shm != NULL) {
		__atomic_fetch_add(&kcov_shm->hints_canary.cmp_hints_count_oob, 1UL,
				   __ATOMIC_RELAXED);
		if (pool->canary_lock_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->hints_canary.cmp_hints_canary_lock_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_pre != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->hints_canary.cmp_hints_canary_pre_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->hints_canary.cmp_hints_canary_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
	}
	__atomic_store_n(&pool->corrupted, true, __ATOMIC_RELAXED);
	return true;
}

/* Mirror of pool_add_locked() for the field pool entries[] array.  Same
 * dedup / LRU-eviction discipline -- caller must hold pool->lock. */
static bool cmp_field_pool_insert_locked(struct cmp_field_pool *pool,
				  unsigned long cmp_ip,
				  unsigned long val,
				  unsigned int size)
{
	unsigned int i, count = pool->count;
	uint64_t stamp;
	unsigned int victim;
	uint64_t oldest;

	if (cmp_field_pool_corrupted(pool, count))
		return false;

	stamp = ++pool->last_used_stamp;

	for (i = 0; i < count; i++) {
		struct cmp_hint_entry *e = &pool->entries[i];

		if (e->value == val && e->cmp_ip == cmp_ip && e->size == size) {
			e->last_used = stamp;
			return false;
		}
	}

	if (count < CMP_HINTS_PER_SYSCALL) {
		struct cmp_hint_entry *e = &pool->entries[count];

		e->value = val;
		e->cmp_ip = cmp_ip;
		e->size = size;
		/* Field pools inherit the same fresh-insert / evict-replace
		 * SHADOW-score reset discipline as the per-syscall pool above;
		 * the score field is recording-only because the score-based
		 * feedback selection is shadow for both pools and does not
		 * steer pool selection yet. */
		e->wins = 0;
		e->misses = 0;
		e->last_used = stamp;
		__atomic_fetch_add(&pool->generation, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&pool->count, count + 1, __ATOMIC_RELEASE);
		return true;
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
	pool->entries[victim].wins = 0;
	pool->entries[victim].misses = 0;
	pool->entries[victim].last_used = stamp;
	__atomic_fetch_add(&pool->generation, 1, __ATOMIC_RELAXED);
	return true;
}

void cmp_hints_field_record(unsigned int nr, bool do32, unsigned int arg_idx,
			    const struct struct_desc *desc,
			    unsigned int field_idx, unsigned int size,
			    unsigned long val, unsigned long cmp_ip)
{
	uint32_t h;
	unsigned int probe;
	unsigned int do32_idx = do32 ? 1U : 0U;

	if (cmp_hints_shm == NULL || desc == NULL)
		return;
	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	h = cmp_field_pool_hash(desc, nr, do32_idx, arg_idx, field_idx, size);

	for (probe = 0; probe < CMP_FIELD_POOL_PROBE_MAX; probe++) {
		unsigned int idx = (h + probe) & (CMP_FIELD_POOL_BUCKETS - 1U);
		struct cmp_field_pool *pool = &cmp_hints_shm->field_pools[idx];
		const struct struct_desc *occ;
		bool inserted;

		/* ACQUIRE-load the occupancy gate so a non-NULL desc read is
		 * guaranteed to see the rest of the key the claimer published.
		 * NULL means empty -- candidate for our claim. */
		occ = __atomic_load_n(&pool->key.desc, __ATOMIC_ACQUIRE);
		if (occ != NULL && occ != desc)
			continue;

		lock(&pool->lock);
		/* Re-read under lock so a racing claimer can't slip a different
		 * desc in between our ACQUIRE-load and lock acquire. */
		occ = pool->key.desc;
		if (occ == NULL) {
			/* Claim: fill all key fields, then RELEASE-store desc
			 * last so a reader that ACQUIRE-loads desc sees a
			 * fully-populated key. */
			pool->key.nr = (uint16_t) nr;
			pool->key.do32 = (uint8_t) do32_idx;
			pool->key.arg_idx = (uint8_t) arg_idx;
			pool->key.field_idx = (uint16_t) field_idx;
			pool->key.size = (uint8_t) size;
			__atomic_store_n(&pool->key.desc, desc,
					 __ATOMIC_RELEASE);
		} else if (occ != desc ||
			   pool->key.nr != (uint16_t) nr ||
			   pool->key.do32 != (uint8_t) do32_idx ||
			   pool->key.arg_idx != (uint8_t) arg_idx ||
			   pool->key.field_idx != (uint16_t) field_idx ||
			   pool->key.size != (uint8_t) size) {
			/* Different key at this probe slot; keep walking. */
			unlock(&pool->lock);
			continue;
		}

		inserted = cmp_field_pool_insert_locked(pool, cmp_ip, val, size);
		unlock(&pool->lock);

		if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_field_attr.cmp_field_attribution_found,
					   1UL, __ATOMIC_RELAXED);
			(void) inserted;	/* dedup-refresh is a hit too */
		}
		return;
	}

	/* All probes filled with unrelated keys; advisory pool, drop. */
	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_field_attr.cmp_field_attribution_pool_full,
				   1UL, __ATOMIC_RELAXED);
}

void cmp_hints_field_record_self_check(void)
{
	/* Synthesise an insert against a sentinel desc pointer that can
	 * never collide with a real catalog entry (the catalog is an array
	 * of structs, never the address of the cmp_hints_shm itself), prove
	 * the counter bumps + the bucket claims, then clear the bucket back
	 * to empty so the live table starts clean.  Runs at every fresh
	 * trinity startup so a regression in the recording path surfaces
	 * loudly here rather than hiding behind silent zero counters during
	 * a fuzz run.
	 *
	 * A sentinel address that is non-NULL, canonical-aligned, and
	 * stable for the lifetime of the process: the address of
	 * cmp_hints_shm itself.  Cast through (const struct struct_desc *)
	 * for the key field type; we never deref it.
	 */
	const struct struct_desc *sentinel;
	unsigned int idx;
	unsigned int probe;
	uint32_t h;
	unsigned long before, after;
	struct cmp_field_pool *claimed = NULL;

	if (cmp_hints_shm == NULL || kcov_shm == NULL)
		return;

	sentinel = (const struct struct_desc *)(uintptr_t) cmp_hints_shm;
	before = __atomic_load_n(&kcov_shm->cmp_field_attr.cmp_field_attribution_found,
				 __ATOMIC_RELAXED);

	cmp_hints_field_record(/*nr=*/0, /*do32=*/false, /*arg_idx=*/1,
			       sentinel, /*field_idx=*/0, /*size=*/8,
			       /*val=*/0x5a5a5a5a5a5a5a5aULL,
			       /*cmp_ip=*/0xc0ffee00c0ffee00ULL);

	after = __atomic_load_n(&kcov_shm->cmp_field_attr.cmp_field_attribution_found,
				__ATOMIC_RELAXED);
	if (after != before + 1)
		BUG("cmp_hints: field-record self-check counter did not bump");

	/* Locate the claimed bucket (linear probe from the same hash) and
	 * reset it so the live table starts empty.  Walk the full probe
	 * window because a subsequent self-check that re-hashes the same
	 * sentinel must land on a freshly-empty slot, not the one we just
	 * filled. */
	h = cmp_field_pool_hash(sentinel, 0, 0, 1, 0, 8);
	for (probe = 0; probe < CMP_FIELD_POOL_PROBE_MAX; probe++) {
		idx = (h + probe) & (CMP_FIELD_POOL_BUCKETS - 1U);
		if (cmp_hints_shm->field_pools[idx].key.desc == sentinel) {
			claimed = &cmp_hints_shm->field_pools[idx];
			break;
		}
	}
	if (claimed == NULL)
		BUG("cmp_hints: field-record self-check could not locate claimed bucket");

	/* Reset the claimed bucket back to empty.  The unreachable() inside
	 * BUG() above makes the NULL branch terminal, but gcc's fortify
	 * memset-bounds check on -O2 still complains about deref through a
	 * possibly-NULL pointer; clear the entries[] in a hand loop so the
	 * checker sees the bounded indexing directly. */
	for (probe = 0; probe < CMP_HINTS_PER_SYSCALL; probe++)
		claimed->entries[probe] = (struct cmp_hint_entry){ 0 };
	claimed->count = 0;
	claimed->generation = 0;
	claimed->last_used_stamp = 0;
	claimed->key = (struct cmp_field_pool_key){ 0 };
	/* Roll back the counter so the live table starts at zero -- the
	 * synthetic self-check insert isn't a real field attribution. */
	__atomic_fetch_sub(&kcov_shm->cmp_field_attr.cmp_field_attribution_found, 1UL,
			   __ATOMIC_RELAXED);

	output(0, "KCOV: CMP field-record self-check passed\n");
}

/*
 * Charge one deflected slot to the skip counters of both struct-field
 * scans (field attribution and LEN_CORRELATED), which share the
 * resolution in cmp_hints_field_scan_resolve() below.
 */
static void cmp_field_scan_skip(bool short_alloc)
{
	if (kcov_shm == NULL)
		return;
	if (short_alloc)
		__atomic_fetch_add(
			&kcov_shm->cmp_field_attr.cmp_field_attribution_arg_skipped_short_alloc,
			1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(
			&kcov_shm->cmp_field_attr.cmp_field_attribution_arg_skipped_bad_ptr,
			1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_bad_desc,
		1UL, __ATOMIC_RELAXED);
}

/*
 * Resolve the cataloged INPUT struct args the per-record field scans
 * walk.  Called once per cmp_hints_collect() call: the desc, the
 * buffer and its extent are the same for every CMP record of the call,
 * and the alloc_track extent lookup walks every alloc_track slot for a
 * buffer zmalloc_tracked() did not hand out.  A deflected slot is
 * counted once per call, not once per record.
 *
 * NARROW MVP scope: fixed-size cataloged structs only.  Tagged-union
 * descs (variants != NULL) and buffer-discriminated descs
 * (buffer_discrim_size != 0) are skipped -- the live variant isn't
 * carried in the dispatch_args[] snapshot and re-reading the post-fill
 * buffer to resolve it would race a sibling stomp.
 */
unsigned int cmp_hints_field_scan_resolve(struct syscallrecord *srec,
					  struct syscallentry *entry,
					  unsigned int nr, bool do32,
					  struct cmp_field_scan_slot slots[6])
{
	unsigned int slot;
	unsigned int slot_max;
	unsigned int nr_slots = 0;

	slot_max = entry->num_args;
	if (slot_max > 6)
		slot_max = 6;

	for (slot = 0; slot < slot_max; slot++) {
		enum argtype t = entry->argtype[slot];
		const struct struct_desc *desc;
		const unsigned char *buf;
		unsigned long limit;
		size_t actual_len;

		if (t != ARG_STRUCT_PTR_IN && t != ARG_STRUCT_PTR_INOUT)
			continue;

		desc = struct_arg_lookup(nr, slot + 1, do32, srec);
		if (desc == NULL || desc->struct_size == 0 ||
		    desc->fields == NULL || desc->num_fields == 0)
			continue;

		/* NARROW MVP: skip tagged-union and buffer-discriminated descs.
		 * Variant-scoped attribution needs the live variant choice
		 * which is post-fill state the CMP-time scan can't resolve
		 * safely from the snapshot alone. */
		if (desc->variants != NULL || desc->num_variants != 0 ||
		    desc->buffer_discrim_size != 0)
			continue;

		/* Pointer comes from the dispatch-time snapshot, not live
		 * rec->aN, so a sibling stomp between dispatch and this scan
		 * cannot redirect us at an unrelated buffer.  Shape-gate
		 * before the deref: a NULL / non-canonical / misaligned
		 * snapshot pointer means the snapshot was never written or
		 * the sanitiser handed the kernel something the field scan
		 * can't safely walk.  Bump the dedicated counter so the
		 * occurrence rate is observable. */
		buf = (const unsigned char *)(uintptr_t)
			srec->dispatch_args[slot];
		if (is_corrupt_ptr_shape(buf)) {
			cmp_field_scan_skip(false);
			continue;
		}

		/* Bound the field-walk against the real sanitiser allocation
		 * extent recovered from alloc_track, NOT range_readable_user
		 * (mappability, not allocation bounds) and NOT desc->struct_size
		 * alone (a variable-length / over-large catalog entry can claim
		 * more bytes than the runtime alloc behind @buf actually owns,
		 * walking the scan past the heap chunk and tripping ASAN
		 * heap-buffer-overflow).  Tracked buffers expose their length
		 * via lookup_size; an untracked buffer cannot prove its extent
		 * and we skip the slot entirely (conservative direction).
		 * limit = min(struct_size, actual_len) so a smaller real alloc
		 * tightens the per-field check while an oversized catalog row
		 * still cannot push us off the chunk. */
		actual_len = alloc_track_lookup_size((void *)(uintptr_t)buf);
		if (actual_len == 0) {
			cmp_field_scan_skip(true);
			continue;
		}
		limit = desc->struct_size;
		if ((unsigned long)actual_len < limit)
			limit = (unsigned long)actual_len;

		/*
		 * A tracked alloc-extent does not prove the page is still
		 * mapped readable at scan time.  CMP harvest runs post-
		 * dispatch and the dispatched syscall (brk()/munmap()/
		 * mprotect(), or a sibling consuming the same shared
		 * region) may have dropped or PROT_NONE'd the page holding
		 * @buf between the dispatch-time alloc and this walk.  The
		 * follow-on memcpy() / direct deref inside the field loop
		 * would then SEGV_ACCERR (mapped-but-wrong-perm or freed-
		 * then-recycled VMA) and kill the child mid-collection.
		 *
		 * Same hazard d51f1a67 closed on the field-scoped TIMESPEC
		 * deref via range_readable_user(); apply the same cached-
		 * VMA readability gate over [buf, limit) here.  alloc_track
		 * still owns the size bound (range_readable_user proves
		 * mappability, not allocation extent -- the two invariants
		 * are complementary, exactly the split eea70d8 called out).
		 * On the unreadable path absorb into
		 * cmp_field_attribution_arg_skipped_bad_ptr (the existing
		 * counter for "@buf is not safe to walk"); shape-corruption
		 * and stale-mapping share semantic family from the caller's
		 * point of view -- both mean "skip this slot".
		 */
		if (!range_readable_user(buf, limit)) {
			cmp_field_scan_skip(false);
			continue;
		}

		slots[nr_slots].desc = desc;
		slots[nr_slots].buf = buf;
		slots[nr_slots].limit = limit;
		slots[nr_slots].arg_idx = slot + 1;
		nr_slots++;
	}
	return nr_slots;
}

/*
 * Field-attribution scan for one CMP record.  For each struct arg
 * cmp_hints_field_scan_resolve() returned, walk its fields and -- on a
 * runtime field value matching arg2 -- record the kernel constant arg1
 * into the field-keyed pool via cmp_hints_field_record().  Independent
 * of the scalar RedQueen attribution path; runs as a recording-side
 * accumulator so a future consumer can re-inject the constant at the
 * named field.
 *
 * Array / pointer / length-pair tags are skipped because their
 * sibling-coupled reads need the array-aware attribution path, which
 * lands later.  Only flat scalar tags with size in {1,2,4,8}
 * contribute records here.
 */
void cmp_hints_field_scan_record(const struct cmp_field_scan_slot *slots,
				 unsigned int nr_slots,
				 unsigned int nr, bool do32,
				 unsigned long arg1, unsigned long arg2,
				 unsigned int size, unsigned long cmp_ip)
{
	unsigned int s;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	for (s = 0; s < nr_slots; s++) {
		const struct struct_desc *desc = slots[s].desc;
		const unsigned char *buf = slots[s].buf;
		unsigned long limit = slots[s].limit;
		unsigned int i;

		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_field_attr.cmp_field_attribution_scanned,
				1UL, __ATOMIC_RELAXED);

		for (i = 0; i < desc->num_fields; i++) {
			const struct struct_field *f = &desc->fields[i];
			unsigned long fv;

			/* NARROW MVP: only flat scalar tags.  Array / pointer
			 * / length-pair / aggregate tags need either array-
			 * aware sibling resolution or sub-buffer reads, both
			 * deferred to a follow-up. */
			switch (f->tag) {
			case FT_PTR_BYTES:
			case FT_PTR_ARRAY:
			case FT_PTR_STRUCT:
			case FT_LEN_BYTES:
			case FT_LEN_COUNT:
			case FT_TAGGED_UNION:
			case FT_BPF_PROGRAM:
			case FT_VOCAB:
			case FT_EMBEDDED_STRUCT:
				continue;
			default:
				break;
			}

			if (f->size != size)
				continue;
			/* Per-field cap against the smaller of the cataloged
			 * struct extent and the real alloc extent (limit above).
			 * Cataloged structs whose real alloc is shorter than
			 * struct_size (variable-length tails, over-large catalog
			 * rows) get rejected here before the deref. */
			if ((unsigned long) f->offset + size > limit)
				continue;

			fv = 0;
			switch (size) {
			case 1:
				fv = *(const uint8_t *)(buf + f->offset);
				break;
			case 2: {
				uint16_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			case 4: {
				uint32_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			case 8: {
				uint64_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			}

			if (fv == arg2)
				cmp_hints_field_record(nr, do32,
						       slots[s].arg_idx, desc,
						       i, size, arg1, cmp_ip);
		}
	}
}
