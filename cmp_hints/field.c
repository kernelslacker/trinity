/*
 * Field-scoped CMP-hint attribution and consumption.
 *
 * The per-syscall pools attribute a kernel CMP constant to a syscall
 * slot but not to a specific struct field, so a value the kernel
 * compared against (say) clone_args::flags is sprayed back into any
 * broad scalar slot of the same syscall.  This cluster owns the
 * field-scoped pool: hash + probe + insert on the recording side, the
 * cataloged-struct field walker that scans a CMP record against every
 * field-eligible arg, the init-time end-to-end self-check, and the
 * SHADOW-gated field consumer that the eventual live arm will
 * promote.
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
#include "rnd.h"
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
		__atomic_fetch_add(&kcov_shm->cmp_hints_count_oob, 1UL,
				   __ATOMIC_RELAXED);
		if (pool->canary_lock_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_lock_post_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_pre != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_pre_corrupt,
					   1UL, __ATOMIC_RELAXED);
		if (pool->canary_post != CMP_HINTS_POOL_CANARY)
			__atomic_fetch_add(&kcov_shm->cmp_hints_canary_post_corrupt,
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
			__atomic_fetch_add(&kcov_shm->cmp_field_attribution_found,
					   1UL, __ATOMIC_RELAXED);
			(void) inserted;	/* dedup-refresh is a hit too */
		}
		return;
	}

	/* All probes filled with unrelated keys; advisory pool, drop. */
	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_field_attribution_pool_full,
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
	before = __atomic_load_n(&kcov_shm->cmp_field_attribution_found,
				 __ATOMIC_RELAXED);

	cmp_hints_field_record(/*nr=*/0, /*do32=*/false, /*arg_idx=*/1,
			       sentinel, /*field_idx=*/0, /*size=*/8,
			       /*val=*/0x5a5a5a5a5a5a5a5aULL,
			       /*cmp_ip=*/0xc0ffee00c0ffee00ULL);

	after = __atomic_load_n(&kcov_shm->cmp_field_attribution_found,
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
	__atomic_fetch_sub(&kcov_shm->cmp_field_attribution_found, 1UL,
			   __ATOMIC_RELAXED);

	output(0, "KCOV: CMP field-record self-check passed\n");
}

/*
 * Field-attribution scan for one CMP record.  For each cataloged INPUT
 * struct arg, walk its fields and -- on a runtime field value matching
 * arg2 -- record the kernel constant arg1 into the field-keyed pool
 * via cmp_hints_field_record().  Independent of the scalar RedQueen
 * attribution path above; runs as a recording-side accumulator so a
 * future consumer can re-inject the constant at the named field.
 *
 * NARROW MVP scope: fixed-size cataloged structs only.  Tagged-union
 * descs (variants != NULL) and buffer-discriminated descs
 * (buffer_discrim_size != 0) are skipped -- the live variant isn't
 * carried in the dispatch_args[] snapshot and re-reading the post-fill
 * buffer to resolve it would race a sibling stomp.  Array / pointer /
 * length-pair tags are skipped because their sibling-coupled reads
 * need the array-aware attribution path, which lands later.  Only flat
 * scalar tags with size in {1,2,4,8} contribute records here.
 */
void cmp_hints_field_scan_record(struct syscallrecord *srec,
				 struct syscallentry *entry,
				 unsigned int nr, bool do32,
				 unsigned long arg1, unsigned long arg2,
				 unsigned int size, unsigned long cmp_ip)
{
	unsigned int slot;
	unsigned int slot_max;

	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;
	slot_max = entry->num_args;
	if (slot_max > 6)
		slot_max = 6;

	for (slot = 0; slot < slot_max; slot++) {
		enum argtype t = entry->argtype[slot];
		const struct struct_desc *desc;
		const unsigned char *buf;
		unsigned long limit;
		size_t actual_len;
		unsigned int i;

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
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_field_attribution_arg_skipped_bad_ptr,
					1UL, __ATOMIC_RELAXED);
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
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_field_attribution_arg_skipped_short_alloc,
					1UL, __ATOMIC_RELAXED);
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
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_field_attribution_arg_skipped_bad_ptr,
					1UL, __ATOMIC_RELAXED);
			continue;
		}

		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_field_attribution_scanned,
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
				cmp_hints_field_record(nr, do32, slot + 1, desc,
						       i, size, arg1, cmp_ip);
		}
	}
}
/*
 * SHADOW gate for the field-scoped pool consumer.  Defaults off so the
 * lookup, would-pick / would-miss counters, and the rest of the pick
 * path are wired end-to-end below without the in-buffer overwrite ever
 * firing -- shadow-first observability before the live arm is wired.
 * The follow-up commit will expose this via a CLI flag; today the field
 * pool stays observation-only.
 */
static bool cmp_field_consumer_live_arm;

/*
 * Generator-invariant guard for the field-scoped consumer.  Some keys
 * the field-attribution recorder can populate carry a kernel constant
 * whose injection into the generated struct would break an invariant
 * the generator relies on (union arm selection, length/buffer pairing,
 * pointer-shaped slots, tagged-union discriminators, coupled scalars)
 * and turn every dispatched call into a guaranteed reject.  Classify
 * from EXISTING desc + field metadata; the classifier is observation-
 * only, only ever gates the SHADOW would_pick and bumps a per-reason
 * skip counter.
 *
 * Categories the existing struct-catalog metadata cannot detect and
 * therefore fall through as CMP_FIELD_GUARD_OK (a wider metadata pass
 * on the catalog would be needed to close these; explicitly out of
 * scope here to avoid catalog sprawl):
 *
 *   - Endian-swapped fields (host-order kernel value smashed into a
 *     big-endian on-wire slot) -- no per-field endian tag today.
 *   - Bitfield-packed fields sharing a byte with an unrelated
 *     neighbour -- the catalog schema records offset+size, not bit
 *     ranges within a byte.
 *   - Checksum fields paired with a covered buffer -- FT_LEN_* covers
 *     length pairing but there is no FT_CSUM tag; injecting a value
 *     into a checksum field will desync the same way FT_LEN_* would.
 *   - Fully arbitrary dependent scalars (field-must-equal-sibling,
 *     value-in-enum-derived-from-another-field) beyond the FT_TAGGED_
 *     UNION / FT_VOCAB cases already covered by CMP_FIELD_GUARD_
 *     DEPENDENT.
 */
enum cmp_field_guard_reason {
	CMP_FIELD_GUARD_OK = 0,
	CMP_FIELD_GUARD_VARIANT_LAYOUT,
	CMP_FIELD_GUARD_BUFFER_DISCRIM,
	CMP_FIELD_GUARD_LEN_PAIR,
	CMP_FIELD_GUARD_NESTED_POINTER,
	CMP_FIELD_GUARD_DEPENDENT,
};

static enum cmp_field_guard_reason
cmp_field_key_classify_guard(const struct struct_desc *desc,
			     unsigned int field_idx)
{
	const struct struct_field *f;

	if (desc->variants != NULL || desc->num_variants != 0)
		return CMP_FIELD_GUARD_VARIANT_LAYOUT;
	if (desc->buffer_discrim_size != 0)
		return CMP_FIELD_GUARD_BUFFER_DISCRIM;

	if (desc->fields == NULL || field_idx >= desc->num_fields)
		return CMP_FIELD_GUARD_OK;

	f = &desc->fields[field_idx];
	switch (f->tag) {
	case FT_LEN_BYTES:
	case FT_LEN_COUNT:
		return CMP_FIELD_GUARD_LEN_PAIR;
	case FT_PTR_BYTES:
	case FT_PTR_ARRAY:
	case FT_PTR_STRUCT:
	case FT_EMBEDDED_STRUCT:
	case FT_BPF_PROGRAM:
		return CMP_FIELD_GUARD_NESTED_POINTER;
	case FT_TAGGED_UNION:
	case FT_VOCAB:
		return CMP_FIELD_GUARD_DEPENDENT;
	default:
		return CMP_FIELD_GUARD_OK;
	}
}

static bool cmp_field_key_guard_skip(const struct struct_desc *desc,
				     unsigned int field_idx)
{
	unsigned long *slot;

	if (kcov_shm == NULL)
		return cmp_field_key_classify_guard(desc, field_idx) !=
		       CMP_FIELD_GUARD_OK;

	switch (cmp_field_key_classify_guard(desc, field_idx)) {
	case CMP_FIELD_GUARD_OK:
		return false;
	case CMP_FIELD_GUARD_VARIANT_LAYOUT:
		slot = &kcov_shm->cmp_field_consumer_guard_variant_layout;
		break;
	case CMP_FIELD_GUARD_BUFFER_DISCRIM:
		slot = &kcov_shm->cmp_field_consumer_guard_buffer_discrim;
		break;
	case CMP_FIELD_GUARD_LEN_PAIR:
		slot = &kcov_shm->cmp_field_consumer_guard_len_pair;
		break;
	case CMP_FIELD_GUARD_NESTED_POINTER:
		slot = &kcov_shm->cmp_field_consumer_guard_nested_pointer;
		break;
	case CMP_FIELD_GUARD_DEPENDENT:
		slot = &kcov_shm->cmp_field_consumer_guard_dependent;
		break;
	default:
		return false;
	}
	__atomic_fetch_add(slot, 1UL, __ATOMIC_RELAXED);
	return true;
}

bool cmp_hints_field_try_get(unsigned int nr, bool do32, unsigned int arg_idx,
			     const struct struct_desc *desc,
			     unsigned int field_idx, unsigned int size,
			     enum cmp_hint_use use, unsigned long old,
			     unsigned long fallback, unsigned long *out)
{
	struct cmp_field_pool *pool = NULL;
	struct cmp_hint_entry *picked;
	unsigned long picked_value;
	unsigned long picked_cmp_ip;
	uint32_t picked_size;
	unsigned int count;
	uint32_t h;
	unsigned int probe;
	unsigned int do32_idx = do32 ? 1U : 0U;

	if (cmp_hints_shm == NULL || desc == NULL)
		return false;
	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return false;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return false;

	/* Chaos-mode gate.  Mirror cmp_hints_try_get_ex so suppressed
	 * windows skip the field consumer the same way they skip the
	 * scalar one -- a chaos window that only suppresses one consumer
	 * arm would bias the kernel-validated mix on the other. */
	if (kcov_shm != NULL &&
	    __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_chaos_active,
			    __ATOMIC_RELAXED))
		return false;

	/* Generator-invariant guard.  Rejects keys whose value, if injected,
	 * would corrupt a generator invariant (variant arm, len/buf pairing,
	 * pointer slot, tagged-union discriminator).  Fires BEFORE the pool
	 * lookup so an ineligible key never contributes to would_pick /
	 * would_miss / key_absent -- each guard skip lands in its own
	 * per-reason counter. */
	if (cmp_field_key_guard_skip(desc, field_idx))
		return false;

	/* Bucket lookup: same hash + ACQUIRE-load key probe loop as the
	 * recorder (cmp_hints_field_record above).  Full-key match
	 * required at every probe slot -- a hash collision on a different
	 * key continues walking until either a matching key is found or
	 * the probe window exhausts. */
	h = cmp_field_pool_hash(desc, nr, do32_idx, arg_idx, field_idx, size);

	for (probe = 0; probe < CMP_FIELD_POOL_PROBE_MAX; probe++) {
		unsigned int idx = (h + probe) & (CMP_FIELD_POOL_BUCKETS - 1U);
		struct cmp_field_pool *cand = &cmp_hints_shm->field_pools[idx];
		const struct struct_desc *occ;

		occ = __atomic_load_n(&cand->key.desc, __ATOMIC_ACQUIRE);
		if (occ == NULL)
			break;
		if (occ != desc ||
		    cand->key.nr != (uint16_t) nr ||
		    cand->key.do32 != (uint8_t) do32_idx ||
		    cand->key.arg_idx != (uint8_t) arg_idx ||
		    cand->key.field_idx != (uint16_t) field_idx ||
		    cand->key.size != (uint8_t) size)
			continue;

		pool = cand;
		break;
	}

	if (pool == NULL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_key_absent,
					   1UL, __ATOMIC_RELAXED);
		return false;
	}

	/* Lockless count + corruption gate, byte-for-byte parallel to the
	 * per-syscall pick path: a kernel-side wild write that stomps
	 * pool->count would otherwise feed garbage into rnd_modulo_u32 and
	 * index off the field_pools[] array.  Hints are advisory -- skip
	 * is the safe response. */
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_would_miss,
					   1UL, __ATOMIC_RELAXED);
		return false;
	}
	if (cmp_field_pool_corrupted(pool, count)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_pool_corrupted,
					   1UL, __ATOMIC_RELAXED);
		return false;
	}

	/* SHADOW: count the would-be-pick on EVERY call regardless of arm
	 * so the would-pick rate is legible from a default (LIVE off) run.
	 * The LIVE arm bumps the separate cmp_field_consumer_live_picks
	 * counter so the two rates stay cleanly separable.
	 *
	 * Prove-overlay: snapshot the current fleet-wide edge / cmp /
	 * per-syscall reject counters at each eligible would-pick so a
	 * later live-arm flip can diff shadow-window vs live-window rates
	 * and answer "did routing this value in produce new edge / cmp
	 * progress, and did it raise the rejected-struct rate?".  Loads
	 * are RELAXED (racing writers may leave the sample a few counts
	 * stale -- a per-sample skew that averages out over the
	 * prove_eligible denominator).  Per-syscall EINVAL bucket is
	 * keyed to the pick's own nr; the (nr < MAX_NR_SYSCALL) bound is
	 * already established by the parameter validation at the head of
	 * the function so the array index is safe. */
	if (kcov_shm != NULL) {
		unsigned long shadow_elect;

		__atomic_fetch_add(&kcov_shm->cmp_field_consumer_would_pick,
				   1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_field_consumer_prove_eligible,
				   1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_field_consumer_prove_edges_at_pick,
				   __atomic_load_n(&kcov_shm->coverage.distinct_edges,
						   __ATOMIC_RELAXED),
				   __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_field_consumer_prove_cmp_records_at_pick,
				   __atomic_load_n(&kcov_shm->cmp_records.cmp_records_collected,
						   __ATOMIC_RELAXED),
				   __ATOMIC_RELAXED);
		__atomic_fetch_add(&kcov_shm->cmp_field_consumer_prove_einval_at_pick,
				   __atomic_load_n(&kcov_shm->per_syscall_errno[nr][ERRNO_BUCKET_EINVAL],
						   __ATOMIC_RELAXED),
				   __ATOMIC_RELAXED);

		/*
		 * SHADOW would_value_differs bump.  Deterministic proxy for
		 * the live arm's rnd_modulo_u32(count) elect: read entries[0]
		 * so no RNG draw fires from the shadow path (a per-child RNG
		 * advance here would break dry-run byte-identical).  Pool
		 * insertion / eviction over run duration rotates fresh
		 * constants through slot 0, so the differs subset observed
		 * here converges on the pool-population differs rate the
		 * uniform live pick would sample.  Sits inside the post-guard
		 * would_pick branch (bounded from above by would_pick) and
		 * uses the caller's pre-injection fallback (the value the
		 * generator was about to write); a raw byte-for-byte match
		 * means a live flip at this call would swap in the same value
		 * the generator already had and change nothing on the wire.
		 * Skipping the cmp_hint_apply_transform() call is safe because
		 * CMP_HINT_FIELD's transform is bare-C (see the FALLTHROUGH
		 * with CMP_HINT_EXACT in cmp_hint_apply_transform).
		 */
		shadow_elect = __atomic_load_n(&pool->entries[0].value,
					       __ATOMIC_RELAXED);
		if (shadow_elect != fallback)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_would_value_differs,
					   1UL, __ATOMIC_RELAXED);
	}

	if (!cmp_field_consumer_live_arm)
		return false;

	/* A/B-gated live-pick policy, identical discipline to the
	 * per-syscall pool pick above: arm A keeps the uniform draw, arm
	 * B routes through the weighted draw on the per-entry score the
	 * SHADOW credit drain maintains.  Both arms still stash the
	 * consumed tuple below so the credit drain keeps populating the
	 * .wins / .misses fields the weighted draw consumes. */
	if (cmp_hint_livepick_arm_b_active())
		picked = &pool->entries[
			cmp_hint_weighted_pick(pool->entries, count)];
	else
		picked = &pool->entries[rnd_modulo_u32(count)];
	/* Snapshot the triplet BEFORE the transform so the stash carries
	 * the raw pool-entry identity (cmp_ip, value, size) -- the tuple
	 * the credit drain uses to re-find the same entry.  Reading each
	 * field once locally also avoids a torn (cmp_ip, value, size)
	 * triplet on a concurrent eviction: even if a sibling overwrites
	 * the slot between our loads, the credit drain just fails to
	 * re-find a matching entry and the per-entry score for that pull
	 * is lost (the flat counter still bumps). */
	picked_value = picked->value;
	picked_cmp_ip = picked->cmp_ip;
	picked_size = picked->size;
	/* Staleness sample.  Field pools share the same durable LRU
	 * discipline as the per-syscall pool (cmp_field_pool_insert_locked
	 * bumps pool->last_used_stamp on every insert/dedup-refresh and
	 * stamps the entry's last_used at insert time), so the same
	 * bucketing partition applies.  Same torn-read tolerance + b<=a
	 * underflow guard as the per-syscall pick. */
	{
		uint64_t cur_stamp = __atomic_load_n(&pool->last_used_stamp,
						     __ATOMIC_RELAXED);
		uint64_t entry_stamp = __atomic_load_n(&picked->last_used,
						       __ATOMIC_RELAXED);
		uint64_t age = (cur_stamp >= entry_stamp) ?
				(cur_stamp - entry_stamp) : 0;
		uint8_t bucket = cmp_hint_age_bucket(age);

		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_hint_durable_consumed_age[bucket],
					   1UL, __ATOMIC_RELAXED);

		*out = cmp_hint_apply_transform(picked_value, use, old);

		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->cmp_field_consumer_live_picks,
					   1UL, __ATOMIC_RELAXED);

		/* CMP_HINT_CALLSITE_NR: field-scoped pulls have no argtype-
		 * handler callsite -- the credit drain's bound check gates
		 * the by-callsite bump so the field-pool stash is silently
		 * skipped in the callsite partition (already carried by the
		 * pool-kind partition). */
		cmp_hints_stash_consumed(nr, do32, CMP_HINT_POOL_FIELD,
					 CMP_HINT_CALLSITE_NR,
					 picked_cmp_ip, picked_value, picked_size, use,
					 arg_idx, field_idx, desc,
					 false, bucket, false, false);
	}
	return true;
}
