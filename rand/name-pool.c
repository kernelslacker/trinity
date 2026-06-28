/*
 * Per-kind stateful name pool.  See include/name-pool.h for the
 * design rationale.
 *
 * Storage layout: a single alloc_shared_pool() region containing one
 * fixed-size ring per kind.  Writes wrap modulo NAME_POOL_SLOTS_PER_
 * KIND, and a separate `filled` counter clamps the slot space the
 * reader picks from (so an unfilled ring never returns a zeroed
 * slot).  Both indices use RELAXED atomics: a torn read of the
 * payload is acceptable (it is fuzz input by construction) but two
 * concurrent writers must not overwrite the same slot, and a reader
 * must not pick a slot past the high-water mark of writes that have
 * landed.  We snapshot the payload into a local buffer before any
 * mutation -- the on-pool bytes can be overwritten by a concurrent
 * record() at any time and the mutator must work against a stable
 * source.
 *
 * Lazy init: the pool pointer is process-private (.bss).  Each child
 * that hits the lane allocates its own shared region on first use;
 * children do NOT share a single pool.  This keeps the alloc safely
 * after parse_args (so --guard-shared=pools wraps it) and avoids any
 * pre-main constructor ordering footgun.  The intra-child stateful
 * arm is the primary coverage win -- the same child's syscall stream
 * is what plants and references a name.
 *
 * Bounding: NAME_KIND__MAX * NAME_POOL_SLOTS_PER_KIND *
 * NAME_POOL_MAX_NAME_LEN = 6 * 16 * 64 = 6 KiB of name bytes plus a
 * few bytes of per-kind bookkeeping, well under any per-region cap.
 * One shared_regions[] slot per child.
 */

#include <stdint.h>

#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

struct pool_slot {
	uint8_t len;
	char buf[NAME_POOL_MAX_NAME_LEN];
};

struct kind_ring {
	uint32_t write_idx;	/* monotonic; & (SLOTS-1) gives slot */
	uint32_t filled;	/* clamped to NAME_POOL_SLOTS_PER_KIND */
	struct pool_slot slots[NAME_POOL_SLOTS_PER_KIND];
};

struct name_pool {
	struct kind_ring per_kind[NAME_KIND__MAX];
};

static struct name_pool *g_pool;

static struct name_pool *get_pool(void)
{
	struct name_pool *p;
	struct name_pool *expected = NULL;

	p = __atomic_load_n(&g_pool, __ATOMIC_ACQUIRE);
	if (p != NULL)
		return p;

	p = alloc_shared_pool(sizeof(*p));
	/* alloc_shared_pool() exits on mmap failure, so p is non-NULL.
	 * It deliberately poisons the new region with random bytes to
	 * expose uninitialized reads -- but for this pool that would
	 * leave filled / write_idx / slot.len garbage, and the reuse
	 * arm would copy poisoned bytes out of "filled" rings that
	 * have never actually recorded a name.  Zero before publish. */
	memset(p, 0, sizeof(*p));

	if (__atomic_compare_exchange_n(&g_pool, &expected, p, false,
					__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return p;

	/*
	 * Lost the CAS race -- a concurrent writer published first.
	 * The redundant region stays mapped for the process lifetime;
	 * one extra entry in shared_regions[] is well inside the 4096
	 * cap and free_shared is only available under CONFIG_GUARD_
	 * SHARED, so a portable release path does not exist.  Use the
	 * winner.
	 */
	return expected;
}

void name_pool_record(enum name_kind kind, const char *name, size_t len)
{
	struct name_pool *pool;
	struct kind_ring *ring;
	struct pool_slot *slot;
	uint32_t idx;
	uint32_t filled;

	if ((unsigned int)kind >= NAME_KIND__MAX)
		return;
	if (name == NULL || len == 0)
		return;
	if (len > NAME_POOL_MAX_NAME_LEN)
		len = NAME_POOL_MAX_NAME_LEN;

	pool = get_pool();
	ring = &pool->per_kind[kind];

	idx = __atomic_fetch_add(&ring->write_idx, 1, __ATOMIC_RELAXED);
	slot = &ring->slots[idx & (NAME_POOL_SLOTS_PER_KIND - 1)];

	memcpy(slot->buf, name, len);
	slot->len = (uint8_t)len;

	/*
	 * Bump filled up to the cap.  Read-modify-write under RELAXED
	 * is safe because the value is monotonically clamped and the
	 * reader only uses it to bound the slot pick.  A concurrent
	 * record() that lands a worse value still leaves filled within
	 * [old, SLOTS] and the reader still picks a valid slot.
	 */
	filled = __atomic_load_n(&ring->filled, __ATOMIC_RELAXED);
	if (filled < NAME_POOL_SLOTS_PER_KIND)
		__atomic_store_n(&ring->filled, filled + 1,
				 __ATOMIC_RELAXED);
}

enum mut_op {
	MUT_EXACT = 0,		/* reuse the recorded bytes verbatim */
	MUT_FLIP_BYTE,		/* xor one random byte with a random delta */
	MUT_TRUNCATE,		/* keep a prefix of length [1, src_len] */
	MUT_CASE_FLIP,		/* toggle case on every ASCII letter */
	MUT_SUFFIX_GROW,	/* append random alphanumerics toward out_cap */
	MUT__MAX
};

static size_t apply_mut(enum mut_op op, char *out, size_t out_cap,
			const char *src, size_t src_len)
{
	size_t i;

	if (out_cap == 0 || src_len == 0)
		return 0;
	if (src_len > out_cap)
		src_len = out_cap;

	switch (op) {
	case MUT_EXACT:
		memcpy(out, src, src_len);
		return src_len;

	case MUT_FLIP_BYTE: {
		uint32_t pos;
		uint8_t delta;

		memcpy(out, src, src_len);
		pos = rnd_modulo_u32((uint32_t)src_len);
		do {
			delta = (uint8_t)(rnd_u32() & 0xff);
		} while (delta == 0);
		out[pos] = (char)((uint8_t)out[pos] ^ delta);
		return src_len;
	}

	case MUT_TRUNCATE: {
		size_t newlen = 1 + rnd_modulo_u32((uint32_t)src_len);

		if (newlen > src_len)
			newlen = src_len;
		memcpy(out, src, newlen);
		return newlen;
	}

	case MUT_CASE_FLIP:
		memcpy(out, src, src_len);
		for (i = 0; i < src_len; i++) {
			char c = out[i];

			if (c >= 'a' && c <= 'z')
				out[i] = (char)(c - 32);
			else if (c >= 'A' && c <= 'Z')
				out[i] = (char)(c + 32);
		}
		return src_len;

	case MUT_SUFFIX_GROW: {
		static const char alphabet[] =
			"abcdefghijklmnopqrstuvwxyz0123456789_";
		size_t headroom;
		size_t want;

		memcpy(out, src, src_len);
		headroom = (out_cap > src_len) ? (out_cap - src_len) : 0;
		if (headroom == 0)
			return src_len;
		want = 1 + rnd_modulo_u32((uint32_t)headroom);
		for (i = 0; i < want; i++)
			out[src_len + i] =
				alphabet[rnd_modulo_u32(sizeof(alphabet) - 1)];
		return src_len + want;
	}

	case MUT__MAX:
		break;
	}
	memcpy(out, src, src_len);
	return src_len;
}

size_t name_pool_draw_mutated(enum name_kind kind, char *out, size_t out_cap)
{
	struct name_pool *pool;
	struct kind_ring *ring;
	const struct pool_slot *slot;
	char local[NAME_POOL_MAX_NAME_LEN];
	uint32_t filled;
	uint32_t cap;
	uint32_t slot_idx;
	uint8_t slen;

	if ((unsigned int)kind >= NAME_KIND__MAX || out_cap == 0)
		return 0;
	if (out == NULL)
		return 0;

	pool = __atomic_load_n(&g_pool, __ATOMIC_ACQUIRE);
	if (pool == NULL)
		return 0;
	ring = &pool->per_kind[kind];

	filled = __atomic_load_n(&ring->filled, __ATOMIC_RELAXED);
	if (filled == 0)
		return 0;
	cap = filled < NAME_POOL_SLOTS_PER_KIND
		? filled : NAME_POOL_SLOTS_PER_KIND;

	slot_idx = rnd_modulo_u32(cap);
	slot = &ring->slots[slot_idx];

	/*
	 * Snapshot slot under a defensive bound: a concurrent record()
	 * may be mid-write into this slot.  Read len first, then copy
	 * at most that many bytes -- a torn len that exceeds the buffer
	 * is rejected.
	 */
	slen = slot->len;
	if (slen == 0 || slen > NAME_POOL_MAX_NAME_LEN)
		return 0;
	memcpy(local, slot->buf, slen);

	return apply_mut((enum mut_op)rnd_modulo_u32(MUT__MAX),
			 out, out_cap, local, slen);
}
