/*
 * Unit harness for the slot-cookie gate in deferred-free.c.
 *
 * Trinity proper is a kernel-fuzz binary that cannot run on a developer
 * host (and cannot run as a hosted unit test even with --dry-run --
 * deferred-free.c is wired into the live syscall loop).  This harness
 * builds standalone with zero trinity headers and validates the
 * per-slot provenance algorithm that ring_evict_oldest_safe(),
 * free_ring_entry(), and tracked_free_now() all gate on.
 *
 * MIRROR ALERT: struct deferred_entry, mk_cookie() and slot_owns()
 * below MUST stay byte-for-byte equivalent to their counterparts in
 * deferred-free.c.  If you change one, change both -- a code-review
 * gate enforces this.  The test exercises the algorithm contract; if
 * the algorithm here diverges from the production helpers, the test
 * passes while production breaks.
 *
 * Scenarios:
 *   T1 clean slot -- slot_owns true, eviction frees, counter unchanged
 *   T2 scribbled .ptr -- slot_owns false, eviction REJECTS, counter++
 *   T3 scribbled .base -- slot_owns false, eviction REJECTS, counter++
 *   T4 scribbled .gen  -- cookie no longer validates, REJECT, counter++
 *   T5 scribbled .cookie -- explicit cookie stomp, REJECT, counter++
 *   T6 full-ring eviction: 1 clean + 1 scribbled -> only the clean slot
 *                          is freed; the scribbled slot is rejected and
 *                          leaks (child exit reclaims).
 *   T7 inverse of T6: only clean slots -> all freed exactly once.
 *   T8 re-tenant gen bump: cookie for slot N admission #2 must differ
 *      from admission #1 (so a stale cookie from a prior tenant cannot
 *      validate after a re-admit).
 *   T9 secret isolation: two independent runs with different secrets
 *      MUST produce different cookies for identical (base, gen, slot)
 *      -- otherwise a replay across runs would forge a match.
 *
 * Build + run:  make tests/test-deferred-free-slot-cookie && \
 *               tests/test-deferred-free-slot-cookie
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFERRED_RING_SIZE	64

/* MIRROR OF struct deferred_entry IN deferred-free.c */
struct deferred_entry {
	void *ptr;
	void *base;
	unsigned long cookie;
	unsigned int ttl;
	unsigned int gen;
};

/* Per-test ring + secret stand-in for the production rc->cookie_secret. */
static struct deferred_entry ring[DEFERRED_RING_SIZE];
static unsigned long g_cookie_secret;
static unsigned long g_slot_reject_counter;
static unsigned long g_free_counter;

/* MIRROR OF mk_cookie() IN deferred-free.c -- KEEP IN SYNC. */
static unsigned long mk_cookie(void *base, unsigned int gen, unsigned int slot)
{
	uint64_t k = (uint64_t)(uintptr_t)base;

	k ^= (uint64_t)gen * 0x9E3779B97F4A7C15ULL;
	k ^= (uint64_t)slot << 16;
	k ^= g_cookie_secret;
	return (unsigned long)k;
}

/* MIRROR OF slot_owns() IN deferred-free.c -- KEEP IN SYNC. */
static bool slot_owns(unsigned int slot)
{
	void *p = ring[slot].ptr;

	if (p == NULL)
		return false;
	if (p != ring[slot].base)
		return false;
	if (ring[slot].cookie != mk_cookie(p, ring[slot].gen, slot))
		return false;
	return true;
}

/* Stand-in for production's admit path: stamp ptr/base/gen/cookie. */
static void admit(unsigned int slot, void *ptr)
{
	ring[slot].ptr = ptr;
	ring[slot].base = ptr;
	ring[slot].gen += 1;
	ring[slot].cookie = mk_cookie(ptr, ring[slot].gen, slot);
	ring[slot].ttl = 10;
}

/* Stand-in for the eviction / TTL-drain free decision: gate on
 * slot_owns; reject -> bump counter + leak; accept -> "free" + bump
 * free counter.  Mirrors the production reject-instead-of-free
 * policy that this commit's mate fix introduces. */
static void eviction_gate(unsigned int slot)
{
	if (!slot_owns(slot)) {
		g_slot_reject_counter++;
		/* leak: production drops free() and lets child exit reclaim */
	} else {
		g_free_counter++;
		/* would call free(ring[slot].ptr) in production */
	}
	ring[slot].ptr = NULL;
}

static void reset(void)
{
	memset(ring, 0, sizeof(ring));
	g_slot_reject_counter = 0;
	g_free_counter = 0;
}

static void t1_clean_slot(void)
{
	reset();
	admit(0, (void *)0x111122223333ULL);
	assert(slot_owns(0));
	eviction_gate(0);
	assert(g_free_counter == 1);
	assert(g_slot_reject_counter == 0);
	printf("T1 PASS: clean slot freed exactly once\n");
}

static void t2_scribbled_ptr(void)
{
	reset();
	admit(1, (void *)0x222233334444ULL);
	ring[1].ptr = (void *)0xdeadbeefULL;	/* sibling scribble */
	assert(!slot_owns(1));
	eviction_gate(1);
	assert(g_slot_reject_counter == 1);
	assert(g_free_counter == 0);
	printf("T2 PASS: scribbled .ptr rejected, no free\n");
}

static void t3_scribbled_base(void)
{
	reset();
	admit(2, (void *)0x333344445555ULL);
	ring[2].base = (void *)0xbaadf00dULL;	/* sibling scribble */
	assert(!slot_owns(2));
	eviction_gate(2);
	assert(g_slot_reject_counter == 1);
	assert(g_free_counter == 0);
	printf("T3 PASS: scribbled .base rejected, no free\n");
}

static void t4_scribbled_gen(void)
{
	reset();
	admit(3, (void *)0x444455556666ULL);
	ring[3].gen += 17;	/* sibling scribble: cookie no longer validates */
	assert(!slot_owns(3));
	eviction_gate(3);
	assert(g_slot_reject_counter == 1);
	assert(g_free_counter == 0);
	printf("T4 PASS: scribbled .gen rejected, no free\n");
}

static void t5_scribbled_cookie(void)
{
	reset();
	admit(4, (void *)0x555566667777ULL);
	ring[4].cookie ^= 0xffULL;	/* sibling scribble */
	assert(!slot_owns(4));
	eviction_gate(4);
	assert(g_slot_reject_counter == 1);
	assert(g_free_counter == 0);
	printf("T5 PASS: scribbled .cookie rejected, no free\n");
}

static void t6_mixed_full_ring_eviction(void)
{
	unsigned int i;

	reset();
	/* Fill the ring with 64 distinct admissions; scribble every
	 * other slot so half get rejected and half get freed. */
	for (i = 0; i < DEFERRED_RING_SIZE; i++)
		admit(i, (void *)(uintptr_t)(0x70000000ULL + (uintptr_t)i * 0x1000ULL));

	for (i = 0; i < DEFERRED_RING_SIZE; i += 2)
		ring[i].ptr = (void *)(uintptr_t)(0xbaad0000ULL + (uintptr_t)i);

	/* Drive a full ring drain through the gate. */
	for (i = 0; i < DEFERRED_RING_SIZE; i++)
		eviction_gate(i);

	assert(g_slot_reject_counter == DEFERRED_RING_SIZE / 2);
	assert(g_free_counter == DEFERRED_RING_SIZE / 2);
	printf("T6 PASS: full-ring eviction: %u freed, %u rejected\n",
	       (unsigned)g_free_counter, (unsigned)g_slot_reject_counter);
}

static void t7_all_clean_full_ring(void)
{
	unsigned int i;

	reset();
	for (i = 0; i < DEFERRED_RING_SIZE; i++)
		admit(i, (void *)(uintptr_t)(0x80000000ULL + (uintptr_t)i * 0x1000ULL));

	for (i = 0; i < DEFERRED_RING_SIZE; i++)
		eviction_gate(i);

	assert(g_free_counter == DEFERRED_RING_SIZE);
	assert(g_slot_reject_counter == 0);
	printf("T7 PASS: all-clean full-ring eviction: %u freed, 0 rejected\n",
	       (unsigned)g_free_counter);
}

static void t8_retenant_gen_bump(void)
{
	unsigned long cookie_v1, cookie_v2;
	void *p = (void *)0x900000000000ULL;

	reset();
	admit(5, p);
	cookie_v1 = ring[5].cookie;
	ring[5].ptr = NULL;	/* simulate the slot release */

	admit(5, p);		/* re-tenant with the same base */
	cookie_v2 = ring[5].cookie;

	assert(cookie_v1 != cookie_v2);
	printf("T8 PASS: re-tenant of slot 5 with same base "
	       "produced distinct cookies (%lx -> %lx)\n",
	       cookie_v1, cookie_v2);
}

static void t9_secret_isolation(void)
{
	unsigned long c_secret_A, c_secret_B;
	void *p = (void *)0xaa0000000000ULL;

	g_cookie_secret = 0xcafebabe11112222ULL;
	c_secret_A = mk_cookie(p, 1, 7);

	g_cookie_secret = 0xdeadbeef33334444ULL;
	c_secret_B = mk_cookie(p, 1, 7);

	assert(c_secret_A != c_secret_B);
	printf("T9 PASS: different secrets produce different cookies "
	       "for the same (base, gen, slot)\n");
}

int main(void)
{
	g_cookie_secret = 0xfeedfacedeadbeefULL;

	t1_clean_slot();
	t2_scribbled_ptr();
	t3_scribbled_base();
	t4_scribbled_gen();
	t5_scribbled_cookie();
	t6_mixed_full_ring_eviction();
	t7_all_clean_full_ring();
	t8_retenant_gen_bump();
	t9_secret_isolation();

	printf("\nALL TESTS PASSED\n");
	return 0;
}
