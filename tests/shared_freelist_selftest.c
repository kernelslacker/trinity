/*
 * Self-checks for utils/shared_freelist.c's bounds armour.
 *
 * The primitives run over a caller-owned slab and treat every token
 * (head or slot-link) as fuzzer-writable input, so this suite drives
 * them against a private fake heap:
 *
 *   - freelist_roundtrip:   push a slot, pop it, prove pop returned
 *                           exactly the same address and a zeroed slot,
 *                           and that a second pop finds an empty list.
 *
 *   - freelist_corrupt_head: stomp the head with a wild token (offset
 *                           past the slab, extending past the end, and
 *                           token == UINT32_MAX) and prove pop returns
 *                           NULL without wild-reading — the fake heap
 *                           is flanked by PROT_NONE guard pages so any
 *                           wild deref/memset would SIGSEGV inside the
 *                           test, not return quietly.
 *
 *   - freelist_corrupt_link: push a valid slot, then stomp its stored
 *                           link with a wild token, and prove pop
 *                           returns the valid slot AND detaches the
 *                           wild chain (the head becomes empty rather
 *                           than pointing into unrelated memory).
 *
 *   - freelist_push_out_of_range: hand freelist_push a pointer that
 *                           isn't inside the slab and prove nothing is
 *                           linked (the head stays sentinel-empty and
 *                           a follow-up pop returns NULL).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "debug.h"			/* BUG */
#include "shared_freelist.h"

#define FAKE_HEAP_CAP		4096U
#define SLOT_SIZE		64U

struct fake_heap {
	char *guard_lo;			/* PROT_NONE, one page */
	char *base;			/* PROT_READ|WRITE, FAKE_HEAP_CAP */
	char *guard_hi;			/* PROT_NONE, one page */
	size_t page;
	size_t total_bytes;
};

static void fake_heap_init(struct fake_heap *h)
{
	long page_l = sysconf(_SC_PAGESIZE);
	size_t page, heap_pages, total;
	char *region;

	if (page_l <= 0)
		BUG("shared_freelist selftest: sysconf(_SC_PAGESIZE) failed");
	page = (size_t)page_l;
	heap_pages = (FAKE_HEAP_CAP + page - 1) / page;
	total = (heap_pages + 2) * page;

	region = mmap(NULL, total, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		BUG("shared_freelist selftest: mmap of fake heap failed");

	if (mprotect(region, page, PROT_NONE) != 0)
		BUG("shared_freelist selftest: mprotect low guard failed");
	if (mprotect(region + total - page, page, PROT_NONE) != 0)
		BUG("shared_freelist selftest: mprotect high guard failed");

	h->guard_lo	= region;
	h->base		= region + page;
	h->guard_hi	= region + total - page;
	h->page		= page;
	h->total_bytes	= total;

	memset(h->base, 0xa5, FAKE_HEAP_CAP);
}

static void fake_heap_release(struct fake_heap *h)
{
	if (munmap(h->guard_lo, h->total_bytes) != 0)
		BUG("shared_freelist selftest: munmap of fake heap failed");
}

/*
 * Bit-for-bit reconstruction of shared_freelist.c's head encoding.
 * Kept local so a future encoding change trips both this helper and a
 * failing test rather than sliding under a shared macro.
 */
static uint64_t make_head(uint32_t token, uint32_t version)
{
	return ((uint64_t)token & 0xffffffffULL) | ((uint64_t)version << 32);
}

static uint32_t head_token(uint64_t head)
{
	return (uint32_t)(head & 0xffffffffULL);
}

static void selftest_roundtrip(void)
{
	struct fake_heap heap;
	uint64_t head = 0;
	void *slot, *popped, *empty;
	unsigned int i;

	fake_heap_init(&heap);

	slot = heap.base + SLOT_SIZE * 3;	/* arbitrary in-slab offset */
	shared_freelist_push(&head, slot, heap.base, FAKE_HEAP_CAP, SLOT_SIZE);

	if (head_token(head) == 0)
		BUG("roundtrip: head still empty after push");

	popped = shared_freelist_pop(&head, heap.base, FAKE_HEAP_CAP,
				     SLOT_SIZE);
	if (popped != slot)
		BUG("roundtrip: pop returned a different address than push");

	for (i = 0; i < SLOT_SIZE; i++) {
		if (((unsigned char *)popped)[i] != 0)
			BUG("roundtrip: pop did not zero the slot");
	}

	empty = shared_freelist_pop(&head, heap.base, FAKE_HEAP_CAP,
				    SLOT_SIZE);
	if (empty != NULL)
		BUG("roundtrip: second pop returned non-NULL from empty list");

	fake_heap_release(&heap);
}

/*
 * Stomp the head with tokens that must NOT be dereferenced: this is
 * the whole point of the armour.  Each case runs on its own fake heap
 * because a failed check would land on the guard pages and abort the
 * process; running them independently keeps the failure signal per-case.
 */
static void selftest_corrupt_head(void)
{
	struct fake_heap heap;
	uint64_t head;
	void *r;

	/* Case 1: token names an offset one past the slab. */
	fake_heap_init(&heap);
	head = make_head((uint32_t)FAKE_HEAP_CAP + 1, 7);
	r = shared_freelist_pop(&head, heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("corrupt_head[past-end]: pop dereferenced a wild token");
	fake_heap_release(&heap);

	/* Case 2: token starts inside the slab but slot_size runs past
	 * the end — the memset would clobber the high guard page. */
	fake_heap_init(&heap);
	head = make_head((uint32_t)(FAKE_HEAP_CAP - (SLOT_SIZE / 2)) + 1, 7);
	r = shared_freelist_pop(&head, heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("corrupt_head[straddle]: pop accepted a slot straddling the end");
	fake_heap_release(&heap);

	/* Case 3: token == UINT32_MAX — maximum wild offset. */
	fake_heap_init(&heap);
	head = make_head(UINT32_MAX, 7);
	r = shared_freelist_pop(&head, heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("corrupt_head[max]: pop dereferenced UINT32_MAX token");
	fake_heap_release(&heap);
}

static void selftest_corrupt_link(void)
{
	struct fake_heap heap;
	uint64_t head = 0;
	void *slot, *popped, *empty;

	fake_heap_init(&heap);

	slot = heap.base + SLOT_SIZE * 5;
	shared_freelist_push(&head, slot, heap.base, FAKE_HEAP_CAP, SLOT_SIZE);

	/* Push zeroed the slot and wrote a token-0 link (empty).  Stomp
	 * the link with a wild token — a naive popper would install
	 * this as the new head and the next pop would dereference it. */
	*(uint32_t *)slot = UINT32_MAX;

	popped = shared_freelist_pop(&head, heap.base, FAKE_HEAP_CAP,
				     SLOT_SIZE);
	if (popped != slot)
		BUG("corrupt_link: pop returned a different address");

	/* The wild link must have been dropped, not installed. */
	if (head_token(head) != 0)
		BUG("corrupt_link: wild link was installed as the new head");

	empty = shared_freelist_pop(&head, heap.base, FAKE_HEAP_CAP,
				    SLOT_SIZE);
	if (empty != NULL)
		BUG("corrupt_link: follow-up pop returned non-NULL");

	fake_heap_release(&heap);
}

static void selftest_push_out_of_range(void)
{
	struct fake_heap heap;
	uint64_t head = 0;
	char *wild;
	void *r;

	fake_heap_init(&heap);

	/* A pointer clearly below the slab (heap.base itself minus one
	 * whole slot).  The negative delta must be refused so we don't
	 * encode it as a very-large positive uint32_t token. */
	wild = heap.base - SLOT_SIZE * 2;
	shared_freelist_push(&head, wild, heap.base, FAKE_HEAP_CAP,
			     SLOT_SIZE);
	if (head_token(head) != 0)
		BUG("push_out_of_range[below]: below-slab pointer was linked");

	/* A pointer beyond the slab. */
	wild = heap.base + FAKE_HEAP_CAP;
	shared_freelist_push(&head, wild, heap.base, FAKE_HEAP_CAP,
			     SLOT_SIZE);
	if (head_token(head) != 0)
		BUG("push_out_of_range[above]: above-slab pointer was linked");

	r = shared_freelist_pop(&head, heap.base, FAKE_HEAP_CAP, SLOT_SIZE);
	if (r != NULL)
		BUG("push_out_of_range: pop returned a slot from an empty list");

	fake_heap_release(&heap);
}

void shared_freelist_self_check(void);
void shared_freelist_self_check(void)
{
	selftest_roundtrip();
	selftest_corrupt_head();
	selftest_corrupt_link();
	selftest_push_out_of_range();
}
