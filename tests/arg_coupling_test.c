/*
 * Self-check for the per-syscall rules validate_arg_coupling() holds the
 * final argument slots to: a rewrite after the sanitiser (chain
 * substitution, a RedQueen pin) must not leave the kernel a range the
 * sanitiser would have refused.  madvise's (addr, len) stays off trinity's
 * tracked regions, and a buffer-filling count stays inside its buffer.
 * mprotect's sanitiser, which pkey_mprotect shares, runs here too.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "arch.h"				/* page_size */
#include "arg_coupling.h"
#include "child.h"			/* struct childdata */
#include "debug.h"			/* BUG */
#include "files.h"			/* get_rand_pagecache_fd */
#include "maps.h"			/* proc_maps_check */
#include "objects.h"			/* struct object */
#include "pathnames.h"		/* get_testfile_path */
#include "sanitise.h"			/* writable pool, get_random_pkey_id */
#include "syscall.h"			/* struct syscallrecord */
#include "testfile.h"			/* get_rand_testfile_fd */
#include "syscalls/syscalls.h"		/* syscall_read, syscall_pread64 */
#include "utils-macros.h"		/* ARRAY_SIZE */
#include "utils-mem.h"			/* log_mm_syscall_post_gate_heap_slip */

/* Region tracking in tests/fake_shm.c. */
void fake_track_region(unsigned long addr, unsigned long size);
void fake_untrack_regions(void);
extern bool fake_overlaps_shared;
extern bool fake_overlaps_libc_heap;

extern struct childdata *fake_this_child;	/* fake_shm.c */

/* sanity_check_tables() over one entry, in tests/sanitiser_owned_mask_test.c. */
int entry_check_status(struct syscallentry *entry);

/* The page-cache fd pool pread64's sanitiser draws from is not in this
 * binary, and an empty one leaves the fd alone. */
int get_rand_pagecache_fd(void)
{
	return -1;
}

/* The xattr getters plant a value in a testfile when there is one, and
 * snapshot their path for the post handler; with no testfiles and no
 * snapshot source they do neither. */
char *get_testfile_path(void)
{
	return NULL;
}

int get_rand_testfile_fd(void)
{
	return -1;
}

bool post_snapshot_str(char *dst, size_t dstsz, const char *src)
{
	(void) dst;
	(void) dstsz;
	(void) src;
	return false;
}

/* The OBJ_PKEY pool, the heap-slip log and the /proc/self/maps oracle
 * the mm sanitisers and post handlers reach.  The pool hands out
 * pkey_drawn and the log keeps the name it was given. */
static int pkey_drawn = -1;
static const char *heap_slip_name;

int get_random_pkey_id(void)
{
	return pkey_drawn;
}

void log_mm_syscall_post_gate_heap_slip(const char *syscall_name,
					unsigned long addr, unsigned long len,
					unsigned long detail)
{
	(void) addr;
	(void) len;
	(void) detail;
	heap_slip_name = syscall_name;
}

bool proc_maps_check(unsigned long addr, unsigned long len,
		     int expected_prot, bool expect_present)
{
	(void) addr;
	(void) len;
	(void) expected_prot;
	(void) expect_present;
	return true;
}

#define REGION		0x7f0000000000UL
#define REGION_SIZE	0x100000UL
#define MADV_REMOVE_ADVICE	9UL

/* The shape of madvise's table entry; its sanitiser needs the OBJ_MMAP
 * pools, which the test binary does not have. */
static struct syscallentry madvise_entry = {
	.name = "madvise",
	.num_args = 3,
	.argtype = { ARG_MMAP, ARG_LEN, ARG_OP },
	.is_madvise = true,
};

/* Same slots, not madvise. */
static struct syscallentry other_entry = {
	.name = "mprotect",
	.num_args = 3,
	.argtype = { ARG_MMAP, ARG_LEN, ARG_OP },
};

static struct syscallrecord rec;

/* Run the validator over one call and leave the final slots in rec. */
static void validated(struct syscallentry *entry, unsigned long addr,
		      unsigned long len)
{
	memset(&rec, 0, sizeof(rec));
	rec.entry = entry;
	rec.a1 = addr;
	rec.a2 = len;
	rec.a3 = MADV_REMOVE_ADVICE;

	if (validate_arg_coupling(&rec) != 0)
		BUG("arg coupling: a call with no rule against it was refused");
	if (rec.a3 != MADV_REMOVE_ADVICE)
		BUG("arg coupling: the advice slot was rewritten");
}

static void expect_zeroed(unsigned long addr, unsigned long len)
{
	validated(&madvise_entry, addr, len);
	if (rec.a1 != 0 || rec.a2 != 0)
		BUG("arg coupling: madvise range reaching a tracked region was kept");
}

static void expect_kept(struct syscallentry *entry, unsigned long addr,
			unsigned long len)
{
	validated(entry, addr, len);
	if (rec.a1 != addr || rec.a2 != len)
		BUG("arg coupling: a range the rule has no reason to touch was rewritten");
}

/* The range the kernel will read is held to what the sanitiser would have
 * accepted: nothing of trinity's own, nothing of the libc heap. */
static void madvise_range_held_off_regions(void)
{
	fake_untrack_regions();
	fake_track_region(REGION, REGION_SIZE);

	/* Wholly inside the region, and a length that grows a clean start
	 * into it: the two things a pin or a substituted return value do. */
	expect_zeroed(REGION + 0x1000, 0x1000);
	expect_zeroed(REGION - 0x10000, 0x7ffff000UL);
	expect_zeroed(REGION - 0x1000, 0x2000);
	expect_zeroed(REGION + REGION_SIZE - 0x1000, 0x10000);

	/* A range that wraps the address space is refused as the sanitiser
	 * refuses it, whatever it started as. */
	expect_zeroed(ULONG_MAX - 0xfffUL, 0x4000);

	/* Clear ranges, below and above the region, keep both slots. */
	expect_kept(&madvise_entry, REGION - 0x10000, 0x1000);
	expect_kept(&madvise_entry, REGION + REGION_SIZE, 0x1000);
	expect_kept(&madvise_entry, 0x10000000UL, 0x4000);

	/* Any other entry with the same slots is not this rule's. */
	expect_kept(&other_entry, REGION + 0x1000, 0x1000);
	expect_kept(&other_entry, REGION - 0x10000, 0x7ffff000UL);

	/* The libc heap is held off the same way. */
	fake_overlaps_libc_heap = true;
	expect_zeroed(0x10000000UL, 0x4000);
	expect_kept(&other_entry, 0x10000000UL, 0x4000);
	fake_overlaps_libc_heap = false;

	fake_untrack_regions();
}

/* The entries that set buf_count_slot whose TUs this binary links, with the
 * slot the kernel's own signature puts the count in; the buffer is the slot
 * before it.  getrandom's sanitiser needs the OBJ_MMAP pools, so its shape
 * is built by hand below. */
static struct {
	struct syscallentry *entry;
	unsigned int slot;
} const count_entries[] = {
	{ &syscall_read, 3 },
	{ &syscall_pread64, 3 },
	{ &syscall_mq_timedreceive, 3 },
	{ &syscall_getxattr, 4 },
	{ &syscall_lgetxattr, 4 },
	{ &syscall_fgetxattr, 4 },
	{ &syscall_listxattr, 3 },
	{ &syscall_llistxattr, 3 },
	{ &syscall_flistxattr, 3 },
	{ &syscall_listxattrat, 5 },
};

/* buf_count_slot is checked at startup: a slot that cannot have a buffer
 * before it, or one that holds no address, would aim the rule at the wrong
 * argument.  The real entries that set it pass. */
static void count_slot_checked_at_table_init(void)
{
	unsigned int i;
	struct syscallentry entry = {
		.name = "count_slot_probe",
		.num_args = 3,
		.argname = { "a1", "a2", "a3" },
		.argtype = { ARG_FD, ARG_ADDRESS, ARG_LEN },
		.buf_count_slot = 3,
	};

	if (entry_check_status(&entry) != 0)
		BUG("sanity_check_tables: refused a count slot after an address");
	entry.argtype[1] = ARG_NON_NULL_ADDRESS;
	if (entry_check_status(&entry) != 0)
		BUG("sanity_check_tables: refused a count slot after a non-null address");
	entry.argtype[1] = ARG_MMAP;
	if (entry_check_status(&entry) != 0)
		BUG("sanity_check_tables: refused a count slot after a map");

	entry.argtype[1] = ARG_PID;
	if (entry_check_status(&entry) != EXIT_FAILURE)
		BUG("sanity_check_tables: accepted a count slot after a pid");
	entry.argtype[1] = ARG_ADDRESS;
	entry.buf_count_slot = 1;
	if (entry_check_status(&entry) != EXIT_FAILURE)
		BUG("sanity_check_tables: accepted a count slot with no slot before it");
	entry.buf_count_slot = 4;
	if (entry_check_status(&entry) != EXIT_FAILURE)
		BUG("sanity_check_tables: accepted a count slot past num_args");

	for (i = 0; i < ARRAY_SIZE(count_entries); i++) {
		if (count_entries[i].entry->buf_count_slot != count_entries[i].slot)
			BUG("arg coupling: an entry lost its count slot, or names the wrong one");
		if (entry_check_status(count_entries[i].entry) != 0)
			BUG("sanity_check_tables: refused a real entry's count slot");
	}
}

/* Slot n of the record, 1-based. */
static unsigned long *slot_of(unsigned int slot)
{
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };

	return slots[slot - 1];
}

/* What the kernel will be given for the count, after the validator. */
static unsigned long count_after(struct syscallentry *entry, unsigned int slot,
				 unsigned long buf, unsigned long count)
{
	memset(&rec, 0, sizeof(rec));
	rec.entry = entry;
	*slot_of(slot - 1) = buf;
	*slot_of(slot) = count;

	if (validate_arg_coupling(&rec) != 0)
		BUG("arg coupling: a read-class call was refused");
	if (*slot_of(slot - 1) != buf)
		BUG("arg coupling: the buffer slot was rewritten");
	return *slot_of(slot);
}

#define SANITISER_DRAWS	500

/* What the generator leaves in the count slot for a sanitiser to size:
 * ARG_LEN's boundaries, and more than a pool holds. */
static const unsigned long generated_counts[] = {
	0, 1, 64, 4095, 4096, 4097, 1UL << 16, WRITABLE_POOL_BYTES + 1,
	0x7ffff000UL, 0xffffffffUL, ~0UL,
};

/* A call the sanitiser built goes through as it is. */
static void vetted_count_kept(struct syscallentry *entry, unsigned int slot,
			      unsigned long pool)
{
	unsigned int i;

	for (i = 0; i < SANITISER_DRAWS; i++) {
		unsigned long buf, count;

		memset(&rec, 0, sizeof(rec));
		rec.entry = entry;
		*slot_of(slot - 1) = (unsigned long) get_writable_address(page_size);
		*slot_of(slot) = RAND_ARRAY(generated_counts);
		entry->sanitise(&rec);
		buf = *slot_of(slot - 1);
		count = *slot_of(slot);

		/* The snapshot a post handler would have released. */
		free((void *) rec.post_state);
		rec.post_state = 0;

		if (buf != 0 && (buf < pool || buf >= pool + WRITABLE_POOL_BYTES))
			BUG("arg coupling: a sanitised buffer left the pool");
		if (validate_arg_coupling(&rec) != 0 ||
		    *slot_of(slot - 1) != buf || *slot_of(slot) != count)
			BUG("arg coupling: a count the sanitiser sized was rewritten");
	}
}

/* The count is cut where the write would leave the buffer's region for
 * another tracked one or the heap, and only there. */
static void count_held_inside_buffer(void)
{
	struct syscallentry unmarked = syscall_read;
	struct syscallentry getrandom_shape = {
		.name = "getrandom",
		.num_args = 3,
		.argtype = { ARG_MMAP, ARG_LEN, ARG_LIST },
		.buf_count_slot = 2,
	};
	const unsigned long tail = 0x800;
	unsigned long pool, end;
	unsigned int e;

	writable_pool_init();
	pool = (unsigned long) get_writable_address(WRITABLE_POOL_BYTES);
	end = pool + WRITABLE_POOL_BYTES;
	unmarked.buf_count_slot = 0;

	fake_untrack_regions();
	fake_track_region(pool, WRITABLE_POOL_BYTES);
	fake_track_region(end, 0x10000);

	for (e = 0; e < ARRAY_SIZE(count_entries); e++) {
		struct syscallentry *entry = count_entries[e].entry;
		unsigned int slot = count_entries[e].slot;

		vetted_count_kept(entry, slot, pool);

		/* A count of the buffer's last bytes, a longer one, and the
		 * values a rewrite brings: MAX_RW_COUNT, a pid, a whole
		 * pool and a bit more, an address. */
		if (count_after(entry, slot, end - tail, tail) != tail)
			BUG("arg coupling: a count that fits the region was cut");
		if (count_after(entry, slot, end - tail, tail + 1) != tail)
			BUG("arg coupling: a count one byte past the region was kept");
		if (count_after(entry, slot, end - tail, 0x7ffff000UL) != tail)
			BUG("arg coupling: MAX_RW_COUNT was kept");
		if (count_after(entry, slot, pool, 3000000UL) != WRITABLE_POOL_BYTES)
			BUG("arg coupling: a pid-sized count was not cut to the pool");
		if (count_after(entry, slot, pool, WRITABLE_POOL_BYTES) != WRITABLE_POOL_BYTES ||
		    count_after(entry, slot, pool + 0x1000, 0x1000) != 0x1000)
			BUG("arg coupling: a count inside the pool was cut");
		if (count_after(entry, slot, pool, 0x7f0000001000UL) != WRITABLE_POOL_BYTES)
			BUG("arg coupling: an address-sized count was not cut to the pool");

		/* An empty count and an empty buffer are not this rule's. */
		if (count_after(entry, slot, end - tail, 0) != 0 ||
		    count_after(entry, slot, 0, 0x7ffff000UL) != 0x7ffff000UL)
			BUG("arg coupling: an empty count or buffer was judged");

		/* Past the region into nothing tracked is left to the kernel's
		 * own checks, unless the heap is there. */
		fake_untrack_regions();
		fake_track_region(pool, WRITABLE_POOL_BYTES);
		if (count_after(entry, slot, end - tail, 0x7ffff000UL) != 0x7ffff000UL)
			BUG("arg coupling: a count running into unmapped memory was cut");
		fake_overlaps_libc_heap = true;
		if (count_after(entry, slot, end - tail, 0x7ffff000UL) != tail)
			BUG("arg coupling: a count running into the heap was kept");
		fake_overlaps_libc_heap = false;
		fake_track_region(end, 0x10000);

		/* A buffer in no tracked region has no extent: a count that
		 * reaches one is 0. */
		if (count_after(entry, slot, 0x10000000UL, 0x4000) != 0x4000)
			BUG("arg coupling: a clear untracked buffer was cut");
		fake_overlaps_shared = true;
		if (count_after(entry, slot, 0x10000000UL, 0x4000) != 0)
			BUG("arg coupling: an untracked buffer reaching a region kept its count");
		fake_overlaps_shared = false;
	}

	/* An entry that does not carry the slot keeps whatever it has. */
	if (count_after(&unmarked, 3, end - tail, 0x7ffff000UL) != 0x7ffff000UL)
		BUG("arg coupling: an entry with no count slot was judged");

	/* getrandom's buffer is a map, so the slots are one earlier. */
	if (count_after(&getrandom_shape, 2, end - tail, 0x7ffff000UL) != tail)
		BUG("arg coupling: a count in slot 2 was not held to its buffer");
	fake_overlaps_shared = true;
	if (count_after(&getrandom_shape, 2, 0x10000000UL, 0x4000) != 0)
		BUG("arg coupling: a map buffer reaching a region kept its count");
	fake_overlaps_shared = false;

	fake_untrack_regions();
}

/* A pool mapping for the mm sanitisers to pick, away from every region a
 * test tracks; ARG_MMAP leaves its struct map in a1.
 * common_set_mmap_ptr_len() works on this_child()'s record, so the calls
 * are built there. */
#define POOL_MAP	0x7e0000000000UL
#define POOL_PAGES	16UL

static struct object pool_obj;
static struct childdata mm_child;

static struct syscallrecord *mm_call(struct syscallentry *entry)
{
	struct syscallrecord *mrec = &mm_child.syscall;

	memset(mrec, 0, sizeof(*mrec));
	mrec->entry = entry;
	mrec->a1 = (unsigned long) &pool_obj.map;
	pool_obj.map.ptr = (void *) POOL_MAP;
	pool_obj.map.size = POOL_PAGES * page_size;
	pool_obj.map.tracked_size = pool_obj.map.size;
	pool_obj.map.prot = PROT_READ | PROT_WRITE;
	fake_this_child = &mm_child;
	return mrec;
}

#define LIVE_PKEY	7

/* pkey_mprotect shares mprotect's sanitiser, which draws a live key for
 * the fourth slot only for it and names it in the heap-slip line.  The
 * record points at the table's copy of the descriptor, not at
 * syscall_pkey_mprotect, so the sanitiser has to know the entry by the
 * byte copy_syscall_table() stamps on the copy. */
static void pkey_mprotect_known_through_its_copy(void)
{
	struct syscallentry pkey_copy = syscall_pkey_mprotect;
	struct syscallentry plain_copy = syscall_mprotect;
	struct syscallentry *const copies[] = { &pkey_copy, &plain_copy };
	unsigned int c, i, live;

	pkey_copy.is_pkey_mprotect = true;
	pkey_drawn = LIVE_PKEY;

	for (c = 0; c < ARRAY_SIZE(copies); c++) {
		struct syscallentry *entry = copies[c];

		live = 0;
		for (i = 0; i < 100; i++) {
			struct syscallrecord *mrec = mm_call(entry);

			mrec->a4 = ~0UL;
			heap_slip_name = NULL;
			entry->sanitise(mrec);
			if (heap_slip_name == NULL ||
			    strcmp(heap_slip_name, entry->name) != 0)
				BUG("mprotect: the heap-slip line named another entry");
			if (mrec->a4 == LIVE_PKEY)
				live++;
			/* A refused call: the post handler releases the
			 * snapshot and leaves the mapping alone. */
			mrec->retval = (unsigned long) -1L;
			entry->post(mrec);
		}
		if (entry->is_pkey_mprotect ? live == 0 : live != 0)
			BUG("mprotect: a live key went to the wrong entry");
	}

	pkey_drawn = -1;
	fake_this_child = NULL;
}

/* The mapping's cached prot after a call that worked with a4 = @key: a
 * read-write mapping, @size long, made read-write again over a range the
 * sanitiser drew.  A mapping of a page or more gets a range that is not
 * empty; under a page the range can only be empty. */
static int prot_after_keyed_call(struct syscallentry *entry, int key,
				 unsigned long size)
{
	struct syscallrecord *mrec;

	pkey_drawn = key;
	for (;;) {
		mrec = mm_call(entry);
		pool_obj.map.size = size;
		pool_obj.map.tracked_size = size;
		mrec->a3 = PROT_READ | PROT_WRITE;
		mrec->a4 = (unsigned long) key;
		entry->sanitise(mrec);
		if (mrec->a2 != 0 || size < page_size)
			break;
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);
	}
	mrec->retval = 0;
	entry->post(mrec);
	pkey_drawn = -1;
	return pool_obj.map.prot;
}

/* A key's access rights live in this thread's PKRU, not in the prot
 * bits, so a range pkey_mprotect gave a live key leaves the mapping's
 * cached prot nothing to vouch for.  Key 0, the default, -1, which keeps
 * the pages' own, and plain mprotect, which has no key slot, leave it to
 * the prot bits, and so does an empty range, which the kernel returns 0
 * for before it reads the key. */
static void keyed_range_drops_cached_prot(void)
{
	struct syscallentry pkey_copy = syscall_pkey_mprotect;
	struct syscallentry plain_copy = syscall_mprotect;
	const unsigned long whole = POOL_PAGES * page_size;
	const int rw = PROT_READ | PROT_WRITE;

	pkey_copy.is_pkey_mprotect = true;
	if (prot_after_keyed_call(&pkey_copy, LIVE_PKEY, whole) != 0)
		BUG("mprotect: a range given a live key kept its cached prot");
	if (prot_after_keyed_call(&pkey_copy, LIVE_PKEY, page_size / 2) != rw)
		BUG("mprotect: a call that changed nothing dropped the cached prot");
	if (prot_after_keyed_call(&pkey_copy, 0, whole) != rw ||
	    prot_after_keyed_call(&pkey_copy, -1, whole) != rw)
		BUG("mprotect: a range left on the default key lost its cached prot");
	if (prot_after_keyed_call(&plain_copy, LIVE_PKEY, whole) != rw)
		BUG("mprotect: plain mprotect's fourth slot was taken for a key");
	fake_this_child = NULL;
}

void arg_coupling_self_check(void);
void arg_coupling_self_check(void)
{
	madvise_range_held_off_regions();
	count_slot_checked_at_table_init();
	count_held_inside_buffer();
	pkey_mprotect_known_through_its_copy();
	keyed_range_drops_cached_prot();
}
