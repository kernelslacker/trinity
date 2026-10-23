/*
 * Self-check for the per-syscall rules validate_arg_coupling() holds the
 * final argument slots to: a rewrite after the sanitiser (chain
 * substitution, a RedQueen pin) must not leave the kernel a range the
 * sanitiser would have refused.  A buffer-filling count stays inside its
 * buffer, a munmap, mprotect, pkey_mprotect or madvise range inside the
 * pool mapping its sanitiser picked, madvise's (addr, len) off trinity's
 * tracked regions too, and a madvise never installs guard pages.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <linux/mempolicy.h>

#include "arch.h"				/* page_size */
#include "arg_coupling.h"
#include "child.h"			/* struct childdata */
#include "debug.h"			/* BUG */
#include "files.h"			/* get_rand_pagecache_fd */
#include "kernel/mman.h"		/* MADV_GUARD_INSTALL */
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
extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */
extern const void *post_state_disowned;	/* post_oracle_test.c */

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

/* The OBJ_PKEY pool, the heap-slip log, the /proc/self/maps oracle and
 * the pool invalidation the mm sanitisers and post handlers reach.  The
 * pool hands out pkey_drawn, the log keeps the name it was given, and the
 * oracle and the invalidation the range they were handed. */
static int pkey_drawn = -1;
static const char *heap_slip_name;
static unsigned long maps_checked_addr, maps_checked_len;
static unsigned int maps_checks;
static unsigned long invalidated_addr, invalidated_len;
static unsigned int invalidations;

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
	(void) expected_prot;
	(void) expect_present;
	maps_checked_addr = addr;
	maps_checked_len = len;
	maps_checks++;
	return true;
}

unsigned int invalidate_obj_mmap_in_range(unsigned long addr,
					  unsigned long len)
{
	invalidated_addr = addr;
	invalidated_len = len;
	invalidations++;
	return 0;
}

#define REGION		0x7f0000000000UL
#define REGION_SIZE	0x100000UL
#define MADV_REMOVE_ADVICE	9UL

/* Same slots as madvise, and no rule of its own. */
static struct syscallentry other_entry = {
	.name = "probe",
	.num_args = 3,
	.argtype = { ARG_MMAP, ARG_LEN, ARG_OP },
};

static struct syscallrecord rec;

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

/* shmat's sanitiser picks its mapping with get_map(), whose stand-in
 * hands out this. */
extern struct map *fake_map_drawn;	/* post_oracle_test.c */

/* A SysV segment two pages long for shmat's sanitiser to size, made on
 * first use and removed at once, so it goes with the test binary; the
 * attach made here keeps it until then.  -1 with no SysV shared memory. */
static int shm_test_segment(void)
{
	static int shmid = -2;
	void *attached;

	if (shmid != -2)
		return shmid;
	shmid = shmget(IPC_PRIVATE, 2 * page_size, IPC_CREAT | 0600);
	if (shmid < 0)
		return shmid;
	attached = shmat(shmid, NULL, SHM_RDONLY);
	shmctl(shmid, IPC_RMID, NULL);
	if (attached == (void *) -1)
		BUG("shmat: the test's own segment would not attach");
	return shmid;
}

/* How many of SANITISER_DRAWS calls that shmat's sanitiser builds for
 * segment @shmid, each drawn with SHM_REMAP, keep it.  A kept one attaches
 * at the start of the mapping fake_map_drawn names, and a dropped one
 * where the kernel picks. */
static unsigned int shmat_remaps_kept(int shmid, bool compat)
{
	unsigned int i, kept = 0;

	for (i = 0; i < SANITISER_DRAWS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_shmat;
		rec.do32bit = compat;
		rec.a1 = (unsigned long) shmid;
		rec.a3 = SHM_REMAP;
		syscall_shmat.sanitise(&rec);
		if (!(rec.a3 & SHM_REMAP)) {
			if (rec.a2 != 0)
				BUG("shmat: a dropped SHM_REMAP left an address an attach can only fail at");
			continue;
		}
		if (fake_map_drawn == NULL ||
		    rec.a2 != (unsigned long) fake_map_drawn->ptr)
			BUG("shmat: SHM_REMAP was kept for an address other than the mapping's");
		kept++;
	}
	return kept;
}

/* shmat attaches at the start of the mapping its sanitiser picked, one call
 * in five, and never at the page holding the struct map.  It keeps
 * SHM_REMAP, which replaces what the attach lands on, only for a segment
 * that fits there whole: not one longer than the mapping, nor one a huge
 * page the address admits would round past it, nor over a tracked region,
 * nor where a compat call's 32-bit slot cannot reach, nor one IPC_STAT
 * cannot size, and with no mapping not at all. */
static void shmat_remap_held_to_mapping(void)
{
	int shmid = shm_test_segment();
	unsigned int i, at_map = 0;

	if (shmid < 0) {
		printf("(no SysV shared memory, skipping shmat) ");
		return;
	}

	fake_map_drawn = &pool_obj.map;
	pool_obj.map.ptr = (void *) (POOL_MAP + page_size);
	pool_obj.map.size = 4 * page_size;
	for (i = 0; i < SANITISER_DRAWS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_shmat;
		rec.a1 = (unsigned long) shmid;
		syscall_shmat.sanitise(&rec);
		if (rec.a2 == (unsigned long) pool_obj.map.ptr)
			at_map++;
		else if (rec.a2 != 0)
			BUG("shmat: an attach was aimed at an address other than the mapping's");
	}
	if (at_map < SANITISER_DRAWS / 10 || at_map > SANITISER_DRAWS / 3)
		BUG("shmat: the attach address lost its split between NULL and the mapping");
	if (shmat_remaps_kept(shmid, false) == 0)
		BUG("shmat: SHM_REMAP was never kept for a segment that fits");

	pool_obj.map.size = page_size;
	if (shmat_remaps_kept(shmid, false) != 0)
		BUG("shmat: SHM_REMAP was kept for a segment longer than the mapping");
	pool_obj.map.size = 4 * page_size;

	fake_track_region(POOL_MAP, 8 * page_size);
	if (shmat_remaps_kept(shmid, false) != 0)
		BUG("shmat: SHM_REMAP was kept over a tracked region");
	fake_untrack_regions();

	if (shmat_remaps_kept(shmid, true) != 0)
		BUG("shmat: SHM_REMAP was kept for a compat call its slot cannot carry");
	pool_obj.map.ptr = (void *) 0x40001000UL;
	if (shmat_remaps_kept(shmid, true) == 0)
		BUG("shmat: SHM_REMAP was never kept for a compat call under 4 GiB");

	/* 2 MiB divides this address, so the segment could be a hugetlb one
	 * whose 2 MiB pages the attach rounds it up to. */
	pool_obj.map.ptr = (void *) (POOL_MAP + MB(2));
	pool_obj.map.size = MB(1);
	if (shmat_remaps_kept(shmid, false) != 0)
		BUG("shmat: SHM_REMAP was kept where a huge page the address admits runs past the mapping");
	pool_obj.map.size = MB(2);
	if (shmat_remaps_kept(shmid, false) == 0)
		BUG("shmat: SHM_REMAP was never kept for a mapping a huge page fits");

	if (shmat_remaps_kept(-1, false) != 0)
		BUG("shmat: SHM_REMAP was kept for a segment IPC_STAT cannot size");
	fake_map_drawn = NULL;
	if (shmat_remaps_kept(shmid, false) != 0)
		BUG("shmat: SHM_REMAP was kept with no mapping picked");
}

/* get_mempolicy's sanitiser turns the ARG_MMAP handle in addr into the
 * start of the mapping it names when the flags carry MPOL_F_ADDR, the one
 * flag the kernel reads addr under, and into 0 otherwise, since
 * do_get_mempolicy() refuses any other address without it.  Never into
 * the struct map, nor anything with no mapping picked. */
static void get_mempolicy_addr_names_mapping(void)
{
	static const unsigned long flags[] = {
		0, MPOL_F_ADDR, MPOL_F_NODE, MPOL_F_NODE | MPOL_F_ADDR,
		MPOL_F_MEMS_ALLOWED,
	};
	unsigned int i, m;

	for (m = 0; m < 2; m++) {
		for (i = 0; i < ARRAY_SIZE(flags); i++) {
			struct syscallrecord *mrec = mm_call(&syscall_get_mempolicy);
			unsigned long want = 0;

			mrec->a1 = 0;
			mrec->a3 = 64;
			mrec->a4 = m ? (unsigned long) &pool_obj.map : 0;
			mrec->a5 = flags[i];
			if (m && (flags[i] & MPOL_F_ADDR))
				want = POOL_MAP;
			syscall_get_mempolicy.sanitise(mrec);
			if (mrec->a4 != want)
				BUG("get_mempolicy: addr is not the mapping's start under MPOL_F_ADDR, nor 0 without it");
			mrec->retval = (unsigned long) -1L;
			syscall_get_mempolicy.post(mrec);
		}
	}
	fake_this_child = NULL;
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

/* No pool holds the test mapping.  munmap's sanitiser asks, to know
 * which pool a whole-mapping unmap takes the entry out of. */
static struct objhead *no_pool(enum obj_scope scope, enum objecttype type)
{
	(void) scope;
	(void) type;
	return NULL;
}

#define MM_DRAWS	500

/* Whatever the sanitiser builds is a range it vetted, a whole-mapping
 * unmap included: of a mapping as it was made, of a file mapping clamped
 * below its VMA, of one whose tracked size was never set, and of one an
 * mremap() grow left larger than its tracked size.  A compat call over
 * the high mapping is built empty rather than refused. */
static void munmap_sanitised_range_passes(struct syscallentry *entry)
{
	unsigned int i;

	for (i = 0; i < MM_DRAWS; i++) {
		struct syscallrecord *mrec = mm_call(entry);

		switch (i % 4) {
		case 1:
			pool_obj.map.size = 5 * page_size + 100;
			pool_obj.map.tracked_size = 8 * page_size;
			break;
		case 2:
			pool_obj.map.size = 5 * page_size + 100;
			pool_obj.map.tracked_size = 0;
			break;
		case 3:
			pool_obj.map.size = 2 * POOL_PAGES * page_size;
			break;
		}
		mrec->do32bit = (i % 10) == 0;
		entry->sanitise(mrec);
		if (mrec->do32bit && (mrec->a1 != 0 || mrec->a2 != 0))
			BUG("munmap: the sanitiser built a compat range its slots cannot carry");
		if (validate_arg_coupling(mrec) != 0)
			BUG("munmap: a range the sanitiser built was refused");
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);
	}
}

/* A rewritten slot that runs the range past the mapping, or moves it out,
 * is refused, whatever brought it: a page too many, a pid, an address.  A
 * range still inside passes, and so does one the kernel acts on nothing
 * of: empty, unaligned, wrapping. */
static void munmap_rewritten_range_held(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);
	unsigned long end = POOL_MAP + POOL_PAGES * page_size;
	unsigned long start, left;
	static const struct {
		unsigned int slot;
		unsigned long value;
		int verdict;
	} cases[] = {
		{ 2, 0x7ffff000UL, -1 },
		{ 2, 3000000UL, -1 },
		{ 2, 0, 0 },
		{ 2, ~0UL, 0 },
		{ 2, ~0UL - 0x1000UL, 0 },
		{ 1, POOL_MAP - 0x1000UL, -1 },
		{ 1, 0x10000000UL, -1 },
		{ 1, POOL_MAP + 1, 0 },
	};
	unsigned int i;

	entry->sanitise(mrec);
	start = mrec->a1;
	left = end - start;

	mrec->a2 = left + page_size;
	if (validate_arg_coupling(mrec) != -1)
		BUG("munmap: a length running a page past the mapping was kept");
	mrec->a2 = left;
	if (validate_arg_coupling(mrec) != 0)
		BUG("munmap: a length reaching the end of the mapping was refused");
	mrec->a2 = left - page_size + 1;
	if (validate_arg_coupling(mrec) != 0)
		BUG("munmap: a length the kernel rounds to the end was refused");
	mrec->a1 = end;
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec) != -1)
		BUG("munmap: a range just past the mapping was kept");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		mrec->a1 = start;
		mrec->a2 = page_size;
		if (cases[i].slot == 1)
			mrec->a1 = cases[i].value;
		else
			mrec->a2 = cases[i].value;
		if (validate_arg_coupling(mrec) != cases[i].verdict)
			BUG("munmap: a rewritten slot was judged wrongly");
	}

	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);
}

/* A call that passes leaves the post handler the range the kernel was
 * handed: the oracle it runs on one call in a hundred asks about the
 * final slots, not the ones the sanitiser drew. */
static void munmap_post_acts_on_final_range(struct syscallentry *entry)
{
	unsigned long final_addr = 0;
	unsigned int i;

	maps_checks = 0;
	for (i = 0; i < 10000 && maps_checks == 0; i++) {
		struct syscallrecord *mrec = mm_call(entry);

		entry->sanitise(mrec);
		mrec->a2 = page_size - 1;
		if (validate_arg_coupling(mrec) != 0)
			BUG("munmap: a page inside the mapping was refused");
		final_addr = mrec->a1;
		mrec->retval = 0;
		entry->post(mrec);
	}
	if (maps_checks == 0)
		BUG("munmap: the post handler never asked the oracle");
	if (maps_checked_addr != final_addr ||
	    maps_checked_len != page_size - 1)
		BUG("munmap: the post handler acted on the range sanitise drew");
}

/* Nothing names a mapping without the call's own snapshot: none, a pid
 * where the pointer was, one the ownership table does not hold, or one
 * with another magic.  Only a range the kernel acts on nothing of goes
 * through then. */
static void munmap_needs_its_snapshot(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);
	unsigned long *snap;

	mrec->a1 = 0;
	entry->sanitise(mrec);
	if (mrec->post_state != 0)
		BUG("munmap: the sanitiser left a snapshot with no mapping");
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec) != -1)
		BUG("munmap: a call with no mapping kept a range");
	mrec->a2 = 0;
	if (validate_arg_coupling(mrec) != 0)
		BUG("munmap: an empty call with no mapping was refused");

	mrec = mm_call(entry);
	entry->sanitise(mrec);
	snap = (unsigned long *) mrec->post_state;
	mrec->a1 = POOL_MAP;
	mrec->a2 = page_size;
	mrec->post_state = 12345;
	if (validate_arg_coupling(mrec) != -1)
		BUG("munmap: a call whose snapshot is a pid was passed");
	mrec->post_state = (unsigned long) snap;
	post_state_disowned = snap;
	if (validate_arg_coupling(mrec) != -1)
		BUG("munmap: a call whose snapshot is not owned was passed");
	post_state_disowned = NULL;
	*snap ^= 1UL;
	if (validate_arg_coupling(mrec) != -1)
		BUG("munmap: a call whose snapshot has the wrong magic was passed");
	*snap ^= 1UL;
	if (validate_arg_coupling(mrec) != 0)
		BUG("munmap: a call refused for its snapshot was refused once it was whole");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);
}

/* A compat call hands the kernel the low 32 bits of each slot, so the
 * range is judged on those: a high mapping's address truncates to
 * somewhere else, and an upper half on a low mapping's slots drops.  The
 * sanitiser builds a real compat range over a low mapping. */
#define LOW_POOL_MAP	0x40000000UL

static void munmap_compat_slots_truncated(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);

	entry->sanitise(mrec);
	mrec->a1 = POOL_MAP;
	mrec->a2 = page_size;
	mrec->do32bit = true;
	if (validate_arg_coupling(mrec) != -1)
		BUG("munmap: a compat call was judged on the slots' upper halves");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);

	mrec = mm_call(entry);
	pool_obj.map.ptr = (void *) LOW_POOL_MAP;
	mrec->do32bit = true;
	entry->sanitise(mrec);
	if (mrec->a1 < LOW_POOL_MAP || validate_arg_coupling(mrec) != 0)
		BUG("munmap: a compat call over a low mapping was emptied or refused");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);

	mrec = mm_call(entry);
	pool_obj.map.ptr = (void *) LOW_POOL_MAP;
	entry->sanitise(mrec);
	mrec->a1 = LOW_POOL_MAP | (1UL << 32);
	mrec->a2 = page_size | (1UL << 32);
	if (validate_arg_coupling(mrec) != -1)
		BUG("munmap: a native call's upper halves were dropped");
	mrec->do32bit = true;
	if (validate_arg_coupling(mrec) != 0)
		BUG("munmap: a compat call inside a low mapping was refused");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);
}

/* munmap's final range stays inside the mapping its sanitiser picked. */
static void munmap_range_held_to_mapping(void)
{
	struct syscallentry munmap_entry = syscall_munmap;
	struct syscallentry other = syscall_munmap;

	/* As copy_syscall_table() stamps the copy. */
	munmap_entry.is_munmap = true;
	fake_get_objhead = no_pool;

	munmap_sanitised_range_passes(&munmap_entry);
	munmap_rewritten_range_held(&munmap_entry);
	munmap_post_acts_on_final_range(&munmap_entry);
	munmap_needs_its_snapshot(&munmap_entry);
	munmap_compat_slots_truncated(&munmap_entry);

	/* The rule is munmap's alone. */
	mm_call(&other)->a2 = 0x7ffff000UL;
	if (validate_arg_coupling(&mm_child.syscall) != 0)
		BUG("munmap: the range rule judged an entry that is not munmap");

	fake_get_objhead = NULL;
	fake_this_child = NULL;
}

/* The mapping's cached prot after a call whose range the sanitiser drew
 * from a mapping with @prot_before, over prot @prot, that was rewritten to
 * the final slots @len, @final_prot and @key, and worked. */
static int prot_after_rewrite(struct syscallentry *entry, int prot_before,
			      unsigned long prot, unsigned long len,
			      unsigned long final_prot, unsigned long key)
{
	struct syscallrecord *mrec = mm_call(entry);

	pool_obj.map.prot = prot_before;
	mrec->a3 = prot;
	mrec->a4 = ~0UL;
	entry->sanitise(mrec);
	mrec->a2 = len;
	mrec->a3 = final_prot;
	mrec->a4 = key;
	if (validate_arg_coupling(mrec) != 0)
		BUG("mprotect: a range inside the mapping was refused");
	mrec->retval = 0;
	entry->post(mrec);
	return pool_obj.map.prot;
}

/* mprotect's and pkey_mprotect's final range stays inside the mapping the
 * sanitiser picked, and the prot and key the post handler caches are the
 * ones the kernel was handed. */
static void mprotect_range_held_to_mapping(void)
{
	struct syscallentry mprotect_entry = syscall_mprotect;
	struct syscallentry pkey_entry = syscall_pkey_mprotect;
	struct syscallentry *const entries[] = { &mprotect_entry, &pkey_entry };
	const unsigned long whole = POOL_PAGES * page_size;
	const int rw = PROT_READ | PROT_WRITE;
	unsigned int e, i;

	/* As copy_syscall_table() stamps the copies. */
	mprotect_entry.is_mprotect_family = true;
	pkey_entry.is_mprotect_family = true;
	pkey_entry.is_pkey_mprotect = true;

	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		struct syscallentry *entry = entries[e];
		struct syscallrecord *mrec;

		/* Over a mapping an mremap() grow left larger than its
		 * tracked size too; a compat call over the high mapping is
		 * built empty rather than refused. */
		for (i = 0; i < MM_DRAWS; i++) {
			mrec = mm_call(entry);
			if (i & 1)
				pool_obj.map.size = 2 * POOL_PAGES * page_size;
			mrec->do32bit = (i % 10) == 0;
			entry->sanitise(mrec);
			if (mrec->do32bit && (mrec->a1 != 0 || mrec->a2 != 0))
				BUG("mprotect: the sanitiser built a compat range its slots cannot carry");
			if (validate_arg_coupling(mrec) != 0)
				BUG("mprotect: a range the sanitiser built was refused");
			mrec->retval = (unsigned long) -1L;
			entry->post(mrec);
		}

		/* The sanitiser starts the range at the mapping. */
		mrec = mm_call(entry);
		entry->sanitise(mrec);
		mrec->a2 = whole + page_size;
		if (validate_arg_coupling(mrec) != -1)
			BUG("mprotect: a length running past the mapping was kept");
		mrec->a2 = whole;
		if (validate_arg_coupling(mrec) != 0)
			BUG("mprotect: a length covering the mapping was refused");
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);

		mrec = mm_call(entry);
		mrec->a1 = 0;
		entry->sanitise(mrec);
		mrec->a2 = page_size;
		if (validate_arg_coupling(mrec) != -1)
			BUG("mprotect: a call with no mapping kept a range");

		/* Over part of the mapping the cached prot can only lose
		 * bits, over all of it it takes the new prot. */
		if (prot_after_rewrite(entry, rw, rw, page_size, PROT_READ,
				       ~0UL) != PROT_READ)
			BUG("mprotect: the post handler cached the prot sanitise drew");
		if (prot_after_rewrite(entry, PROT_READ, PROT_READ, whole, rw,
				       ~0UL) != rw)
			BUG("mprotect: the post handler took a whole-mapping call for a part");
	}

	/* A live key put in pkey_mprotect's slot after the sanitiser leaves
	 * the cached prot nothing to vouch for. */
	if (prot_after_rewrite(&pkey_entry, rw, rw, page_size, rw,
			       LIVE_PKEY) != 0)
		BUG("pkey_mprotect: the post handler cached a prot over a key it never saw");

	fake_this_child = NULL;
}

/* Run the validator over a call whose slots end up (@addr, @len,
 * MADV_REMOVE) and leave the final slots in the record.  An entry with a
 * sanitiser builds the call first, over a pool mapping that starts at
 * @addr's page and runs past @len, so its snapshot names a mapping the
 * range lies in. */
static struct syscallrecord *validated(struct syscallentry *entry,
				       unsigned long addr, unsigned long len)
{
	struct syscallrecord *mrec = mm_call(entry);

	if (entry->sanitise != NULL) {
		pool_obj.map.ptr = (void *) (addr & PAGE_MASK);
		pool_obj.map.size = (len | (page_size - 1)) + 1;
		pool_obj.map.tracked_size = pool_obj.map.size;
		entry->sanitise(mrec);
	}
	mrec->a1 = addr;
	mrec->a2 = len;
	mrec->a3 = MADV_REMOVE_ADVICE;

	if (validate_arg_coupling(mrec) != 0)
		BUG("arg coupling: a call with no rule against it was refused");
	if (mrec->a3 != MADV_REMOVE_ADVICE)
		BUG("arg coupling: the advice slot was rewritten");
	if (entry->sanitise != NULL) {
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);
	}
	return mrec;
}

static void expect_zeroed(struct syscallentry *entry, unsigned long addr,
			  unsigned long len)
{
	struct syscallrecord *mrec = validated(entry, addr, len);

	if (mrec->a1 != 0 || mrec->a2 != 0)
		BUG("arg coupling: madvise range reaching a tracked region was kept");
}

static void expect_kept(struct syscallentry *entry, unsigned long addr,
			unsigned long len)
{
	struct syscallrecord *mrec = validated(entry, addr, len);

	if (mrec->a1 != addr || mrec->a2 != len)
		BUG("arg coupling: a range the rule has no reason to touch was rewritten");
}

/* The range the kernel will read is held to what the sanitiser would have
 * accepted: nothing of trinity's own, nothing of the libc heap.  A range
 * that reaches either is emptied, not refused, as the sanitiser empties
 * it; the initial anonymous mappings and mmap_fd()'s file mappings are
 * tracked regions as well as pool mappings, so the hold to the mapping
 * below does not make this redundant. */
static void madvise_range_held_off_regions(struct syscallentry *madvise_entry)
{
	fake_untrack_regions();
	fake_track_region(REGION, REGION_SIZE);

	/* Wholly inside the region, and a length that grows a clean start
	 * into it: the two things a pin or a substituted return value do. */
	expect_zeroed(madvise_entry, REGION + 0x1000, 0x1000);
	expect_zeroed(madvise_entry, REGION - 0x10000, 0x7ffff000UL);
	expect_zeroed(madvise_entry, REGION - 0x1000, 0x2000);
	expect_zeroed(madvise_entry, REGION + REGION_SIZE - 0x1000, 0x10000);

	/* A range that wraps the address space is refused as the sanitiser
	 * refuses it, whatever it started as. */
	expect_zeroed(madvise_entry, ULONG_MAX - 0xfffUL, 0x4000);

	/* Clear ranges, below and above the region, inside the call's own
	 * mapping keep both slots. */
	expect_kept(madvise_entry, REGION - 0x10000, 0x1000);
	expect_kept(madvise_entry, REGION + REGION_SIZE, 0x1000);
	expect_kept(madvise_entry, 0x10000000UL, 0x4000);

	/* Any other entry with the same slots is not this rule's. */
	expect_kept(&other_entry, REGION + 0x1000, 0x1000);
	expect_kept(&other_entry, REGION - 0x10000, 0x7ffff000UL);

	/* The libc heap is held off the same way. */
	fake_overlaps_libc_heap = true;
	expect_zeroed(madvise_entry, 0x10000000UL, 0x4000);
	expect_kept(&other_entry, 0x10000000UL, 0x4000);
	fake_overlaps_libc_heap = false;

	fake_untrack_regions();
}

/* What validate_arg_coupling() makes of a madvise the sanitiser built
 * over the pool mapping and a rewrite left at (@addr, @len, @advice). */
static int madvise_verdict(struct syscallentry *entry, unsigned long addr,
			   unsigned long len, unsigned long advice)
{
	struct syscallrecord *mrec = mm_call(entry);
	int verdict;

	entry->sanitise(mrec);
	mrec->a1 = addr;
	mrec->a2 = len;
	mrec->a3 = advice;
	verdict = validate_arg_coupling(mrec);
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);
	return verdict;
}

/* Whether the post handler invalidated the final range of a call that
 * worked, after its sanitiser drew an advice that @punched holes (or not)
 * and a rewrite left page_size - 1 bytes at the mapping and @advice. */
static bool madvise_post_invalidates(struct syscallentry *entry,
				     bool punched, unsigned long advice)
{
	struct syscallrecord *mrec;
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		mrec = mm_call(entry);
		entry->sanitise(mrec);
		if ((mrec->a3 == MADV_DONTNEED ||
		     mrec->a3 == MADV_DONTNEED_LOCKED ||
		     mrec->a3 == MADV_REMOVE || mrec->a3 == MADV_FREE) == punched)
			break;
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);
	}
	if (i == 1000)
		BUG("madvise: the sanitiser never drew the advice the case needs");

	mrec->a1 = POOL_MAP;
	mrec->a2 = page_size - 1;
	mrec->a3 = advice;
	if (validate_arg_coupling(mrec) != 0)
		BUG("madvise: a page of the mapping was refused");
	invalidations = 0;
	mrec->retval = 0;
	entry->post(mrec);
	if (invalidations != 0 &&
	    (invalidated_addr != POOL_MAP || invalidated_len != page_size - 1))
		BUG("madvise: the post handler invalidated the range sanitise drew");
	return invalidations != 0;
}

/* madvise's final range stays inside the mapping the sanitiser picked,
 * and a GUARD_INSTALL a rewrite puts in the advice acts on no range: its
 * guard pages would fault while the pool entry still claims them. */
static void madvise_range_held_to_mapping(struct syscallentry *madvise_entry)
{
	const unsigned long end = POOL_MAP + POOL_PAGES * page_size;
	const unsigned long guard = MADV_GUARD_INSTALL;
	struct syscallrecord *mrec;
	unsigned int i;

	/* Over a mapping an mremap() grow left larger than its tracked size
	 * too; a compat call over the high mapping is built empty rather
	 * than refused. */
	for (i = 0; i < MM_DRAWS; i++) {
		mrec = mm_call(madvise_entry);
		if (i & 1)
			pool_obj.map.size = 2 * POOL_PAGES * page_size;
		mrec->do32bit = (i % 10) == 0;
		madvise_entry->sanitise(mrec);
		if (mrec->do32bit && (mrec->a1 != 0 || mrec->a2 != 0))
			BUG("madvise: the sanitiser built a compat range its slots cannot carry");
		if (validate_arg_coupling(mrec) != 0)
			BUG("madvise: a call the sanitiser built was refused");
		mrec->retval = (unsigned long) -1L;
		madvise_entry->post(mrec);
	}

	if (madvise_verdict(madvise_entry, POOL_MAP, end - POOL_MAP + 1,
			    MADV_REMOVE_ADVICE) != -1 ||
	    madvise_verdict(madvise_entry, end, page_size,
			    MADV_REMOVE_ADVICE) != -1 ||
	    madvise_verdict(madvise_entry, POOL_MAP - page_size, 2 * page_size,
			    MADV_REMOVE_ADVICE) != -1)
		BUG("madvise: a range leaving the mapping was kept");
	if (madvise_verdict(madvise_entry, POOL_MAP, end - POOL_MAP,
			    MADV_REMOVE_ADVICE) != 0)
		BUG("madvise: a range covering the mapping was refused");

	/* The kernel reads the advice as an int. */
	if (madvise_verdict(madvise_entry, POOL_MAP, page_size, guard) != -1 ||
	    madvise_verdict(madvise_entry, POOL_MAP, page_size,
			    guard | (1UL << 32)) != -1)
		BUG("madvise: a guard install over the mapping was kept");
	if (madvise_verdict(madvise_entry, POOL_MAP, 0, guard) != 0 ||
	    madvise_verdict(madvise_entry, POOL_MAP + 1, page_size, guard) != 0)
		BUG("madvise: a guard install the kernel acts on nothing of was refused");

	mrec = mm_call(madvise_entry);
	mrec->a1 = 0;
	madvise_entry->sanitise(mrec);
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec) != -1)
		BUG("madvise: a call with no mapping kept a range");

	/* The post handler invalidates by the advice and the range the
	 * kernel was handed. */
	if (!madvise_post_invalidates(madvise_entry, false, MADV_DONTNEED))
		BUG("madvise: a hole punch put in the advice was not invalidated");
	if (madvise_post_invalidates(madvise_entry, true, MADV_NORMAL))
		BUG("madvise: an advice rewritten from a hole punch was invalidated");
}

/* madvise's rules, over a copy of its table entry. */
static void madvise_held(void)
{
	struct syscallentry madvise_entry = syscall_madvise;

	/* As copy_syscall_table() stamps the copy. */
	madvise_entry.is_madvise = true;

	madvise_range_held_off_regions(&madvise_entry);
	madvise_range_held_to_mapping(&madvise_entry);
	fake_this_child = NULL;
}

void arg_coupling_self_check(void);
void arg_coupling_self_check(void)
{
	shmat_remap_held_to_mapping();
	get_mempolicy_addr_names_mapping();
	madvise_held();
	count_slot_checked_at_table_init();
	count_held_inside_buffer();
	pkey_mprotect_known_through_its_copy();
	keyed_range_drops_cached_prot();
	munmap_range_held_to_mapping();
	mprotect_range_held_to_mapping();
}
