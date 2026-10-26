/*
 * Self-check for the per-syscall rules validate_arg_coupling() holds the
 * final argument slots to, an entry's own .vet_final rule first: a rewrite
 * after the sanitiser (chain substitution, a RedQueen pin) must not leave
 * the kernel a range the sanitiser would have refused.  A buffer-filling
 * count stays inside its buffer, a munmap, mprotect, pkey_mprotect,
 * madvise, set_mempolicy_home_node or remap_file_pages range inside the
 * pool mapping its sanitiser picked, madvise's (addr, len) off trinity's
 * tracked regions too, a madvise or process_madvise never installs guard
 * pages, and an mseal seals only a mapping its sanitiser made for it.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/mempolicy.h>

#include "arch.h"				/* page_size */
#include "arg_coupling.h"
#include "child.h"			/* struct childdata */
#include "cmsg_build.h"			/* pick_cmsg_kind, cmsg_build */
#include "debug.h"			/* BUG */
#include "files.h"			/* get_rand_pagecache_fd */
#include "hugepages.h"			/* pick_random_huge_size_encoding */
#include "kernel/mman.h"		/* MADV_GUARD_INSTALL */
#include "kernel/syslog.h"		/* SYSLOG_ACTION_READ */
#include "maps.h"			/* proc_maps_check */
#include "net.h"			/* generate_sockaddr */
#include "objects.h"			/* struct object */
#include "pathnames.h"		/* get_testfile_path */
#include "pids.h"			/* cached_pid */
#include "rnd.h"			/* rnd_state */
#include "sanitise.h"			/* writable pool, get_random_pkey_id */
#include "shm.h"			/* shm->stats */
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
extern bool fake_random_fd_empty;	/* fake_stubs.c */
extern bool fake_rand_bitmask_draws;	/* genl_ops_test.c */

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
 * before it.  getrandom's, recv's and recvfrom's sanitisers take a map
 * handle there instead: getrandom's shape is built by hand below, and
 * recv_count_held_inside_buffer() judges the real recv entries. */
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

	if (validate_arg_coupling(&rec, rec.entry) != 0)
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
		if (validate_arg_coupling(&rec, rec.entry) != 0 ||
		    *slot_of(slot - 1) != buf || *slot_of(slot) != count)
			BUG("arg coupling: a count the sanitiser sized was rewritten");
	}
}

/* recv and recvfrom fill the buffer their sanitiser makes of the ARG_MMAP
 * handle with as much as the socket holds, up to the count, so the count
 * is held inside the buffer's region as getrandom's is: one running from
 * a tracked region into the next is cut to the region's end, one inside
 * it is kept, and one from an untracked buffer that reaches a region is
 * cut to 0.  The rule judges the final slots, so no sanitiser runs. */
static void recv_count_held_inside_buffer(void)
{
	struct syscallentry *const entries[] = {
		&syscall_recv, &syscall_recvfrom,
	};
	const unsigned long tail = 0x800, end = REGION + REGION_SIZE;
	unsigned int e;

	fake_untrack_regions();
	fake_track_region(REGION, REGION_SIZE);
	fake_track_region(end, 0x10000);
	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		if (entries[e]->buf_count_slot != 3 ||
		    entry_check_status(entries[e]) != 0)
			BUG("recv: the count slot is not named, or sanity_check_tables() refuses it");
		if (count_after(entries[e], 3, end - tail, 0x7ffff000UL) != tail)
			BUG("recv: a count running past the buffer's region was kept");
		if (count_after(entries[e], 3, end - tail, tail) != tail)
			BUG("recv: a count inside the buffer's region was cut");
		fake_overlaps_shared = true;
		if (count_after(entries[e], 3, 0x10000000UL, 0x4000) != 0)
			BUG("recv: an untracked buffer reaching a region kept its count");
		fake_overlaps_shared = false;
	}
	fake_untrack_regions();
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

/* The probe entry's final-slot rule: it counts its calls, keeps the record,
 * entry and count it was handed, and answers vet_final_verdict. */
static unsigned int vet_final_calls;
static const struct syscallrecord *vet_final_saw_rec;
static const struct syscallentry *vet_final_saw_entry;
static unsigned long vet_final_saw_count;
static int vet_final_verdict;

static int probe_vet_final(struct syscallrecord *r,
			   const struct syscallentry *entry)
{
	vet_final_calls++;
	vet_final_saw_rec = r;
	vet_final_saw_entry = entry;
	vet_final_saw_count = r->a3;
	return vet_final_verdict;
}

/* validate_arg_coupling() asks an entry's .vet_final once per call, ahead
 * of its generic rules.  Any non-zero answer refuses the call before the
 * count rule runs; a pass leaves the count rule to cut, after the hook, a
 * count the hook saw as the rewrite left it. */
static void vet_final_asked_first(void)
{
	struct syscallentry entry = {
		.name = "vet_final_probe",
		.num_args = 3,
		.argtype = { ARG_FD, ARG_ADDRESS, ARG_LEN },
		.buf_count_slot = 3,
		.vet_final = probe_vet_final,
	};
	static const int verdicts[] = { 1, -1, 0 };
	const unsigned long tail = 0x800, count = 0x7ffff000UL;
	unsigned int i;

	fake_untrack_regions();
	fake_track_region(REGION, REGION_SIZE);
	fake_track_region(REGION + REGION_SIZE, 0x10000);

	for (i = 0; i < ARRAY_SIZE(verdicts); i++) {
		bool refused = verdicts[i] != 0;

		memset(&rec, 0, sizeof(rec));
		rec.entry = &entry;
		rec.a2 = REGION + REGION_SIZE - tail;
		rec.a3 = count;
		vet_final_calls = 0;
		vet_final_verdict = verdicts[i];
		if (validate_arg_coupling(&rec, rec.entry) != (refused ? -1 : 0))
			BUG("arg coupling: the call did not take its final-slot rule's verdict");
		if (vet_final_calls != 1 || vet_final_saw_rec != &rec ||
		    vet_final_saw_count != count)
			BUG("arg coupling: a final-slot rule was not asked once, ahead of the count rule");
		if (rec.a3 != (refused ? count : tail))
			BUG("arg coupling: the count rule ran after a refusal, or not after a pass");
	}

	fake_untrack_regions();
}

/* The rules are those of the entry the dispatcher passes, not of the one
 * the record names, which a sibling's stray write can repoint: a record
 * naming an entry with no hook and no count slot is held to the probe's
 * hook and count rule when the probe is passed, and one naming the probe,
 * whose hook would refuse, is held to neither when the other is.  The
 * hook is handed the passed entry too. */
static void vet_final_from_the_dispatched_entry(void)
{
	struct syscallentry probe = {
		.name = "vet_final_probe",
		.num_args = 3,
		.argtype = { ARG_FD, ARG_ADDRESS, ARG_LEN },
		.buf_count_slot = 3,
		.vet_final = probe_vet_final,
	};
	struct syscallentry bare = probe;
	struct syscallentry *const named[] = { &bare, &probe };
	const unsigned long tail = 0x800, count = 0x7ffff000UL;
	unsigned int i;

	bare.name = "bare";
	bare.buf_count_slot = 0;
	bare.vet_final = NULL;

	fake_untrack_regions();
	fake_track_region(REGION, REGION_SIZE);
	fake_track_region(REGION + REGION_SIZE, 0x10000);

	for (i = 0; i < ARRAY_SIZE(named); i++) {
		struct syscallentry *passed = named[i] == &bare ? &probe : &bare;
		bool probed = passed == &probe;

		memset(&rec, 0, sizeof(rec));
		rec.entry = named[i];
		rec.a2 = REGION + REGION_SIZE - tail;
		rec.a3 = count;
		vet_final_calls = 0;
		vet_final_verdict = probed ? 0 : -1;
		vet_final_saw_entry = NULL;
		if (validate_arg_coupling(&rec, passed) != 0 ||
		    vet_final_calls != (probed ? 1U : 0U) ||
		    rec.a3 != (probed ? tail : count) ||
		    (probed && vet_final_saw_entry != &probe))
			BUG("arg coupling: a rule came from the record's entry, not the one passed");
	}

	fake_untrack_regions();
}

/* epoll_wait, epoll_pwait and epoll_pwait2 refuse a positive maxevents with
 * no events buffer, and leave a maxevents of 0 or below, or a buffer, to
 * the kernel, which reads maxevents as an int: a slot whose low 32 bits are
 * 0 is no positive maxevents, and one whose low 32 bits are 1 is.  A compat
 * call hands over the low 32 bits of the buffer slot, so one whose low 32
 * bits are 0 is no buffer. */
static void epoll_wait_events_held(void)
{
	struct syscallentry *const entries[] = {
		&syscall_epoll_wait, &syscall_epoll_pwait, &syscall_epoll_pwait2,
	};
	static const struct {
		unsigned long events, maxevents;
		bool compat;
		int verdict;
	} cases[] = {
		{ 0, 8, false, -1 },
		{ 0, 1, false, -1 },
		{ 0, 0, false, 0 },
		{ 0, (unsigned long) -1L, false, 0 },
		{ 0, 1UL << 32, false, 0 },
		{ 0, 0xffffffff00000001UL, false, -1 },
		{ REGION, 8, false, 0 },
		{ 1UL << 32, 8, false, 0 },
		{ 1UL << 32, 8, true, -1 },
		{ REGION + 0x1000, 8, true, 0 },
	};
	unsigned int e, i;

	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		for (i = 0; i < ARRAY_SIZE(cases); i++) {
			memset(&rec, 0, sizeof(rec));
			rec.entry = entries[e];
			rec.do32bit = cases[i].compat;
			rec.a2 = cases[i].events;
			rec.a3 = cases[i].maxevents;
			if (validate_arg_coupling(&rec, rec.entry) != cases[i].verdict)
				BUG("epoll_wait: an events buffer and maxevents were judged wrongly");
		}
	}
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
		syscall_shmat.cleanup(&rec);
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
		syscall_shmat.cleanup(&rec);
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

extern bool fake_socket_fd_none;	/* post_oracle_test.c */

/* recv's sanitiser, which recvfrom's begins with, turns the ARG_MMAP
 * handle in the buffer slot into the start of the mapping it names, which
 * the kernel writes what it receives to, and never leaves the struct map
 * there: a buffer clear of trinity's regions stays at the mapping, one
 * over a tracked mapping moves to a pool slot of the count's length, and
 * with no mapping picked there is no buffer.  The kernel fills as much of
 * the buffer as the socket holds, so the count is held to the mapping: one
 * that fits is kept, a longer one cut to the mapping's size, and with no
 * mapping there is nothing to hold it to.  recvfrom's sanitiser is not run
 * itself: its value-result buffers go to deferred free, which in this
 * binary keeps every chunk it is handed. */
static void recv_buffer_names_mapping(void)
{
	const unsigned long size = POOL_PAGES * page_size;
	const unsigned long counts[] = {
		page_size, size, size + 1, WRITABLE_POOL_BYTES + 1, 0x7ffff000UL,
	};
	unsigned int c, n;

	if (get_writable_struct(1) == NULL)
		writable_pool_init();
	fake_socket_fd_none = true;
	for (c = 0; c < 3; c++) {
		for (n = 0; n < ARRAY_SIZE(counts); n++) {
			struct syscallrecord *mrec = mm_call(&syscall_recv);
			unsigned long held = counts[n];

			if (c != 2 && held > size)
				held = size;
			mrec->a1 = 0;
			mrec->a2 = c == 2 ? 0 : (unsigned long) &pool_obj.map;
			mrec->a3 = counts[n];
			if (c == 1)
				fake_track_region(POOL_MAP, size);
			syscall_recv.sanitise(mrec);
			fake_untrack_regions();
			if ((c == 0 && mrec->a2 != POOL_MAP) ||
			    (c == 1 && !range_in_writable_pool(mrec->a2, held)) ||
			    (c == 2 && mrec->a2 != 0))
				BUG("recv: the buffer is not the mapping the ARG_MMAP handle names");
			if (mrec->a3 != held)
				BUG("recv: the count was not held to the mapping");
			mrec->retval = (unsigned long) -1L;
			syscall_recv.post(mrec);
		}
	}
	fake_socket_fd_none = false;
	fake_this_child = NULL;
}

/* send.c brings sendmsg and sendmmsg along, and an ASAN build keeps them
 * linked: no test builds their messages. */
enum cmsg_kind pick_cmsg_kind(unsigned int family)
{
	(void) family;
	BUG("send: a test built a sendmsg message");
}

int cmsg_build(struct msghdr *m, enum cmsg_kind k, unsigned int family)
{
	(void) m;
	(void) k;
	(void) family;
	BUG("send: a test built a sendmsg message");
}

void generate_sockaddr(struct sockaddr **addr, socklen_t *addrlen, int pf)
{
	(void) addr;
	(void) addrlen;
	(void) pf;
	BUG("send: a test built a sendmsg message");
}

/* send's and sendto's shared sanitiser turns the ARG_MMAP handle in the
 * buffer slot into the start of the mapping it names, which the kernel
 * reads what it sends from, and never leaves the struct map there; with
 * no mapping picked there is no buffer. */
static void send_buffer_names_mapping(void)
{
	struct syscallentry *const entries[] = {
		&syscall_send, &syscall_sendto,
	};
	unsigned int e, m;

	fake_socket_fd_none = true;
	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		for (m = 0; m < 2; m++) {
			struct syscallrecord *mrec = mm_call(entries[e]);

			mrec->a1 = 0;
			mrec->a2 = m ? (unsigned long) &pool_obj.map : 0;
			entries[e]->sanitise(mrec);
			if (mrec->a2 != (m ? POOL_MAP : 0))
				BUG("send: the buffer is not the mapping the ARG_MMAP handle names");
		}
	}
	fake_socket_fd_none = false;
	fake_this_child = NULL;
}

/* getrandom fills every byte of its count, so its sanitiser holds the size
 * it draws to the mapping the ARG_MMAP handle names: no draw runs past it,
 * over a mapping of one page or of POOL_PAGES, and a boundary size that
 * fits, 4095, is still drawn as it is.  The sanitiser stamps a poison
 * pattern over the buffer, and range_readable_user() vouches for any range
 * in this binary, so the mapping is a real one, long enough for any size
 * the sanitiser draws. */
static void getrandom_size_held_to_mapping(void)
{
	const unsigned long sizes[] = { page_size, POOL_PAGES * page_size };
	const unsigned long real_len = MB(4) + page_size;
	unsigned int s, i, kept;
	void *real;

	real = mmap(NULL, real_len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (real == MAP_FAILED)
		BUG("getrandom: no mapping for the sanitiser to stamp");
	for (s = 0; s < ARRAY_SIZE(sizes); s++) {
		kept = 0;
		for (i = 0; i < SANITISER_DRAWS; i++) {
			struct syscallrecord *mrec = mm_call(&syscall_getrandom);

			pool_obj.map.ptr = real;
			pool_obj.map.size = sizes[s];
			pool_obj.map.tracked_size = sizes[s];
			syscall_getrandom.sanitise(mrec);
			if (mrec->a1 != (unsigned long) real || mrec->a2 > sizes[s])
				BUG("getrandom: a size past the mapping was kept");
			if (mrec->a2 == 4095)
				kept++;
			mrec->retval = (unsigned long) -1L;
			syscall_getrandom.post(mrec);
		}
		if (kept == 0)
			BUG("getrandom: a boundary size that fits the mapping was never drawn");
	}
	munmap(real, real_len);
	fake_this_child = NULL;
}

/* syslog's read-class calls copy up to their length of log into the
 * buffer, so the sanitiser never asks for more than the mapping get_map()
 * picked holds.  A negative length, which the kernel refuses before it
 * copies anything, is still drawn. */
static void syslog_read_held_to_mapping(void)
{
	const unsigned long size = POOL_PAGES * page_size;
	unsigned int i, reads = 0, negative = 0;

	fake_map_drawn = &pool_obj.map;
	pool_obj.map.ptr = (void *) POOL_MAP;
	pool_obj.map.size = size;
	for (i = 0; i < SANITISER_DRAWS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_syslog;
		syscall_syslog.sanitise(&rec);
		if ((rec.a1 != SYSLOG_ACTION_READ &&
		     rec.a1 != SYSLOG_ACTION_READ_ALL &&
		     rec.a1 != SYSLOG_ACTION_READ_CLEAR) || rec.a2 == 0)
			continue;
		reads++;
		if ((int) rec.a3 < 0) {
			negative++;
			continue;
		}
		if (rec.a2 != POOL_MAP || rec.a3 > size)
			BUG("syslog: a read asked for more than the mapping holds");
	}
	if (reads == 0 || negative == 0)
		BUG("syslog: the sanitiser lost its reads, or the negative length among them");
	fake_map_drawn = NULL;
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
 * sanitiser drew.  A mapping of more than a page gets a range that is not
 * empty; the sanitiser rounds a length drawn below the mapping's size
 * down to whole pages, so one of a page or less can only get an empty
 * one. */
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
		if (mrec->a2 != 0 || size <= page_size)
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

/* mprotect's hook moves a key a rewrite put in a4 into the snapshot for
 * the entry the dispatcher passed: a pkey_mprotect call whose record a
 * stray write repointed at plain mprotect still has a live key drop the
 * mapping's cached prot. */
static void keyed_range_known_through_the_dispatched_entry(void)
{
	struct syscallentry pkey_copy = syscall_pkey_mprotect;
	struct syscallentry plain_copy = syscall_mprotect;
	struct syscallrecord *mrec;

	pkey_copy.is_pkey_mprotect = true;
	for (;;) {
		mrec = mm_call(&pkey_copy);
		mrec->a3 = PROT_READ | PROT_WRITE;
		mrec->a4 = 0;
		pkey_copy.sanitise(mrec);
		if (mrec->a2 != 0)
			break;
		mrec->retval = (unsigned long) -1L;
		pkey_copy.post(mrec);
	}
	mrec->a4 = LIVE_PKEY;
	mrec->entry = &plain_copy;
	if (validate_arg_coupling(mrec, &pkey_copy) != 0)
		BUG("mprotect: a range the sanitiser built was refused");
	mrec->retval = 0;
	pkey_copy.post(mrec);
	if (pool_obj.map.prot != 0)
		BUG("mprotect: the hook told the variant from the record, not the dispatched entry");
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
 * below its VMA, of one whose tracked size was never set, and of one
 * whose size is larger than its tracked size.  A compat call over the
 * high mapping is built empty rather than refused. */
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
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
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
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("munmap: a length running a page past the mapping was kept");
	mrec->a2 = left;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("munmap: a length reaching the end of the mapping was refused");
	mrec->a2 = left - page_size + 1;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("munmap: a length the kernel rounds to the end was refused");
	mrec->a1 = end;
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("munmap: a range just past the mapping was kept");

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		mrec->a1 = start;
		mrec->a2 = page_size;
		if (cases[i].slot == 1)
			mrec->a1 = cases[i].value;
		else
			mrec->a2 = cases[i].value;
		if (validate_arg_coupling(mrec, mrec->entry) != cases[i].verdict)
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
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
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

/* @mrec, a call @name's hook passes with its own snapshot, is judged
 * without it: the pointer swapped for a pid, the snapshot disowned by the
 * ownership table, its magic changed.  Each is refused, and the call
 * passes again once the snapshot is whole. */
static void snapshot_gate_held(struct syscallrecord *mrec, const char *name)
{
	unsigned long *snap = (unsigned long *) mrec->post_state;
	int pid, disowned, magic, whole;

	mrec->post_state = 12345;
	pid = validate_arg_coupling(mrec, mrec->entry);
	mrec->post_state = (unsigned long) snap;
	post_state_disowned = snap;
	disowned = validate_arg_coupling(mrec, mrec->entry);
	post_state_disowned = NULL;
	*snap ^= 1UL;
	magic = validate_arg_coupling(mrec, mrec->entry);
	*snap ^= 1UL;
	whole = validate_arg_coupling(mrec, mrec->entry);
	if (pid != -1 || disowned != -1 || magic != -1 || whole != 0) {
		fprintf(stderr, "%s: verdict %d with a pid for its snapshot, %d disowned, %d with another magic, %d whole\n",
			name, pid, disowned, magic, whole);
		BUG("arg coupling: a call was judged by a snapshot not its own");
	}
}

/* Nothing names a mapping without the call's own snapshot: none, a pid
 * where the pointer was, one the ownership table does not hold, or one
 * with another magic.  Only a range the kernel acts on nothing of goes
 * through then. */
static void munmap_needs_its_snapshot(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);

	mrec->a1 = 0;
	entry->sanitise(mrec);
	if (mrec->post_state != 0)
		BUG("munmap: the sanitiser left a snapshot with no mapping");
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("munmap: a call with no mapping kept a range");
	mrec->a2 = 0;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("munmap: an empty call with no mapping was refused");

	mrec = mm_call(entry);
	entry->sanitise(mrec);
	mrec->a1 = POOL_MAP;
	mrec->a2 = page_size;
	snapshot_gate_held(mrec, "munmap");
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
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("munmap: a compat call was judged on the slots' upper halves");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);

	mrec = mm_call(entry);
	pool_obj.map.ptr = (void *) LOW_POOL_MAP;
	mrec->do32bit = true;
	entry->sanitise(mrec);
	if (mrec->a1 < LOW_POOL_MAP || validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("munmap: a compat call over a low mapping was emptied or refused");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);

	mrec = mm_call(entry);
	pool_obj.map.ptr = (void *) LOW_POOL_MAP;
	entry->sanitise(mrec);
	mrec->a1 = LOW_POOL_MAP | (1UL << 32);
	mrec->a2 = page_size | (1UL << 32);
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("munmap: a native call's upper halves were dropped");
	mrec->do32bit = true;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("munmap: a compat call inside a low mapping was refused");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);
}

/* munmap.c's WHOLE: the sanitiser's action for a whole-mapping unmap,
 * which it leaves in a4. */
#define MUNMAP_WHOLE	1UL

/* A whole-mapping unmap is one draw in twenty, so the draws above build
 * one as a compat call only by chance.  Find one built natively and
 * replay its draws as a compat call, which takes the same branch: the
 * sanitiser draws it before it looks at do32bit or the address.  Over the
 * high mapping, whose address the slots cannot carry, the call is built
 * empty with its action dropped, and passes; over a low mapping it is the
 * whole mapping, and passes. */
static void munmap_compat_whole_mapping(struct syscallentry *entry)
{
	struct syscallrecord *mrec;
	uint64_t state = 0;
	unsigned int i;

	for (i = 0; i < 10000; i++) {
		mrec = mm_call(entry);
		state = rnd_state;
		entry->sanitise(mrec);
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);
		if (mrec->a4 == MUNMAP_WHOLE)
			break;
	}
	if (i == 10000)
		BUG("munmap: the sanitiser never built a whole-mapping unmap");

	mrec = mm_call(entry);
	mrec->do32bit = true;
	rnd_state = state;
	entry->sanitise(mrec);
	if (mrec->a1 != 0 || mrec->a2 != 0 || mrec->a4 != 0)
		BUG("munmap: a compat whole-mapping unmap of a high mapping was kept");
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("munmap: an emptied compat whole-mapping unmap was refused");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);

	mrec = mm_call(entry);
	pool_obj.map.ptr = (void *) LOW_POOL_MAP;
	mrec->do32bit = true;
	rnd_state = state;
	entry->sanitise(mrec);
	if (mrec->a4 != MUNMAP_WHOLE || mrec->a1 != LOW_POOL_MAP ||
	    mrec->a2 != POOL_PAGES * page_size)
		BUG("munmap: a compat whole-mapping unmap of a low mapping was not built whole");
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("munmap: a compat whole-mapping unmap of a low mapping was refused");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);
}

/* munmap's final range stays inside the mapping its sanitiser picked. */
static void munmap_range_held_to_mapping(void)
{
	struct syscallentry munmap_entry = syscall_munmap;
	struct syscallentry other = syscall_munmap;
	struct syscallrecord *mrec;

	/* munmap's slots and sanitiser, without its final-slot rule. */
	other.vet_final = NULL;
	fake_get_objhead = no_pool;

	munmap_sanitised_range_passes(&munmap_entry);
	munmap_compat_whole_mapping(&munmap_entry);
	munmap_rewritten_range_held(&munmap_entry);
	munmap_post_acts_on_final_range(&munmap_entry);
	munmap_needs_its_snapshot(&munmap_entry);
	munmap_compat_slots_truncated(&munmap_entry);

	/* The rule is the hook's alone: munmap's would refuse this aligned
	 * range, which no snapshot vouches for. */
	mrec = mm_call(&other);
	mrec->a1 = POOL_MAP;
	mrec->a2 = 0x7ffff000UL;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("munmap: the range rule judged an entry without munmap's hook");

	fake_get_objhead = NULL;
	fake_this_child = NULL;
}

/* The pages a range has the kernel act on, read both ways a kernel reads
 * one: munmap and its like refuse an unaligned start and round the length
 * up, remap_file_pages rounds the start and the length down.  Either acts
 * on nothing for a range that is empty or wraps, and a compat call is read
 * from the slots' low halves.  A mapping's pages run on to the page
 * boundary after its length, whatever the mapping. */
static void range_pages_read_as_the_kernel_does(void)
{
	const unsigned long pg = page_size, top = ULONG_MAX - pg + 1;
	const unsigned long hi = 1UL << 32;
	const struct {
		unsigned long addr, len;
		bool compat, round_down, acts;
		unsigned long start, end;
	} cases[] = {
		{ POOL_MAP, 1, false, false, true, POOL_MAP, POOL_MAP + pg },
		{ POOL_MAP, pg + 1, false, false, true, POOL_MAP, POOL_MAP + 2 * pg },
		{ POOL_MAP + 1, pg, false, false, false, 0, 0 },
		{ POOL_MAP, 0, false, false, false, 0, 0 },
		{ POOL_MAP, ULONG_MAX, false, false, false, 0, 0 },
		{ top, 2 * pg, false, false, false, 0, 0 },
		{ POOL_MAP + 1, 2 * pg - 1, false, true, true, POOL_MAP, POOL_MAP + pg },
		{ POOL_MAP + 1, pg - 1, false, true, false, 0, 0 },
		{ top, 2 * pg, false, true, false, 0, 0 },
		{ hi | LOW_POOL_MAP, hi | pg, true, false, true,
		  LOW_POOL_MAP, LOW_POOL_MAP + pg },
		{ hi | (LOW_POOL_MAP + 1), hi | (pg + 1), true, true, true,
		  LOW_POOL_MAP, LOW_POOL_MAP + pg },
	};
	struct page_span pages;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		bool acts = map_range_pages(cases[i].addr, cases[i].len,
					    cases[i].compat, cases[i].round_down,
					    &pages);

		if (acts != cases[i].acts ||
		    (acts && (pages.start != cases[i].start ||
			      pages.end != cases[i].end)))
			BUG("maps: a range was not read as the kernel reads it");
	}

	pages.start = POOL_MAP;
	pages.end = POOL_MAP + 2 * pg;
	if (!page_span_inside(&pages, POOL_MAP, 2 * pg) ||
	    !page_span_inside(&pages, POOL_MAP, pg + 1) ||
	    !page_span_inside(&pages, POOL_MAP - pg, 3 * pg))
		BUG("maps: pages inside a mapping were judged outside it");
	if (page_span_inside(&pages, POOL_MAP, pg) ||
	    page_span_inside(&pages, POOL_MAP + pg, 2 * pg) ||
	    page_span_inside(&pages, POOL_MAP, ULONG_MAX))
		BUG("maps: pages outside a mapping were judged inside it");
}

/* set_mempolicy_home_node's sanitiser turns the ARG_MMAP handle into the
 * picked mapping's address and a length inside it, over a mapping whose
 * size is larger than its tracked size too, and its hook holds
 * the final slots there: a length or an address a rewrite moves out of
 * the mapping is refused, a range still inside passes, and so does one
 * the kernel acts on nothing of.  A compat call is built empty over the
 * high mapping and kept over a low one; a call with no mapping passes
 * only an empty range. */
static void home_node_range_held_to_mapping(void)
{
	struct syscallentry entry = syscall_set_mempolicy_home_node;
	const unsigned long pg = page_size, whole = POOL_PAGES * pg;
	const struct {
		unsigned long addr, len;
		int verdict;
	} cases[] = {
		{ POOL_MAP, whole + pg, -1 },
		{ POOL_MAP, 0x7ffff000UL, -1 },
		{ POOL_MAP - pg, 2 * pg, -1 },
		{ POOL_MAP + whole, pg, -1 },
		{ 0x10000000UL, pg, -1 },
		{ POOL_MAP, whole, 0 },
		{ POOL_MAP + pg, pg - 1, 0 },
		{ POOL_MAP + 1, pg, 0 },
		{ POOL_MAP, 0, 0 },
		{ POOL_MAP, ~0UL, 0 },
	};
	struct syscallrecord *mrec;
	unsigned int i;

	for (i = 0; i < MM_DRAWS; i++) {
		mrec = mm_call(&entry);
		if (i & 1)
			pool_obj.map.size = 2 * whole;
		mrec->do32bit = (i % 10) == 0;
		entry.sanitise(mrec);
		if (mrec->do32bit ? (mrec->a1 != 0 || mrec->a2 != 0) :
		    (mrec->a1 != POOL_MAP || mrec->a2 >= pool_obj.map.size))
			BUG("set_mempolicy_home_node: the range was not built in the picked mapping");
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("set_mempolicy_home_node: a range the sanitiser built was refused");
		entry.cleanup(mrec);
	}

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		mrec = mm_call(&entry);
		entry.sanitise(mrec);
		mrec->a1 = cases[i].addr;
		mrec->a2 = cases[i].len;
		if (validate_arg_coupling(mrec, mrec->entry) != cases[i].verdict)
			BUG("set_mempolicy_home_node: a rewritten range was judged wrongly");
		entry.cleanup(mrec);
	}

	mrec = mm_call(&entry);
	pool_obj.map.ptr = (void *) LOW_POOL_MAP;
	mrec->do32bit = true;
	entry.sanitise(mrec);
	if (mrec->a1 != LOW_POOL_MAP || validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("set_mempolicy_home_node: a compat call over a low mapping was emptied or refused");
	entry.cleanup(mrec);

	mrec = mm_call(&entry);
	mrec->a1 = 0;
	entry.sanitise(mrec);
	if (mrec->post_state != 0)
		BUG("set_mempolicy_home_node: the sanitiser left a snapshot with no mapping");
	mrec->a1 = POOL_MAP;
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("set_mempolicy_home_node: a call with no mapping kept a range");
	mrec->a2 = 0;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("set_mempolicy_home_node: an empty call with no mapping was refused");

	fake_this_child = NULL;
}

/* mseal.c's disposable mapping, in pages, and how many sealed ones a
 * child keeps before its calls get an empty range. */
#define MSEAL_MAP_PAGES		4
#define MSEAL_MAX_SEALED	16

/* munmap() as the kernel answers it over a sealed mapping (the munmap wrap
 * in tests/Makefile): a range that holds munmap_sealed fails with EPERM
 * and nothing is unmapped, and munmap_refused_len keeps how long it was.
 * Any other range goes to the real call. */
static unsigned long munmap_sealed;
static unsigned long munmap_refused_len;

int __real_munmap(void *addr, size_t len);
int __wrap_munmap(void *addr, size_t len);
int __wrap_munmap(void *addr, size_t len)
{
	unsigned long start = (unsigned long) addr;

	if (munmap_sealed != 0 && munmap_sealed >= start &&
	    munmap_sealed - start < len) {
		munmap_refused_len = len;
		errno = EPERM;
		return -1;
	}
	return __real_munmap(addr, len);
}

/* An mseal the sanitiser built, whatever the ARG_MMAP handle in its start
 * slot: an empty range, or one inside a fresh mapping of the call's own. */
static struct syscallrecord *mseal_call(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);
	unsigned char vec;

	entry->sanitise(mrec);
	if (mrec->a1 == (unsigned long) &pool_obj.map ||
	    (mrec->a1 >= POOL_MAP && mrec->a1 < POOL_MAP + POOL_PAGES * page_size))
		BUG("mseal: the call named a pool mapping or its handle");
	if (mrec->a1 != 0 &&
	    ((mrec->a1 & ~PAGE_MASK) != 0 || mrec->a2 == 0 ||
	     mrec->a2 > MSEAL_MAP_PAGES * page_size ||
	     mincore((void *) mrec->a1, page_size, &vec) != 0))
		BUG("mseal: the range is not one inside a mapping the sanitiser made");
	return mrec;
}

/* The rewrites the hook refuses and the ones it lets through, over a call
 * whose range is the whole disposable mapping at @base: a range past the
 * mapping or outside it, a pool mapping included, is refused; one inside
 * it, and one the kernel seals nothing of, passes.  Flags a rewrite turns
 * from 0 to something else, or back, are refused, since they decide
 * whether the kernel reads the range at all; flags that still pass or
 * fail as the drawn ones did are not. */
static void mseal_rewrites_held(struct syscallrecord *mrec, unsigned long base)
{
	const unsigned long pg = page_size, whole = MSEAL_MAP_PAGES * pg;
	const struct {
		unsigned long addr, len;
		int verdict;
	} cases[] = {
		{ base, whole + 1, -1 },
		{ base, 0x7ffff000UL, -1 },
		{ base + pg, whole, -1 },
		{ base - pg, pg, -1 },
		{ POOL_MAP, pg, -1 },
		{ base, whole, 0 },
		{ base + pg, whole - pg, 0 },
		{ base + whole - pg, pg - 1, 0 },
		{ base + 1, pg, 0 },
		{ base, 0, 0 },
		{ POOL_MAP, 0, 0 },
	};
	const unsigned long drawn = mrec->a3;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		mrec->a1 = cases[i].addr;
		mrec->a2 = cases[i].len;
		if (validate_arg_coupling(mrec, mrec->entry) != cases[i].verdict)
			BUG("mseal: a rewritten range was judged wrongly");
	}

	mrec->a1 = base;
	mrec->a2 = pg;
	mrec->a3 = drawn == 0 ? 1UL << 5 : 0;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mseal: flags rewritten to pass or fail otherwise were kept");
	mrec->a3 = drawn == 0 ? 0 : (drawn == 1 ? 2 : 1);
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mseal: flags that pass or fail as the drawn ones did were refused");
}

/* mseal seals only a mapping its sanitiser makes for the call, never a
 * pool mapping, and holds the final slots to it.  The cleanup gives the
 * mapping back by its extent, not by the slots a rewrite moved, unless the
 * kernel refuses to unmap it because the call sealed it: then it stays,
 * whatever the call returned, and counts.  A child that has kept
 * MSEAL_MAX_SEALED gets an empty range from then on.  This can run only
 * once per process: it leaves the count at the cap, the mappings mapped. */
static void mseal_seals_only_its_own_mapping(void)
{
	struct syscallentry entry = syscall_mseal;
	struct syscallrecord *mrec;
	unsigned long region, scratch;
	unsigned int i, tested = 0, kept;
	unsigned char vec;
	void *p;

	for (i = 0; i < MM_DRAWS; i++) {
		mrec = mseal_call(&entry);
		region = mrec->a1;
		if (region == 0)
			BUG("mseal: a child under its cap was given no mapping");
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mseal: a range the sanitiser built was refused");
		mrec->retval = (unsigned long) -1L;
		entry.cleanup(mrec);
		if (mincore((void *) region, page_size, &vec) == 0)
			BUG("mseal: a call that failed kept its mapping");
	}

	/* Calls covering the whole mapping, so starting at its base: one
	 * whose flags drew 0 and one whose flags drew something else. */
	for (i = 0; i < 10000 && tested != 3; i++) {
		unsigned int kind;

		mrec = mseal_call(&entry);
		region = mrec->a1;
		kind = mrec->a3 == 0 ? 1 : 2;
		if (mrec->a2 > (MSEAL_MAP_PAGES - 1) * page_size &&
		    (tested & kind) == 0) {
			mseal_rewrites_held(mrec, region);
			tested |= kind;
		}
		mrec->retval = (unsigned long) -1L;
		entry.cleanup(mrec);
		if (mincore((void *) region, page_size, &vec) == 0)
			BUG("mseal: a call that was refused kept its mapping");
	}
	if (tested != 3)
		BUG("mseal: the sanitiser never covered its mapping with each kind of flags");

	/* A rewrite onto another mapping is refused, and the cleanup unmaps
	 * the call's own mapping, not the one the slots now name. */
	p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		BUG("mseal: no scratch mapping for the test");
	scratch = (unsigned long) p;
	mrec = mseal_call(&entry);
	region = mrec->a1;
	mrec->a1 = scratch;
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mseal: a range rewritten onto another mapping was kept");
	mrec->retval = (unsigned long) -1L;
	entry.cleanup(mrec);
	if (mincore((void *) region, page_size, &vec) == 0 ||
	    mincore(p, page_size, &vec) != 0)
		BUG("mseal: the cleanup unmapped by the slots, not by the snapshot");
	munmap(p, page_size);

	/* A call whose return says it worked, over a range that names pages,
	 * still gives its mapping back if the kernel unmaps it. */
	mrec = mseal_call(&entry);
	region = mrec->a1;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mseal: a range the sanitiser built was refused");
	mrec->retval = 0;
	entry.cleanup(mrec);
	if (mincore((void *) region, page_size, &vec) == 0)
		BUG("mseal: a mapping the kernel did not seal was kept on the return value's word");

	/* A mapping the kernel refuses to unmap stays, whatever the call
	 * returned, and counts: the cleanup asked for all of it. */
	for (kept = 0; kept <= MSEAL_MAX_SEALED; kept++) {
		mrec = mseal_call(&entry);
		region = mrec->a1;
		if (region == 0)
			break;
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mseal: a range the sanitiser built was refused");
		mrec->retval = (unsigned long) -1L;
		munmap_sealed = region;
		munmap_refused_len = 0;
		entry.cleanup(mrec);
		munmap_sealed = 0;
		if (munmap_refused_len != MSEAL_MAP_PAGES * page_size ||
		    mincore((void *) region, page_size, &vec) != 0)
			BUG("mseal: a sealed mapping was not asked back whole, or was lost");
	}
	if (kept != MSEAL_MAX_SEALED)
		BUG("mseal: the sanitiser did not stop at its cap");

	/* Past it, the range is empty, which still reaches the kernel, and a
	 * rewrite has no mapping to give it pages in. */
	if (mrec->a2 != 0 || validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mseal: a call past the cap was not an empty one");
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mseal: a call past the cap kept a rewritten range");
	entry.cleanup(mrec);

	fake_this_child = NULL;
}

/* A remap_file_pages call over the pool mapping, made a MAP_SHARED file
 * mapping, the one kind the sanitiser remaps, for it to build. */
static struct syscallrecord *remap_call(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);

	pool_obj.map.type = MMAPED_FILE;
	pool_obj.map.fd = 3;
	pool_obj.map.flags = MAP_SHARED;
	return mrec;
}

/* remap_file_pages' hook holds the pages the kernel replaces, read with
 * the start and the size rounded down, to the mapping the sanitiser
 * picked: a start pinned outside it, or a size that runs past it, is
 * refused, even where an unaligned start would make munmap's reading act
 * on nothing, and a range that rounds back inside, or down to nothing,
 * passes.  The sanitiser's own ranges pass.  A mapping it will not remap,
 * and a call it emptied over a tracked region, leave no mapping a rewrite
 * can put a range back in. */
static void remap_file_pages_range_held_to_mapping(void)
{
	struct syscallentry entry = syscall_remap_file_pages;
	const unsigned long pg = page_size, whole = POOL_PAGES * pg;
	const unsigned long end = POOL_MAP + whole;
	const struct {
		unsigned long addr, len;
		int verdict;
	} cases[] = {
		{ REGION, pg, -1 },
		{ POOL_MAP, whole + pg, -1 },
		{ POOL_MAP, 0x7ffff000UL, -1 },
		{ POOL_MAP - pg, 2 * pg, -1 },
		{ end, pg, -1 },
		{ end - 1, 2 * pg, -1 },
		{ POOL_MAP + 1, whole + pg, -1 },
		{ POOL_MAP, whole, 0 },
		{ end - 1, 2 * pg - 1, 0 },
		{ POOL_MAP + 1, whole + pg - 1, 0 },
		{ REGION, pg - 1, 0 },
		{ 0, 0, 0 },
	};
	struct syscallrecord *mrec;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		mrec = remap_call(&entry);
		entry.sanitise(mrec);
		mrec->a1 = cases[i].addr;
		mrec->a2 = cases[i].len;
		if (validate_arg_coupling(mrec, mrec->entry) != cases[i].verdict)
			BUG("remap_file_pages: a rewritten range was judged wrongly");
		entry.cleanup(mrec);
	}

	/* Over a mapping whose size is larger than its tracked size too; a
	 * compat call over the high mapping is built empty rather than
	 * refused. */
	for (i = 0; i < MM_DRAWS; i++) {
		mrec = remap_call(&entry);
		if (i & 1)
			pool_obj.map.size = 2 * whole;
		mrec->do32bit = (i % 10) == 0;
		entry.sanitise(mrec);
		if (mrec->do32bit && (mrec->a1 != 0 || mrec->a2 != 0))
			BUG("remap_file_pages: the sanitiser built a compat range its slots cannot carry");
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("remap_file_pages: a range the sanitiser built was refused");
		entry.cleanup(mrec);
	}

	mrec = remap_call(&entry);
	pool_obj.map.flags = MAP_PRIVATE;
	entry.sanitise(mrec);
	mrec->a1 = POOL_MAP;
	mrec->a2 = pg;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("remap_file_pages: a range was put back in a private mapping");
	entry.cleanup(mrec);

	fake_untrack_regions();
	fake_track_region(POOL_MAP, whole);
	mrec = remap_call(&entry);
	entry.sanitise(mrec);
	if (mrec->a1 != 0 || mrec->a2 != 0)
		BUG("remap_file_pages: a range over a tracked region was kept");
	mrec->a1 = POOL_MAP;
	mrec->a2 = pg;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("remap_file_pages: a range was put back over a tracked region");
	entry.cleanup(mrec);
	fake_untrack_regions();

	pool_obj.map.type = 0;
	pool_obj.map.fd = 0;
	pool_obj.map.flags = 0;
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
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
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

	/* As copy_syscall_table() stamps the copy. */
	pkey_entry.is_pkey_mprotect = true;

	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		struct syscallentry *entry = entries[e];
		struct syscallrecord *mrec;

		/* Over a mapping whose size is larger than its tracked
		 * size too; a compat call over the high mapping is built
		 * empty rather than refused. */
		for (i = 0; i < MM_DRAWS; i++) {
			mrec = mm_call(entry);
			if (i & 1)
				pool_obj.map.size = 2 * POOL_PAGES * page_size;
			mrec->do32bit = (i % 10) == 0;
			entry->sanitise(mrec);
			if (mrec->do32bit && (mrec->a1 != 0 || mrec->a2 != 0))
				BUG("mprotect: the sanitiser built a compat range its slots cannot carry");
			if (validate_arg_coupling(mrec, mrec->entry) != 0)
				BUG("mprotect: a range the sanitiser built was refused");
			mrec->retval = (unsigned long) -1L;
			entry->post(mrec);
		}

		/* The sanitiser starts the range at the mapping. */
		mrec = mm_call(entry);
		entry->sanitise(mrec);
		mrec->a2 = whole + page_size;
		if (validate_arg_coupling(mrec, mrec->entry) != -1)
			BUG("mprotect: a length running past the mapping was kept");
		mrec->a2 = whole;
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mprotect: a length covering the mapping was refused");
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);

		mrec = mm_call(entry);
		mrec->a1 = 0;
		entry->sanitise(mrec);
		mrec->a2 = page_size;
		if (validate_arg_coupling(mrec, mrec->entry) != -1)
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

	if (validate_arg_coupling(mrec, mrec->entry) != 0)
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

/* A compat call hands the kernel the low 32 bits of each slot, so its range
 * is held off the regions on those: an upper half added to a range over a
 * low tracked mapping does not keep it, and a region the full slots reach
 * but their low halves do not empties nothing.  Either way the call passes,
 * the low halves lying inside the low mapping its sanitiser picked. */
static void madvise_compat_range_held_off_regions(struct syscallentry *madvise_entry)
{
	const unsigned long upper = 1UL << 32;
	unsigned int t;

	for (t = 0; t < 2; t++) {
		bool low_region = t == 0;
		struct syscallrecord *mrec = mm_call(madvise_entry);

		fake_untrack_regions();
		fake_track_region(low_region ? LOW_POOL_MAP : LOW_POOL_MAP | upper,
				  POOL_PAGES * page_size);
		pool_obj.map.ptr = (void *) LOW_POOL_MAP;
		mrec->do32bit = true;
		madvise_entry->sanitise(mrec);
		mrec->a1 = LOW_POOL_MAP | upper;
		mrec->a2 = page_size;
		mrec->a3 = MADV_REMOVE_ADVICE;
		if (validate_arg_coupling(mrec, mrec->entry) != 0 ||
		    (mrec->a1 == 0) != low_region || (mrec->a2 == 0) != low_region)
			BUG("madvise: a compat range was held off the regions on its upper halves");
		mrec->retval = (unsigned long) -1L;
		madvise_entry->post(mrec);
	}
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
	verdict = validate_arg_coupling(mrec, mrec->entry);
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
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
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

	/* Over a mapping whose size is larger than its tracked size too; a
	 * compat call over the high mapping is built empty rather than
	 * refused. */
	for (i = 0; i < MM_DRAWS; i++) {
		mrec = mm_call(madvise_entry);
		if (i & 1)
			pool_obj.map.size = 2 * POOL_PAGES * page_size;
		mrec->do32bit = (i % 10) == 0;
		madvise_entry->sanitise(mrec);
		if (mrec->do32bit && (mrec->a1 != 0 || mrec->a2 != 0))
			BUG("madvise: the sanitiser built a compat range its slots cannot carry");
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
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

	/* Nor one the overlap repair emptied off a tracked region. */
	fake_track_region(POOL_MAP, POOL_PAGES * page_size);
	if (madvise_verdict(madvise_entry, POOL_MAP, page_size, guard) != 0)
		BUG("madvise: a guard install emptied off a region was refused");
	fake_untrack_regions();

	mrec = mm_call(madvise_entry);
	mrec->a1 = 0;
	madvise_entry->sanitise(mrec);
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
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

	madvise_range_held_off_regions(&madvise_entry);
	madvise_compat_range_held_off_regions(&madvise_entry);
	madvise_range_held_to_mapping(&madvise_entry);
	fake_this_child = NULL;
}

static int process_madvise_verdict(const struct iovec *vec, unsigned long vlen,
				   unsigned long advice, bool compat)
{
	memset(&rec, 0, sizeof(rec));
	rec.entry = &syscall_process_madvise;
	rec.do32bit = compat;
	rec.a2 = (unsigned long) vec;
	rec.a3 = vlen;
	rec.a4 = advice;
	return validate_arg_coupling(&rec, rec.entry);
}

/* process_madvise refuses a final GUARD_INSTALL, its advice read as an
 * int, when an iovec the kernel reads names a page, and when it cannot
 * judge the array: one outside the iovec pool, or any array a compat
 * call reads.  A count of 0, or one the kernel refuses, reads no iovec.
 * What its sanitiser builds for a GUARD_INSTALL aimed at the calling
 * process names no page, compat or not. */
static void process_madvise_guard_install_held(void)
{
	const unsigned long guard = MADV_GUARD_INSTALL;
	const struct iovec outside[1] = { { NULL, 0 } };
	struct iovec *iov = alloc_iovec(3, IOV_KERNEL_WRITE);
	unsigned int i;

	/* Two iovecs emptied, as the sanitiser leaves them, then a page. */
	for (i = 0; i < 3; i++) {
		iov[i].iov_base = (void *) (POOL_MAP + i * page_size);
		iov[i].iov_len = i == 2 ? page_size : 0;
	}

	if (process_madvise_verdict(iov, 2, guard, false) != 0 ||
	    process_madvise_verdict(iov, 0, guard, false) != 0 ||
	    process_madvise_verdict(iov, UIO_MAXIOV + 1, guard, false) != 0 ||
	    process_madvise_verdict(iov, 3, MADV_COLD, false) != 0)
		BUG("process_madvise: a call that installs no guard page was refused");
	if (process_madvise_verdict(iov, 3, guard, false) != -1 ||
	    process_madvise_verdict(iov + 2, 1, guard | (1UL << 32), false) != -1)
		BUG("process_madvise: a guard install over a page was kept");
	if (process_madvise_verdict(outside, 1, guard, false) != -1 ||
	    process_madvise_verdict(iov, 2, guard, true) != -1 ||
	    process_madvise_verdict(iov, (1UL << 32) | 2, guard, true) != -1)
		BUG("process_madvise: a guard install over an array it cannot judge was kept");

	/* The kernel refuses an unaligned start before it acts on a page. */
	iov[2].iov_base = (void *) (POOL_MAP + 2 * page_size + 1);
	if (process_madvise_verdict(iov, 3, guard, false) != 0)
		BUG("process_madvise: a guard install the kernel acts on nothing of was refused");

#ifdef __NR_pidfd_open
	{
		pid_t saved_pid = cached_pid;
		int self = syscall(__NR_pidfd_open, getpid(), 0);

		if (self < 0)
			return;

		/* A pidfd for this process takes the sanitiser's self path. */
		cached_pid = getpid();
		for (i = 0; i < 3; i++)
			iov[i].iov_len = page_size;
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_process_madvise;
		rec.a1 = (unsigned long) self;
		rec.a2 = (unsigned long) iov;
		rec.a3 = 3;
		rec.a4 = guard | (1UL << 32);
		syscall_process_madvise.sanitise(&rec);
		if (validate_arg_coupling(&rec, rec.entry) != 0)
			BUG("process_madvise: a guard install its sanitiser built was refused");

		/* A compat one too, though it reads no array built here. */
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_process_madvise;
		rec.do32bit = true;
		rec.a1 = (unsigned long) self;
		rec.a2 = (unsigned long) iov;
		rec.a3 = 3;
		rec.a4 = guard;
		syscall_process_madvise.sanitise(&rec);
		if (validate_arg_coupling(&rec, rec.entry) != 0)
			BUG("process_madvise: a compat guard install its sanitiser built was refused");
		cached_pid = saved_pid;
		close(self);
	}
#endif
}

/* The image table holds the pages of every segment of this binary's own
 * image, text, rodata and data alike, and nothing else: a function, a
 * constant and a variable of the binary are in it, a fresh anonymous
 * mapping is not, and a range that wraps counts as in it. */
static void image_table_covers_the_image(void)
{
	static const char constant[] = "rodata";
	static char variable[16];
	void *anon;

	register_loaded_image_segments();
	if (!range_overlaps_image((unsigned long) image_table_covers_the_image, 1) ||
	    !range_overlaps_image((unsigned long) constant, sizeof(constant)) ||
	    !range_overlaps_image((unsigned long) variable, sizeof(variable)))
		BUG("image-segments: a page of the binary's own image was left out");

	anon = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (anon == MAP_FAILED)
		BUG("image-segments: no anonymous page to compare");
	if (range_overlaps_image((unsigned long) anon, page_size))
		BUG("image-segments: an anonymous mapping was taken for the image");
	munmap(anon, page_size);

	if (!range_overlaps_image(ULONG_MAX - page_size + 1, 2 * page_size))
		BUG("image-segments: a range that wraps was not counted");
}

/* A fixed move unmaps its target first, so mremap's sanitiser keeps the
 * target off trinity's own image as well as its regions and the heap: a
 * non-PIE build loads its text where the small alignments put targets.
 * The image table is the one image_table_covers_the_image() filled. */
static void mremap_fixed_target_off_image(void)
{
	struct syscallentry mremap_entry = syscall_mremap;
	unsigned int i;

	for (i = 0; i < MM_DRAWS; i++) {
		struct syscallrecord *mrec = mm_call(&mremap_entry);

		mremap_entry.sanitise(mrec);
		if ((mrec->a4 & MREMAP_FIXED) &&
		    range_overlaps_image(mrec->a5, mrec->a3))
			BUG("mremap: a fixed target on trinity's own image was kept");
		mrec->retval = (unsigned long) -1L;
		mremap_entry.post(mrec);
	}
	fake_this_child = NULL;
}

/* A hugetlb source has the kernel round new_len up to its huge page size
 * before a fixed move unmaps the target, and refuse a target that size does
 * not divide, so the sanitiser checks the target as far as the largest
 * power of two dividing it rounds new_len.  A region in the last page of
 * that rounding drops MREMAP_FIXED from a draw that keeps it without one:
 * the draw is found, then replayed from the same RNG state. */
static void mremap_fixed_target_checked_rounded(void)
{
	struct syscallentry mremap_entry = syscall_mremap;
	struct syscallrecord *mrec;
	unsigned long newaddr = 0, huge, end;
	uint64_t state = 0;
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		mrec = mm_call(&mremap_entry);
		state = rnd_state;
		mremap_entry.sanitise(mrec);
		newaddr = mrec->a5;
		mrec->retval = (unsigned long) -1L;
		mremap_entry.post(mrec);
		if (mrec->a4 & MREMAP_FIXED)
			break;
	}
	if (i == 1000)
		BUG("mremap: the sanitiser never kept a fixed target");

	/* The drawn new_len is a few pages, under any huge page size. */
	huge = newaddr & -newaddr;
	end = newaddr + ((mrec->a3 + huge - 1) & ~(huge - 1));
	if (end - page_size < newaddr + mrec->a3)
		BUG("mremap: the drawn new_len already reaches the rounding");

	fake_untrack_regions();
	fake_track_region(end - page_size, page_size);
	mrec = mm_call(&mremap_entry);
	rnd_state = state;
	mremap_entry.sanitise(mrec);
	if (mrec->a4 & MREMAP_FIXED)
		BUG("mremap: a fixed target was checked only as far as new_len");
	mrec->retval = (unsigned long) -1L;
	mremap_entry.post(mrec);
	fake_untrack_regions();
	fake_this_child = NULL;
}

/* What an mremap() call is redrawn for: a new_len below the mapping's size
 * or above it, a fixed target, MAYMOVE alone or with DONTUNMAP, or no move
 * at all. */
enum mremap_draw {
	MREMAP_DRAW_SHRINK,
	MREMAP_DRAW_GROW,
	MREMAP_DRAW_FIXED,
	MREMAP_DRAW_MAYMOVE,
	MREMAP_DRAW_DONTUNMAP,
	MREMAP_DRAW_IN_PLACE,
};

/* An mremap() call the sanitiser built over the pool mapping, redrawn
 * until it is the one @want names. */
static struct syscallrecord *mremap_drawn(struct syscallentry *entry,
					  enum mremap_draw want)
{
	const unsigned long whole = POOL_PAGES * page_size;
	const unsigned long moves = MREMAP_FIXED | MREMAP_MAYMOVE |
				    MREMAP_DONTUNMAP;
	struct syscallrecord *mrec;
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		bool hit = false;

		mrec = mm_call(entry);
		entry->sanitise(mrec);
		switch (want) {
		case MREMAP_DRAW_SHRINK:
			hit = mrec->a3 < whole;
			break;
		case MREMAP_DRAW_GROW:
			hit = mrec->a3 > whole;
			break;
		case MREMAP_DRAW_FIXED:
			hit = (mrec->a4 & MREMAP_FIXED) != 0;
			break;
		case MREMAP_DRAW_MAYMOVE:
			hit = (mrec->a4 & moves) == MREMAP_MAYMOVE;
			break;
		case MREMAP_DRAW_DONTUNMAP:
			hit = (mrec->a4 & moves) ==
			      (MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
			break;
		case MREMAP_DRAW_IN_PLACE:
			hit = !(mrec->a4 & (MREMAP_FIXED | MREMAP_MAYMOVE));
			break;
		}
		if (hit)
			return mrec;
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);
	}
	BUG("mremap: the sanitiser never drew the call the case needs");
}

/* An mremap() that worked leaves the pool entry describing the mapping the
 * kernel made, where it returned and new_len long, as its VMA's extent too:
 * a munmap of it is held to that, not to the length it had before.  A
 * shrink in place, a shrink that moved, and a grow. */
static void mremap_post_follows_mapping(void)
{
	struct syscallentry mremap_entry = syscall_mremap;
	struct syscallentry munmap_entry = syscall_munmap;
	const unsigned long moved_to = POOL_MAP + 0x40000000UL;
	unsigned int i;

	fake_get_objhead = no_pool;
	for (i = 0; i < 3; i++) {
		struct syscallrecord *mrec =
			mremap_drawn(&mremap_entry, i == 2 ? MREMAP_DRAW_GROW :
						    MREMAP_DRAW_SHRINK);
		unsigned long to = i == 1 ? moved_to : POOL_MAP;
		unsigned long new_len = mrec->a3;

		mrec->retval = to;
		mremap_entry.post(mrec);
		if (pool_obj.map.ptr != (void *) to ||
		    pool_obj.map.size != new_len ||
		    pool_obj.map.tracked_size != new_len)
			BUG("mremap: the pool entry does not describe the mapping the kernel made");

		/* mm_call() would put the mapping back as it was. */
		mrec = &mm_child.syscall;
		memset(mrec, 0, sizeof(*mrec));
		mrec->entry = &munmap_entry;
		mrec->a1 = (unsigned long) &pool_obj.map;
		munmap_entry.sanitise(mrec);
		mrec->a1 = to;
		mrec->a2 = new_len + page_size;
		if (validate_arg_coupling(mrec, mrec->entry) != -1)
			BUG("mremap: a munmap past the remapped mapping was kept");
		mrec->a2 = new_len;
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mremap: a munmap of the remapped mapping was refused");
		mrec->retval = (unsigned long) -1L;
		munmap_entry.post(mrec);
	}
	fake_get_objhead = NULL;
	fake_this_child = NULL;
}

/* Whatever the sanitiser builds passes: over the pool mapping, over one
 * whose size is larger than its tracked size, and as a compat call.
 * Over the high mapping a compat call is built with an empty old range,
 * and never with a target its 32-bit slots cannot carry. */
static void mremap_sanitised_call_passes(struct syscallentry *entry)
{
	unsigned int i;

	for (i = 0; i < MM_DRAWS; i++) {
		struct syscallrecord *mrec = mm_call(entry);

		if (i & 1)
			pool_obj.map.size = 2 * POOL_PAGES * page_size;
		if (i % 5 == 0)
			pool_obj.map.ptr = (void *) LOW_POOL_MAP;
		mrec->do32bit = (i % 3) == 0;
		entry->sanitise(mrec);
		if (mrec->do32bit &&
		    (mrec->a1 > UINT_MAX || mrec->a2 > UINT_MAX ||
		     ((mrec->a4 & MREMAP_FIXED) &&
		      (mrec->a5 > UINT_MAX || mrec->a3 > UINT_MAX))))
			BUG("mremap: the sanitiser built a compat call its slots cannot carry");
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mremap: a call the sanitiser built was refused");
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);
	}
}

/* A rewritten slot is refused when it runs the old range past the mapping,
 * moves a mapping the sanitiser meant to resize in place, or aims a fixed
 * move anywhere but the target the sanitiser vetted: a substituted
 * address, a longer new_len, other flags.  MREMAP_DONTUNMAP alone only
 * hints at a target, so a DONTUNMAP move to a substituted address passes,
 * with the equal lengths the kernel requires of it; and a resize with no
 * fixed target is the kernel's to place, so a rewritten new_len passes,
 * and the post handler caches the new_len the kernel was handed. */
static void mremap_rewrites_held(struct syscallentry *entry)
{
	const unsigned long whole = POOL_PAGES * page_size;
	const unsigned long elsewhere = POOL_MAP + 0x40000000UL;
	struct syscallrecord *mrec;
	unsigned long a3, a4, a5;

	mrec = mremap_drawn(entry, MREMAP_DRAW_IN_PLACE);
	mrec->a2 = whole + page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: an old range running past the mapping was kept");
	mrec->a2 = whole;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mremap: an old range covering the mapping was refused");
	mrec->a4 |= MREMAP_MAYMOVE;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: a MAYMOVE the sanitiser did not draw was kept");
	mrec->a4 |= MREMAP_FIXED;
	mrec->a5 = elsewhere;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: a FIXED the sanitiser did not draw was kept");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);

	mrec = mremap_drawn(entry, MREMAP_DRAW_FIXED);
	a3 = mrec->a3;
	a4 = mrec->a4;
	a5 = mrec->a5;
	mrec->a5 = elsewhere;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: a fixed move to a substituted address was kept");
	mrec->a5 = a5;
	mrec->a3 = a3 + page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: a fixed move grown past its vetted target was kept");
	mrec->a3 = a3;
	mrec->a4 = a4 ^ MREMAP_DONTUNMAP;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: a fixed move with flags the sanitiser did not draw was kept");
	mrec->a4 = a4;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mremap: the fixed move the sanitiser vetted was refused");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);

	mrec = mremap_drawn(entry, MREMAP_DRAW_DONTUNMAP);
	mrec->a2 = 2 * page_size;
	mrec->a3 = 2 * page_size;
	mrec->a5 = elsewhere;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mremap: a DONTUNMAP move to a substituted address was refused");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);

	mrec = mremap_drawn(entry, MREMAP_DRAW_MAYMOVE);
	mrec->a3 = 3 * page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mremap: a resize with a rewritten new_len was refused");
	mrec->retval = elsewhere;
	entry->post(mrec);
	if (pool_obj.map.size != 3 * page_size ||
	    pool_obj.map.tracked_size != 3 * page_size)
		BUG("mremap: the post handler cached the new_len sanitise drew");
}

/* Nothing was drawn for a call without the call's own snapshot: none, a pid
 * where the pointer was, one the ownership table does not hold, or one with
 * another magic.  Only a call that moves nothing over an old range the
 * kernel acts on nothing of goes through then.  The sanitiser drops the
 * move bits the generator drew for a call it found no mapping for, so a
 * refusal there still means a rewrite. */
static void mremap_needs_its_snapshot(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);

	mrec->a1 = 0;
	mrec->a4 = MREMAP_FIXED | MREMAP_MAYMOVE;
	entry->sanitise(mrec);
	if (mrec->post_state != 0)
		BUG("mremap: the sanitiser left a snapshot with no mapping");
	if (mrec->a4 & (MREMAP_FIXED | MREMAP_MAYMOVE))
		BUG("mremap: a call with no mapping kept the move the generator drew");
	mrec->a3 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mremap: a call with no mapping that moves nothing was refused");
	mrec->a4 = MREMAP_MAYMOVE;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: a call with no mapping kept a move");
	mrec->a4 = 0;
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: a call with no mapping kept an old range");

	mrec = mremap_drawn(entry, MREMAP_DRAW_FIXED);
	mrec->a2 = 0;
	snapshot_gate_held(mrec, "mremap");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);
}

/* A compat call's kernel reads the low 32 bits of each slot: over a low
 * mapping, a fixed target whose upper half a rewrite changed is still the
 * one the sanitiser vetted, and a native call's is not. */
static void mremap_compat_target_truncated(struct syscallentry *entry)
{
	struct syscallrecord *mrec;
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		mrec = mm_call(entry);
		pool_obj.map.ptr = (void *) LOW_POOL_MAP;
		mrec->do32bit = true;
		entry->sanitise(mrec);
		if (mrec->a4 & MREMAP_FIXED)
			break;
		mrec->retval = (unsigned long) -1L;
		entry->post(mrec);
	}
	if (i == 1000)
		BUG("mremap: the sanitiser never drew a compat fixed move");

	mrec->a5 |= 1UL << 32;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mremap: a compat fixed move was judged on its target's upper half");
	mrec->do32bit = false;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mremap: a native fixed move's rewritten upper half was dropped");
	mrec->retval = (unsigned long) -1L;
	entry->post(mrec);
}

/* mremap's final old range stays inside the mapping its sanitiser picked,
 * and it moves to a fixed target only as the sanitiser vetted it. */
static void mremap_held_to_vetted_call(void)
{
	struct syscallentry mremap_entry = syscall_mremap;

	mremap_sanitised_call_passes(&mremap_entry);
	mremap_rewrites_held(&mremap_entry);
	mremap_needs_its_snapshot(&mremap_entry);
	mremap_compat_target_truncated(&mremap_entry);
	fake_this_child = NULL;
}

/* Run mincore()'s post handler over a call that returned @retval, then free
 * the vec its sanitiser handed the record: rec_owned_drain() frees only
 * what alloc-track holds, which the test binary's zmalloc_tracked() never
 * registers. */
static void mincore_done(struct syscallentry *entry, struct syscallrecord *mrec,
			 unsigned long retval)
{
	mrec->retval = retval;
	entry->post(mrec);
	while (mrec->owned_count > 0)
		free(mrec->owned[--mrec->owned_count]);
}

/* The sanitiser sizes vec to the pages of the len it drew, and whatever it
 * builds passes, a compat call included.  A len rewritten to more pages
 * than vec holds is refused, whatever brought it: one byte more, which the
 * kernel counts as a page, a pid, an address, the largest length.  One
 * within vec passes, a compat call's judged on the slot's low 32 bits.
 * The post handler's untouched-buffer check then looks only at the bytes
 * the kernel was asked to fill, so a call rewritten to a len of 0, which
 * the kernel returns 0 for without writing a byte, is not taken for one
 * that left vec untouched. */
static void mincore_len_held_to_vec(struct syscallentry *entry)
{
	/* Added to the len the sanitiser drew, a whole number of pages. */
	const unsigned long grown_by[] = {
		1, page_size, 3000000UL, 0x7f0000001000UL,
	};
	struct syscallrecord *mrec;
	unsigned long cap, untouched;
	unsigned int i;

	for (i = 0; i < MM_DRAWS; i++) {
		mrec = mm_call(entry);
		mrec->do32bit = (i % 10) == 0;
		entry->sanitise(mrec);
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mincore: a call the sanitiser built was refused");
		mincore_done(entry, mrec, (unsigned long) -1L);
	}

	for (i = 0; i < ARRAY_SIZE(grown_by); i++) {
		mrec = mm_call(entry);
		entry->sanitise(mrec);
		mrec->a2 += grown_by[i];
		if (validate_arg_coupling(mrec, mrec->entry) != -1)
			BUG("mincore: a len grown past vec was kept");
		mincore_done(entry, mrec, (unsigned long) -1L);
	}

	/* A pass leaves the snapshot the bytes the final len has the kernel
	 * fill, so a len of 0 comes last. */
	mrec = mm_call(entry);
	entry->sanitise(mrec);
	cap = mrec->a2;
	mrec->a2 = ULONG_MAX;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mincore: the largest len was kept");
	mrec->a2 = cap - 1;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mincore: a len inside vec was refused");
	mrec->a2 = cap | (1UL << 32);
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mincore: a native len's upper half was dropped");
	/* A compat call reads the low halves: of len, which are cap again,
	 * and of vec, which name the sanitiser's vec only below 4 GiB, as a
	 * non-PIE brk heap's do and an ASAN heap's do not. */
	mrec->do32bit = true;
	if (validate_arg_coupling(mrec, mrec->entry) != (mrec->a3 <= UINT_MAX ? 0 : -1))
		BUG("mincore: a compat call was judged on its slots' upper halves");
	mrec->do32bit = false;
	mrec->a2 = 0;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mincore: a len of 0 was refused");
	untouched = shm->stats.post_handler_untouched_out_buf;
	mincore_done(entry, mrec, 0);
	if (shm->stats.post_handler_untouched_out_buf != untouched)
		BUG("mincore: a call asked to fill nothing was taken for one that left vec untouched");
}

/* Without the call's own snapshot there is no vec to count on: none, from
 * a mapping too small to have a page, which leaves vec the buffer the
 * generator drew, a pid where the pointer was, one the ownership table
 * does not hold, or one with another magic.  Only a len of no pages goes
 * through then. */
static void mincore_needs_its_snapshot(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);

	pool_obj.map.size = page_size / 2;
	mrec->a3 = 0x10000000UL;
	entry->sanitise(mrec);
	if (mrec->post_state != 0 || mrec->a2 != 0)
		BUG("mincore: the sanitiser built a call over a mapping with no page");
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mincore: an empty call with no vec was refused");
	mrec->a2 = 1;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mincore: a call with no vec kept a len");

	mrec = mm_call(entry);
	entry->sanitise(mrec);
	snapshot_gate_held(mrec, "mincore");
	mincore_done(entry, mrec, (unsigned long) -1L);
}

/* The kernel writes into whatever vec the final slot names, so a call that
 * reports any page has to name the vec the sanitiser sized: a pinned vec
 * is refused unless the len reports none.  A compat call's kernel reads
 * the slot's low 32 bits, so the sanitiser gives a compat call whose vec
 * lies above them, as the writable pool it moves vec into does, a len of
 * no pages, and the call passes; one whose vec fits keeps its len. */
static void mincore_vec_held(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mm_call(entry);
	unsigned long vec;

	entry->sanitise(mrec);
	vec = mrec->a3;
	mrec->a3 = vec + page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mincore: a pinned vec was kept");
	mrec->a2 = 0;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mincore: a pinned vec reporting no pages was refused");
	mrec->a3 = vec;
	mincore_done(entry, mrec, (unsigned long) -1L);

	/* The heap the vec comes from counts as the libc heap here, so the
	 * sanitiser moves it into the writable pool count_held_inside_buffer()
	 * set up. */
	mrec = mm_call(entry);
	mrec->do32bit = true;
	fake_overlaps_libc_heap = true;
	entry->sanitise(mrec);
	fake_overlaps_libc_heap = false;
	if (mrec->a3 <= UINT_MAX)
		BUG("mincore: the vec did not move into the pool above 4 GiB");
	if (mrec->a2 != 0)
		BUG("mincore: a compat call kept a len for a vec its slot cannot carry");
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mincore: an emptied compat call was refused");
	mrec->a2 = page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mincore: a compat len rewritten past an emptied call was kept");
	mincore_done(entry, mrec, (unsigned long) -1L);

	mrec = mm_call(entry);
	mrec->do32bit = true;
	entry->sanitise(mrec);
	if ((mrec->a3 <= UINT_MAX) != (mrec->a2 != 0))
		BUG("mincore: a compat call's len did not follow whether its slot carries vec");
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mincore: a compat call the sanitiser built was refused");
	mincore_done(entry, mrec, (unsigned long) -1L);
}

/* mincore's final len reports no more pages than its vec holds. */
static void mincore_held_to_vec(void)
{
	struct syscallentry mincore_entry = syscall_mincore;

	mincore_len_held_to_vec(&mincore_entry);
	mincore_needs_its_snapshot(&mincore_entry);
	mincore_vec_held(&mincore_entry);
	fake_this_child = NULL;
}

/* post_mmap() dirties half the mappings it records, and maps_name_test.c
 * has it record some; what the walk writes is no part of a test. */
void dirty_mapping(struct map *map)
{
	(void) map;
}

/* No huge page sizes are known: the kernel's default. */
unsigned long pick_random_huge_size_encoding(void)
{
	return 0;
}

/* What an mmap() call is redrawn for: a MAP_FIXED that replaces what it
 * lands on, anonymous or over a file, or a call that replaces nothing. */
enum mmap_draw {
	MMAP_DRAW_FIXED_ANON,
	MMAP_DRAW_FIXED_FILE,
	MMAP_DRAW_UNFIXED,
};

/* An mmap() call the sanitiser built, redrawn until it is the one @want
 * names.  An empty fd pool leaves a file mapping fd 0. */
static struct syscallrecord *mmap_drawn(struct syscallentry *entry,
					enum mmap_draw want)
{
	struct syscallrecord *mrec;
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		bool replaces, hit = false;

		mrec = mm_call(entry);
		entry->sanitise(mrec);
		replaces = (mrec->a4 & MAP_FIXED) &&
			   !(mrec->a4 & MAP_FIXED_NOREPLACE);
		switch (want) {
		case MMAP_DRAW_FIXED_ANON:
			hit = replaces && (mrec->a4 & MAP_ANONYMOUS);
			break;
		case MMAP_DRAW_FIXED_FILE:
			hit = replaces && !(mrec->a4 & MAP_ANONYMOUS);
			break;
		case MMAP_DRAW_UNFIXED:
			hit = !replaces;
			break;
		}
		if (hit)
			return mrec;
		entry->cleanup(mrec);
	}
	BUG("mmap: the sanitiser never drew the call the case needs");
}

/* Whatever the sanitiser builds passes, natively and as a compat call. */
static void mmap_sanitised_call_passes(struct syscallentry *entry)
{
	unsigned int i;

	for (i = 0; i < MM_DRAWS; i++) {
		struct syscallrecord *mrec = mm_call(entry);

		mrec->do32bit = (i % 10) == 0;
		entry->sanitise(mrec);
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mmap: a call the sanitiser built was refused");
		entry->cleanup(mrec);
	}
}

/* A call whose final flags replace what MAP_FIXED lands on is refused
 * unless it places and sizes that range as the sanitiser vetted it: not at
 * an address an earlier mmap() returned, not longer, not with other flags,
 * which may round the length up to a huge page, and over a file not with
 * another fd.  An anonymous call's fd is no part of it.  MAP_FIXED_NOREPLACE
 * leaves an occupied range alone and no MAP_FIXED leaves the address a
 * hint, and either passes, but a MAP_FIXED the sanitiser did not draw is
 * refused. */
static void mmap_fixed_held(struct syscallentry *entry)
{
	struct syscallrecord *mrec;
	unsigned long a2, a4, a5;

	mrec = mmap_drawn(entry, MMAP_DRAW_FIXED_FILE);
	a2 = mrec->a2;
	a4 = mrec->a4;
	a5 = mrec->a5;
	mrec->a1 = POOL_MAP;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mmap: a MAP_FIXED at a substituted address was kept");
	mrec->a1 = 0;
	mrec->a2 = a2 + page_size;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mmap: a MAP_FIXED grown past its vetted length was kept");
	mrec->a2 = a2;
	mrec->a4 = a4 ^ MAP_HUGETLB;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mmap: a MAP_FIXED with flags the sanitiser did not draw was kept");
	mrec->a4 = a4;
	mrec->a5 = a5 + 1;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mmap: a MAP_FIXED over another file was kept");
	mrec->a5 = a5;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mmap: the MAP_FIXED the sanitiser vetted was refused");
	mrec->a1 = POOL_MAP;
	mrec->a4 = a4 | MAP_FIXED_NOREPLACE;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mmap: a MAP_FIXED_NOREPLACE was refused");
	entry->cleanup(mrec);

	mrec = mmap_drawn(entry, MMAP_DRAW_FIXED_ANON);
	mrec->a5 = 5;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mmap: an anonymous MAP_FIXED was judged on its fd");
	entry->cleanup(mrec);

	mrec = mmap_drawn(entry, MMAP_DRAW_UNFIXED);
	a4 = mrec->a4;
	mrec->a1 = POOL_MAP;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mmap: an address hint was refused");
	mrec->a4 = (a4 | MAP_FIXED) & ~(unsigned long) MAP_FIXED_NOREPLACE;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mmap: a MAP_FIXED the sanitiser did not draw was kept");
	entry->cleanup(mrec);
}

/* A compat call's kernel reads the low 32 bits of each slot: a MAP_FIXED
 * address whose upper half a rewrite changed is still the one the
 * sanitiser vetted, and a native call's is not. */
static void mmap_compat_slots_truncated(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mmap_drawn(entry, MMAP_DRAW_FIXED_ANON);

	mrec->do32bit = true;
	mrec->a1 |= 1UL << 32;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mmap: a compat MAP_FIXED was judged on its address's upper half");
	mrec->do32bit = false;
	if (validate_arg_coupling(mrec, mrec->entry) != -1)
		BUG("mmap: a native MAP_FIXED's rewritten upper half was dropped");
	entry->cleanup(mrec);
}

/* Nothing vets a MAP_FIXED without the call's own snapshot: a pid where
 * the pointer was, one the ownership table does not hold, or one with
 * another magic.  A call that replaces nothing is held to nothing, and the
 * sanitiser gives it no snapshot at all. */
static void mmap_needs_its_snapshot(struct syscallentry *entry)
{
	struct syscallrecord *mrec = mmap_drawn(entry, MMAP_DRAW_FIXED_ANON);

	snapshot_gate_held(mrec, entry->name);
	entry->cleanup(mrec);

	mrec = mmap_drawn(entry, MMAP_DRAW_UNFIXED);
	if (mrec->post_state != 0)
		BUG("mmap: a call that replaces nothing was given a snapshot");
	mrec->post_state = 12345;
	if (validate_arg_coupling(mrec, mrec->entry) != 0)
		BUG("mmap: a call that replaces nothing was refused for its snapshot");
	mrec->post_state = 0;
	entry->cleanup(mrec);
}

#if defined(__x86_64__)
/* A compat call through the i386 table's mmap is old_mmap(): the kernel
 * copies all six arguments from a struct at a1, as the low 32 bits read
 * it, so a1 is held to the NULL the sanitiser leaves there whatever the
 * other slots say, MAP_FIXED or not.  A compat mmap2 takes its arguments
 * in registers, and a1 without MAP_FIXED is only a hint there. */
static void mmap_arg_struct_held(struct syscallentry *mmap_entry,
				 struct syscallentry *mmap2_entry)
{
	struct syscallentry *const entries[] = { mmap_entry, mmap2_entry };
	unsigned int e, i;

	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		struct syscallrecord *mrec = NULL;

		for (i = 0; i < 1000; i++) {
			mrec = mm_call(entries[e]);
			mrec->do32bit = true;
			entries[e]->sanitise(mrec);
			if (!(mrec->a4 & MAP_FIXED) ||
			    (mrec->a4 & MAP_FIXED_NOREPLACE))
				break;
			entries[e]->cleanup(mrec);
		}
		if (i == 1000)
			BUG("mmap: the sanitiser never drew a compat call that replaces nothing");

		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mmap: a compat call the sanitiser built was refused");
		mrec->a1 = 1UL << 32;
		if (validate_arg_coupling(mrec, mrec->entry) != 0)
			BUG("mmap: a compat call was judged on a1's upper half");
		mrec->a1 = LOW_POOL_MAP;
		if (validate_arg_coupling(mrec, mrec->entry) != (entries[e]->is_mmap2 ? 0 : -1))
			BUG("mmap: a1 was held on the wrong ABI");
		entries[e]->cleanup(mrec);
	}
}
#endif

/* mmap's and mmap2's final MAP_FIXED replaces only the range their shared
 * sanitiser vetted. */
static void mmap_fixed_held_to_vetted_call(void)
{
	struct syscallentry mmap_entry = syscall_mmap;
	struct syscallentry mmap2_entry = syscall_mmap2;
	struct syscallentry *const entries[] = { &mmap_entry, &mmap2_entry };
	unsigned int e;

	/* As copy_syscall_table() stamps the copy. */
	mmap2_entry.is_mmap2 = true;
	fake_random_fd_empty = true;
	fake_rand_bitmask_draws = true;
	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		mmap_sanitised_call_passes(entries[e]);
		mmap_fixed_held(entries[e]);
		mmap_compat_slots_truncated(entries[e]);
		mmap_needs_its_snapshot(entries[e]);
	}
#if defined(__x86_64__)
	mmap_arg_struct_held(&mmap_entry, &mmap2_entry);
#endif
	fake_rand_bitmask_draws = false;
	fake_random_fd_empty = false;
	fake_this_child = NULL;
}

/* MAP_FIXED unmaps whatever its range covers, so mmap's sanitiser keeps
 * the range off trinity's own image too: from the address 0 it draws, a
 * long enough mapping reaches the text a non-PIE build loads low, which a
 * child with CAP_SYS_RAWIO may map over.  The lengths come from the
 * sizes production draws, which this binary otherwise leaves zero, and
 * the image table is the one image_table_covers_the_image() filled.  A
 * binary loaded past the longest of them, as a PIE one is, leaves nothing
 * here to check, and the test says so rather than passing. */
static void mmap_fixed_off_image(void)
{
	static const unsigned long sizes[NR_MAPPING_SIZES] = {
		4096, 64UL * 1024, 256UL * 1024, MB(1), MB(2),
		MB(4), MB(16), MB(64), GB(1),
	};
	struct syscallentry mmap_entry = syscall_mmap;
	unsigned long saved[NR_MAPPING_SIZES];
	unsigned int i, kept = 0;

	if (!range_overlaps_image((unsigned long) mmap_fixed_off_image, 1))
		BUG("mmap: the image table holds none of this binary");
	if (!range_overlaps_image(0, GB(1))) {
		printf("(no image segment below 1 GiB, skipping mmap's image check) ");
		return;
	}

	memcpy(saved, mapping_sizes, sizeof(saved));
	memcpy(mapping_sizes, sizes, sizeof(sizes));
	fake_random_fd_empty = true;
	fake_rand_bitmask_draws = true;
	for (i = 0; i < MM_DRAWS; i++) {
		struct syscallrecord *mrec = mm_call(&mmap_entry);

		mmap_entry.sanitise(mrec);
		if ((mrec->a4 & MAP_FIXED) && !(mrec->a4 & MAP_FIXED_NOREPLACE)) {
			if (range_overlaps_image(mrec->a1, mrec->a2))
				BUG("mmap: a MAP_FIXED over trinity's own image was kept");
			kept++;
		}
		mmap_entry.cleanup(mrec);
	}
	if (kept == 0)
		BUG("mmap: the sanitiser never kept a MAP_FIXED");
	memcpy(mapping_sizes, saved, sizeof(saved));
	fake_rand_bitmask_draws = false;
	fake_random_fd_empty = false;
	fake_this_child = NULL;
}

/* A shmat call the sanitiser built for segment @shmid over the mapping
 * fake_map_drawn names, redrawn until it keeps SHM_REMAP. */
static void shmat_remap_drawn(int shmid, bool compat)
{
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_shmat;
		rec.do32bit = compat;
		rec.a1 = (unsigned long) shmid;
		rec.a3 = SHM_REMAP;
		syscall_shmat.sanitise(&rec);
		if (rec.a3 & SHM_REMAP)
			return;
		syscall_shmat.cleanup(&rec);
	}
	BUG("shmat: the sanitiser never kept SHM_REMAP");
}

/* A final call carrying SHM_REMAP over an address replaces what lies there,
 * so it has to be the attach the sanitiser vetted: not at another address,
 * a page further into the mapping, nor of another segment, which may be
 * longer, nor with other flags, SHM_RND among them, which moves the
 * address.  The kernel reads shmid and shmflg as ints, so their upper
 * halves are no part of it.  A SHM_REMAP over a NULL address, which the
 * kernel refuses, and a call that lost SHM_REMAP pass, and the snapshot
 * is the call's own and goes at cleanup.  A SHM_REMAP the sanitiser did
 * not draw is refused. */
static void shmat_remap_held(int shmid)
{
	unsigned long a1, a2, a3;
	unsigned int i;

	shmat_remap_drawn(shmid, false);
	a1 = rec.a1;
	a2 = rec.a2;
	a3 = rec.a3;
	if (validate_arg_coupling(&rec, rec.entry) != 0)
		BUG("shmat: the SHM_REMAP attach the sanitiser vetted was refused");
	rec.a2 = a2 + page_size;
	if (validate_arg_coupling(&rec, rec.entry) != -1)
		BUG("shmat: a SHM_REMAP at a substituted address was kept");
	rec.a2 = a2;
	rec.a1 = a1 + 1;
	if (validate_arg_coupling(&rec, rec.entry) != -1)
		BUG("shmat: a SHM_REMAP of another segment was kept");
	rec.a1 = a1;
	rec.a3 = a3 | SHM_RND;
	if (validate_arg_coupling(&rec, rec.entry) != -1)
		BUG("shmat: a SHM_REMAP with flags the sanitiser did not draw was kept");
	rec.a3 = a3 & ~(unsigned long) SHM_REMAP;
	if (validate_arg_coupling(&rec, rec.entry) != 0)
		BUG("shmat: an attach without SHM_REMAP was refused");
	rec.a3 = a3;
	rec.a2 = 0;
	if (validate_arg_coupling(&rec, rec.entry) != 0)
		BUG("shmat: a SHM_REMAP with no address was refused");
	rec.a2 = a2;
	rec.a1 = a1 | (1UL << 32);
	rec.a3 = a3 | (1UL << 40);
	if (validate_arg_coupling(&rec, rec.entry) != 0)
		BUG("shmat: a SHM_REMAP was judged on the upper half of an int slot");
	rec.a1 = a1;
	rec.a3 = a3;
	snapshot_gate_held(&rec, "shmat");
	syscall_shmat.cleanup(&rec);
	if (rec.post_state != 0)
		BUG("shmat: cleanup left the snapshot behind");

	for (i = 0; i < 1000; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_shmat;
		rec.a1 = (unsigned long) shmid;
		syscall_shmat.sanitise(&rec);
		if (rec.a2 != 0)
			break;
	}
	if (i == 1000)
		BUG("shmat: the sanitiser never aimed an attach at the mapping");
	if (rec.post_state != 0)
		BUG("shmat: an attach without SHM_REMAP was given a snapshot");
	rec.a3 |= SHM_REMAP;
	if (validate_arg_coupling(&rec, rec.entry) != -1)
		BUG("shmat: a SHM_REMAP the sanitiser did not draw was kept");
	syscall_shmat.cleanup(&rec);
}

/* A compat call's kernel reads the low 32 bits of the address: a SHM_REMAP
 * address whose upper half a rewrite changed is still the one the
 * sanitiser vetted, and a native call's is not. */
static void shmat_compat_address_truncated(int shmid)
{
	pool_obj.map.ptr = (void *) 0x40001000UL;
	shmat_remap_drawn(shmid, true);
	rec.a2 |= 1UL << 32;
	if (validate_arg_coupling(&rec, rec.entry) != 0)
		BUG("shmat: a compat SHM_REMAP was judged on its address's upper half");
	rec.do32bit = false;
	if (validate_arg_coupling(&rec, rec.entry) != -1)
		BUG("shmat: a native SHM_REMAP's rewritten upper half was dropped");
	syscall_shmat.cleanup(&rec);
}

/* A SHM_REMAP attach that worked replaced pages of the mapping with the
 * segment's, so the post handler drops the pool entry: prot 0, known_rw
 * cleared, and the snapshot released.  One that failed, or an attach with
 * no SHM_REMAP, where the kernel picked the address, leaves the entry as
 * it was. */
static void shmat_remap_drops_entry(int shmid)
{
	unsigned int c;

	for (c = 0; c < 3; c++) {
		bool drops = c == 0;

		if (c < 2) {
			shmat_remap_drawn(shmid, false);
		} else {
			memset(&rec, 0, sizeof(rec));
			rec.entry = &syscall_shmat;
			rec.a1 = (unsigned long) shmid;
			syscall_shmat.sanitise(&rec);
		}
		pool_obj.map.prot = PROT_READ | PROT_WRITE;
		pool_obj.map.known_rw = true;
		rec.retval = c == 1 ? (unsigned long) -1L : POOL_MAP + page_size;
		syscall_shmat.post(&rec);
		if (rec.post_state != 0)
			BUG("shmat: the post handler left the snapshot behind");
		if ((pool_obj.map.prot == 0) != drops ||
		    pool_obj.map.known_rw == drops)
			BUG("shmat: the pool entry was kept after a SHM_REMAP attach, or dropped after another call");
		syscall_shmat.cleanup(&rec);
	}
}

/* shmat's final SHM_REMAP attaches only as its sanitiser vetted, and a call
 * the sanitiser built passes as it is, natively and as a compat call. */
static void shmat_remap_held_to_vetted_call(void)
{
	int shmid = shm_test_segment();
	unsigned int i;

	if (shmid < 0) {
		printf("(no SysV shared memory, skipping shmat's final slots) ");
		return;
	}

	fake_map_drawn = &pool_obj.map;
	pool_obj.map.ptr = (void *) (POOL_MAP + page_size);
	pool_obj.map.size = 4 * page_size;
	for (i = 0; i < SANITISER_DRAWS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_shmat;
		rec.do32bit = (i % 10) == 0;
		rec.a1 = (unsigned long) shmid;
		rec.a3 = rnd_u32() & (SHM_RDONLY | SHM_RND | SHM_REMAP | SHM_EXEC);
		syscall_shmat.sanitise(&rec);
		if (validate_arg_coupling(&rec, rec.entry) != 0)
			BUG("shmat: a call the sanitiser built was refused");
		syscall_shmat.cleanup(&rec);
	}
	shmat_remap_held(shmid);
	shmat_remap_drops_entry(shmid);
	shmat_compat_address_truncated(shmid);
	fake_map_drawn = NULL;
}

/* ipc()'s sanitiser draws its sem, msg and shm ids from pools this binary
 * does not have, and an empty pool hands out 0. */
int get_random_sysv_sem(void)
{
	return 0;
}

int get_random_sysv_msg(void)
{
	return 0;
}

int get_random_sysv_shm(void)
{
	return 0;
}

/* ipc()'s call numbers for shmat, shmdt and shmget, from <linux/ipc.h>,
 * which cannot share a file with <sys/shm.h>. */
enum { IPC_SHMAT = 21, IPC_SHMDT = 22, IPC_SHMGET = 23 };

/* An ipc() SHMAT call the sanitiser built. */
static void ipc_shmat_built(bool compat)
{
	memset(&rec, 0, sizeof(rec));
	rec.entry = &syscall_ipc;
	rec.do32bit = compat;
	rec.a1 = IPC_SHMAT;
	syscall_ipc.sanitise(&rec);
	if (rec.a4 == 0 || rec.post_state == 0)
		BUG("ipc: the sanitiser built a SHMAT with no result slot");
}

/* ipc() reaches shmat's attach through a SHMAT call.  The kernel stores
 * the attach address through third, which the sanitiser builds as a pool
 * slot, and SHM_REMAP replaces what lies at ptr, which it never draws, so
 * a final SHMAT passes only with that third and with no SHM_REMAP over a
 * shmaddr.  The slots are read as ksys_ipc() reads them: the version in
 * call's next 16 bits, of which only 1 refuses a SHMAT, an int shmid and
 * shmflg, and a compat call's third and ptr as their low 32 bits.  A
 * negative shmid, which attaches nothing, and another call's slots pass,
 * and so does every call the sanitiser builds, of each kind its ARG_OP
 * list names; a SHMAT made from another call's slots has no result slot
 * and does not. */
static void ipc_shmat_held(void)
{
	const struct arglist *calls = &syscall_ipc.arg_params[0].list;
	static const struct {
		unsigned long call, shmflg, ptr;
		int verdict;
	} cases[] = {
		{ IPC_SHMAT, SHM_REMAP, POOL_MAP, -1 },
		{ IPC_SHMAT, SHM_REMAP | SHM_RND, POOL_MAP + 1, -1 },
		{ IPC_SHMAT | (2UL << 16), SHM_REMAP, POOL_MAP, -1 },
		{ IPC_SHMAT | (1UL << 32), SHM_REMAP, POOL_MAP, -1 },
		{ IPC_SHMAT, SHM_REMAP | (1UL << 32), POOL_MAP, -1 },
		{ IPC_SHMAT, SHM_REMAP, 0, 0 },
		{ IPC_SHMAT | (1UL << 16), SHM_REMAP, POOL_MAP, 0 },
		{ IPC_SHMAT | (1UL << 16) | (1UL << 32), SHM_REMAP, POOL_MAP, 0 },
		{ IPC_SHMAT, (unsigned long) SHM_REMAP << 32, POOL_MAP, 0 },
		{ IPC_SHMAT, SHM_RND, POOL_MAP, 0 },
		{ IPC_SHMGET, SHM_REMAP, POOL_MAP, 0 },
		{ IPC_SHMDT, SHM_REMAP, POOL_MAP, 0 },
	};
	unsigned long raddr;
	unsigned int i;

	if (get_writable_struct(1) == NULL)
		writable_pool_init();

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		ipc_shmat_built(false);
		rec.a1 = cases[i].call;
		rec.a3 = cases[i].shmflg;
		rec.a5 = cases[i].ptr;
		if (validate_arg_coupling(&rec, rec.entry) != cases[i].verdict) {
			fprintf(stderr, "ipc: case %u, call 0x%lx shmflg 0x%lx ptr 0x%lx\n",
				i, cases[i].call, cases[i].shmflg, cases[i].ptr);
			BUG("ipc: a SHMAT's SHM_REMAP was judged wrongly");
		}
		syscall_ipc.cleanup(&rec);
	}

	ipc_shmat_built(false);
	raddr = rec.a4;
	rec.a4 = raddr + sizeof(unsigned long);
	if (validate_arg_coupling(&rec, rec.entry) != -1)
		BUG("ipc: a SHMAT storing its result past the slot sanitise built was kept");
	rec.a4 = POOL_MAP;
	if (validate_arg_coupling(&rec, rec.entry) != -1)
		BUG("ipc: a SHMAT storing its result at a substituted address was kept");
	rec.a2 = (unsigned long) -1;
	if (validate_arg_coupling(&rec, rec.entry) != 0)
		BUG("ipc: a SHMAT that attaches nothing was refused");
	rec.a2 = 0;
	rec.a4 = raddr;
	snapshot_gate_held(&rec, "ipc");
	syscall_ipc.cleanup(&rec);
	if (rec.post_state != 0)
		BUG("ipc: cleanup left the snapshot behind");

	/* A compat call's kernel stores through the low 32 bits of third,
	 * so where the pool lies past 4 GiB the sanitiser gives up the
	 * attach, and otherwise the upper halves are no part of the call. */
	ipc_shmat_built(true);
	if (rec.a4 > UINT_MAX) {
		if ((int) rec.a2 >= 0)
			BUG("ipc: a compat SHMAT kept a shmid for a result slot its third cannot carry");
		if (validate_arg_coupling(&rec, rec.entry) != 0)
			BUG("ipc: a compat SHMAT that attaches nothing was refused");
		rec.a2 = 0;
		if (validate_arg_coupling(&rec, rec.entry) != -1)
			BUG("ipc: a compat SHMAT storing through a truncated third was kept");
	} else {
		rec.a4 |= 1UL << 32;
		rec.a3 = SHM_REMAP;
		rec.a5 = 1UL << 32;
		if (validate_arg_coupling(&rec, rec.entry) != 0)
			BUG("ipc: a compat SHMAT was judged on the upper halves of third and ptr");
		rec.a5 |= 0x10000;
		if (validate_arg_coupling(&rec, rec.entry) != -1)
			BUG("ipc: a compat SHMAT remapping at a truncated shmaddr was kept");
	}
	syscall_ipc.cleanup(&rec);

	memset(&rec, 0, sizeof(rec));
	rec.entry = &syscall_ipc;
	rec.a1 = IPC_SHMDT;
	syscall_ipc.sanitise(&rec);
	rec.a1 = IPC_SHMAT;
	if (validate_arg_coupling(&rec, rec.entry) != -1)
		BUG("ipc: a SHMAT made from another call's slots was kept");

	for (i = 0; i < SANITISER_DRAWS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_ipc;
		rec.do32bit = (i % 10) == 0;
		rec.a1 = calls->values[i % calls->num];
		rec.a3 = rnd_u64();
		rec.a5 = rnd_u64();
		syscall_ipc.sanitise(&rec);
		if (validate_arg_coupling(&rec, rec.entry) != 0)
			BUG("ipc: a call the sanitiser built was refused");
		syscall_ipc.cleanup(&rec);
	}
}

void arg_coupling_self_check(void);
void arg_coupling_self_check(void)
{
	recv_count_held_inside_buffer();
	shmat_remap_held_to_mapping();
	get_mempolicy_addr_names_mapping();
	recv_buffer_names_mapping();
	send_buffer_names_mapping();
	getrandom_size_held_to_mapping();
	syslog_read_held_to_mapping();
	madvise_held();
	process_madvise_guard_install_held();
	count_slot_checked_at_table_init();
	count_held_inside_buffer();
	vet_final_asked_first();
	vet_final_from_the_dispatched_entry();
	epoll_wait_events_held();
	pkey_mprotect_known_through_its_copy();
	keyed_range_drops_cached_prot();
	keyed_range_known_through_the_dispatched_entry();
	munmap_range_held_to_mapping();
	range_pages_read_as_the_kernel_does();
	home_node_range_held_to_mapping();
	mseal_seals_only_its_own_mapping();
	remap_file_pages_range_held_to_mapping();
	mprotect_range_held_to_mapping();
	image_table_covers_the_image();
	mremap_fixed_target_off_image();
	mremap_fixed_target_checked_rounded();
	mremap_post_follows_mapping();
	mremap_held_to_vetted_call();
	mincore_held_to_vec();
	mmap_fixed_held_to_vetted_call();
	mmap_fixed_off_image();
	shmat_remap_held_to_vetted_call();
	ipc_shmat_held();
}
