#include <errno.h>
#include <setjmp.h>	// sigsetjmp for asb_relocate copy-fault recovery
#include <stdlib.h>	// exit / EXIT_FAILURE for alloc_iovec_init
#include <sys/uio.h>
#include <sys/socket.h>	// struct msghdr
#include <sys/mman.h>	// mmap for writable_pool_init
#include <string.h>

#include "arch.h"	// KERNEL_ADDR etc
#include "child.h"	// this_child(), per-child storm counters
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "maps.h"
#include "shm.h"
#include "signals.h"	// asb_copy_recover / asb_copy_active recovery slot
#include "stats_ring.h"
#include "tables.h"
#include "utils.h"

#include "kernel/mman.h"
/*
 * Dedicated MAP_PRIVATE|MAP_ANONYMOUS backing buffer for
 * get_writable_address().  Allocated once in the parent by
 * writable_pool_init() and inherited COW by every forked child.
 *
 * Properties that make this safe to hand to the kernel as a
 * copyout buffer across the fleet:
 *   - MAP_PRIVATE|MAP_ANON  -- no shared inode, no shmem object;
 *                              madvise(MADV_REMOVE), fallocate
 *                              (PUNCH_HOLE), ftruncate(shrink),
 *                              and madvise(MADV_DONTNEED_LOCKED)
 *                              cannot touch the backing pages.
 *   - track_shared_region   -- every mm-syscall sanitiser (munmap,
 *                              mremap, mprotect, madvise, mmap with
 *                              MAP_FIXED) rejects fuzzed addrs that
 *                              would land inside the pool.  The
 *                              mprotect_split / mmap_lifecycle /
 *                              madvise_pattern_cycler childops
 *                              already gate on range_overlaps_shared,
 *                              so the pool is invisible to them
 *                              without childop-side changes.
 *   - not add_object'd      -- the pool is never inserted into any
 *                              OBJ_MMAP_* pool, so get_random_object
 *                              walks cannot return it and a fuzzed
 *                              MAP_FIXED mmap cannot ask to land on
 *                              it (rejected by the shared-region
 *                              gate above).
 *   - parent-allocated      -- one VMA, COW per child; every child's
 *                              first write faults a private zero
 *                              page in -- cross-child writes never
 *                              interfere.
 *
 * Cursor advances forward; wraps when the next allocation would
 * overrun.  Within a single arg-gen pass the cursor never wraps
 * (pool sized far above per-syscall demand), so distinct
 * get_writable_address() calls from one syscall's sanitiser yield
 * disjoint buffers.  Across syscalls (sequential within one child)
 * wrap is harmless: the prior syscall's buffer is no longer in
 * use.
 */
#define WRITABLE_POOL_BYTES   (1UL << 20)   /* 1 MiB */
#define WRITABLE_POOL_ALIGN   16UL          /* covers __alignof__(max_align_t) */

static unsigned char *writable_pool;

void * get_writable_address(unsigned long size)
{
	struct childdata *child = this_child();
	unsigned long aligned, cursor, end;
	static unsigned long parent_cursor;
	unsigned long *cursor_p;

	if (writable_pool == NULL)
		return NULL;

	if (size == 0)
		size = page_size;

	aligned = (size + (WRITABLE_POOL_ALIGN - 1)) & ~(WRITABLE_POOL_ALIGN - 1);
	if (aligned > WRITABLE_POOL_BYTES)
		return NULL;

	cursor_p = (child != NULL) ? &child->writable_pool_cursor
				   : &parent_cursor;
	cursor = *cursor_p;
	end = cursor + aligned;
	if (end > WRITABLE_POOL_BYTES) {
		cursor = 0;
		end = aligned;
	}
	*cursor_p = end;
	return writable_pool + cursor;
}

/*
 * Page-aligned bump allocation from the writable pool.
 *
 * get_writable_address() returns 16-byte-aligned slots (max_align_t),
 * which is fine for arbitrary structs but wrong for buffers a kernel
 * ioctl aligns down internally -- notably VFIO_IOMMU_MAP_DMA, whose
 * vaddr is masked to PAGE_SIZE before the kernel pins the range.  A
 * 16-byte-aligned pool slot rounded down to the next page boundary
 * rewinds up to page_size - 1 bytes into whatever the previous
 * sanitiser call parked immediately below (typically the ioctl arg
 * struct itself), so the kernel then maps/pins those unrelated bytes
 * and truncates the payload tail.  If the ioctl writes through the
 * mapping, trinity's own scratch is corrupted and the child crashes
 * far from the syscall that scribbled it.
 *
 * Reserve size + page_size - 1 bytes so we can slide the base up to
 * the next page boundary and still fit `size` bytes above it inside
 * the reservation.  The pool VMA is page-aligned (mmap), so a cursor
 * offset rounded up to page_size is itself page-aligned in address
 * space.  Cursor is advanced past the payload end and re-rounded to
 * WRITABLE_POOL_ALIGN so subsequent get_writable_address() calls
 * still start on a 16-byte boundary.
 */
void * get_writable_page_aligned(unsigned long size)
{
	struct childdata *child = this_child();
	unsigned long cursor, aligned_offset, next_cursor;
	static unsigned long parent_cursor;
	unsigned long *cursor_p;
	unsigned long page_mask = (unsigned long)page_size - 1;

	if (writable_pool == NULL)
		return NULL;

	if (size == 0)
		size = page_size;

	if (size > WRITABLE_POOL_BYTES)
		return NULL;

	cursor_p = (child != NULL) ? &child->writable_pool_cursor
				   : &parent_cursor;
	cursor = *cursor_p;

	aligned_offset = (cursor + page_mask) & ~page_mask;
	if (aligned_offset + size > WRITABLE_POOL_BYTES) {
		/*
		 * Wrap: pool base is page-aligned so offset 0 is a valid
		 * page-aligned start.  size <= WRITABLE_POOL_BYTES was
		 * checked above, so the payload is guaranteed to fit.
		 */
		aligned_offset = 0;
	}

	next_cursor = (aligned_offset + size + (WRITABLE_POOL_ALIGN - 1))
		      & ~(WRITABLE_POOL_ALIGN - 1);
	*cursor_p = next_cursor;
	return writable_pool + aligned_offset;
}

void * get_non_null_address(void)
{
	unsigned long size = RAND_ARRAY(mapping_sizes);

	return get_writable_address(size);
}

void * get_writable_struct(size_t size)
{
	return get_writable_address(size);
}

/*
 * Defense-in-depth for output-buffer syscall args.  A fuzzed pointer that
 * lands inside one of trinity's own alloc_shared() regions — childdata,
 * the global stats blob, fd-event rings, etc. — turns any "kernel writes
 * here" syscall (read, recv, getdents, statx, ioctl _IOR, ...) into a
 * silent corruption of trinity bookkeeping.  Symptoms include impossible
 * counter values, non-canonical pointers, and crashes far from the
 * scribbled write.
 *
 * The same wholesale-stomp shape applies to trinity's *private* libc
 * heap arena: a fuzzed pointer landing in [heap_start, heap_end) lets
 * the kernel write on top of a glibc chunk header, and the next malloc
 * anywhere finds the corrupted arena and aborts.  The overnight
 * asan-self-kill triage attributed 1094 of 3488 child crashes (~31%)
 * to this exact shape -- libasan abort() inside __interceptor_malloc,
 * surfacing far from the upstream syscall that did the scribble.
 *
 * Sanitisers that hand the kernel a writable buffer call this to swap
 * the address out for a known-safe one before the syscall is issued.
 * Both regions are checked; the per-region counters tell which class
 * the redirect saved us from.
 *
 * Two flavors are exposed:
 *
 *   avoid_shared_buffer_out()   — relocate only. Correct for buffers the
 *                                 kernel *writes* into (read, recv,
 *                                 getdents, getsockname, …): trinity has
 *                                 no input bytes to preserve, and the
 *                                 kernel will populate the replacement
 *                                 page itself.
 *
 *   avoid_shared_buffer_inout() — relocate AND memcpy the original bytes
 *                                 into the replacement before rewriting
 *                                 the pointer. Required for buffers the
 *                                 kernel *reads* (or value-result: read
 *                                 then write). Without the copy, the
 *                                 kernel consumes whatever pool garbage
 *                                 happens to live at the replacement
 *                                 address instead of the sanitiser's
 *                                 curated input.
 */

static void asb_relocate(unsigned long *addr, unsigned long len,
			 bool copy_original)
{
	void *replacement;
	void *original;
	bool overlap_shared, overlap_heap;
	/*
	 * readable_skip / copy_faulted span the sigsetjmp/siglongjmp
	 * window below: readable_skip is set on the else arm that
	 * never enters sigsetjmp, copy_faulted is set on the longjmp
	 * return path.  Per C11 7.13.2.1 a non-volatile local whose
	 * value can change between setjmp and longjmp is indeterminate
	 * after the longjmp return, and gcc -Wclobbered flags both.
	 * Mark them volatile so the post-block stats reads see the
	 * value we actually wrote, not whatever ended up in a register
	 * the longjmp restore didn't preserve.
	 */
	volatile bool readable_skip = false;
	volatile bool copy_faulted = false;

	if (addr == NULL)
		return;
	if (*addr == 0)
		return;

	overlap_shared = range_overlaps_shared(*addr, len);
	overlap_heap = range_overlaps_libc_heap(*addr, len);
	if (!overlap_shared && !overlap_heap)
		return;

	/*
	 * Skip pointers that already live inside the writable pool.  The
	 * pool is track_shared_region()'d at init so every pool-vended
	 * address trips overlap_shared, but the pool is a safe kernel-
	 * write target by construction (MAP_PRIVATE|MAP_ANON scratch,
	 * never add_object'd, not on the libc heap) -- redirecting a
	 * pool address to a fresh pool address is pure waste and, when
	 * the two ranges intersect, feeds overlapping src/dst into the
	 * copy_original memcpy below (undefined behaviour, flagged by
	 * ASAN's memcpy-param-overlap).
	 */
	{
		unsigned long pool_start = (unsigned long) writable_pool;

		if (writable_pool != NULL &&
		    *addr >= pool_start &&
		    *addr + len <= pool_start + WRITABLE_POOL_BYTES)
			return;
	}

	replacement = get_writable_address(len ? len : page_size);
	if (replacement == NULL)
		return;

	original = (void *) *addr;
	/*
	 * Gate the source-side read.  The overlap predicates above only
	 * prove the range intersects a protected region; they do not
	 * prove the source is fully mapped.  range_readable_user() proves
	 * coverage from cached state (tracked shared regions + heap
	 * snapshots) so a wrapped pointer or a range that walks off the
	 * end of a VMA does not fault inside the memcpy and mask the
	 * kernel behaviour we are trying to fuzz with a userspace
	 * SIGSEGV.
	 *
	 * Even the cached-state gate is racy under fuzzed workloads: a
	 * sibling can tear down a tracked MAP_SHARED region via a raw
	 * munmap/mremap that bypasses untrack_shared_region(), leaving
	 * range_in_tracked_shared() with a stale "yes" answer.  The next
	 * memcpy from that source then faults on the now-unmapped VMA
	 * (SIGSEGV / SEGV_MAPERR) and the child dies, masking the
	 * kernel behaviour we were about to fuzz.  Wrap the speculative
	 * copy in sigsetjmp/siglongjmp so the fault degrades to the
	 * no-copy fall-through instead of killing the child: the kernel
	 * SIGSEGV/SIGBUS handler (child_fault_handler) checks
	 * asb_copy_active first and longjmp's back here when the fault
	 * fires inside the copy window.
	 *
	 * The no-copy fall-through is safe: get_writable_address()
	 * already filled @replacement with fuzz data, and the *addr
	 * rewrite below still redirects the kernel away from the
	 * protected region.  Kernel reading pool scratch bytes is
	 * strictly better than the kernel chasing an unreadable source.
	 */
	if (copy_original && len != 0) {
		if (range_readable_user(original, len)) {
			if (sigsetjmp(asb_copy_recover, 1) == 0) {
				asb_copy_active = 1;
				memcpy(replacement, original, len);
				asb_copy_active = 0;
			} else {
				/*
				 * child_fault_handler caught a real
				 * SIGSEGV/SIGBUS inside the memcpy and
				 * longjmp'd back.  Clear the flag FIRST so
				 * any subsequent fault in this child (real
				 * kernel-fuzzed crash, unrelated bug) takes
				 * the normal diagnostic + _exit path rather
				 * than silently recovering here.  Skip the
				 * copy; *addr is still redirected below.
				 */
				asb_copy_active = 0;
				copy_faulted = true;
			}
		} else {
			readable_skip = true;
		}
	}

	*addr = (unsigned long) replacement;
	if (shm != NULL) {
		struct childdata *c = this_child();

		if (c != NULL && c->stats_ring != NULL) {
			if (overlap_shared)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_SHARED_BUFFER_REDIRECTED,
						   0, 1);
			if (overlap_heap)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_LIBC_HEAP_REDIRECTED,
						   0, 1);
			if (readable_skip)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_ASB_RELOCATE_READABLE_SKIP,
						   0, 1);
			if (copy_faulted)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_ASB_RELOCATE_COPY_FAULT,
						   0, 1);
		} else {
			if (overlap_shared)
				parent_stats.shared_buffer_redirected++;
			if (overlap_heap)
				parent_stats.libc_heap_redirected++;
			if (readable_skip)
				parent_stats.asb_relocate_readable_skip++;
			if (copy_faulted)
				parent_stats.asb_relocate_copy_fault++;
		}
	}
}

void avoid_shared_buffer_out(unsigned long *addr, unsigned long len)
{
	asb_relocate(addr, len, false);
}

void avoid_shared_buffer_inout(unsigned long *addr, unsigned long len)
{
	asb_relocate(addr, len, true);
}

void * get_address(void)
{
	if (ONE_IN(100))
		return NULL;

	return get_non_null_address();
}

static bool is_arg_address(enum argtype argtype)
{
	if (argtype == ARG_ADDRESS)
		return true;
	if (argtype == ARG_NON_NULL_ADDRESS)
		return true;
	return false;
}

unsigned long find_previous_arg_address(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	unsigned long addr = 0;

	if (argnum > 1)
		if (is_arg_address(entry->argtype[0]) == true)
			addr = rec->a1;

	if (argnum > 2)
		if (is_arg_address(entry->argtype[1]) == true)
			addr = rec->a2;

	if (argnum > 3)
		if (is_arg_address(entry->argtype[2]) == true)
			addr = rec->a3;

	if (argnum > 4)
		if (is_arg_address(entry->argtype[3]) == true)
			addr = rec->a4;

	if (argnum > 5)
		if (is_arg_address(entry->argtype[4]) == true)
			addr = rec->a5;

	return addr;
}


/*
 * Second-pass scrub of an iovec[] handed to a kernel-write syscall
 * (readv / preadv* / process_vm_readv / recvmsg / recvmmsg / process_
 * madvise -- and the corresponding kernel-read syscalls where a
 * scribbled iov_base would still let the kernel touch the wrong page).
 *
 * alloc_iovec() already runs avoid_shared_buffer() per iov_base at
 * build time (which post c4f1c69cdb08 covers both alloc_shared regions
 * and the libc brk arena), but the iovec array lives in the per-child
 * heap as a vlen * sizeof(struct iovec) zmalloc().  A sibling syscall
 * that scribbles bytes into that allocation between the sanitiser
 * returning and the kernel reading the array can replace any iov_base
 * with a fuzzed value -- and a value landing in the libc brk arena
 * lets the kernel write on top of a glibc chunk header, surfacing
 * later as a glibc heap-corruption assert via the next malloc anywhere
 * in trinity (the dominant non-ASAN cluster: __zmalloc -> malloc ->
 * malloc_printerr -> abort).
 *
 * Walk the array one final time and zero any entry whose [base, base+
 * len) overlaps either an alloc_shared region or the libc brk arena.
 * Zero base + zero len makes the kernel skip the entry without erroring
 * the whole call.  Bumps libc_heap_embedded_redirected so the operator
 * can see the second-pass coverage independently from the
 * shared_buffer_redirected / libc_heap_redirected counters that track
 * the build-time defense.
 */
void scrub_iovec_for_kernel_write(struct iovec *iov, unsigned long count)
{
	unsigned long i;

	if (iov == NULL || count == 0)
		return;

	if (count > UIO_MAXIOV)
		count = UIO_MAXIOV;

	for (i = 0; i < count; i++) {
		unsigned long base = (unsigned long) iov[i].iov_base;
		unsigned long len = iov[i].iov_len;
		bool overlap_shared, overlap_heap;

		if (base == 0 || len == 0)
			continue;

		overlap_shared = range_overlaps_shared(base, len);
		overlap_heap = range_overlaps_libc_heap(base, len);
		if (!overlap_shared && !overlap_heap)
			continue;

		iov[i].iov_base = NULL;
		iov[i].iov_len = 0;
		if (shm != NULL && overlap_heap) {
			struct childdata *c = this_child();

			if (c != NULL && c->stats_ring != NULL)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_LIBC_HEAP_EMBEDDED_REDIRECTED,
						   0, 1);
			else
				parent_stats.libc_heap_embedded_redirected++;
		}
	}
}

/*
 * Per-msghdr second-pass scrub.  Walks the embedded msg_iov array via
 * scrub_iovec_for_kernel_write() so a sibling scribble that landed an
 * iov_base in the libc brk arena (or in an alloc_shared region) is
 * defanged before the kernel walks the array.  msg_name / msg_control
 * are intentionally not redirected: those fields are populated only by
 * trinity-controlled allocators (zmalloc, get_address) at sanitise
 * time and the post handlers free them based on their stored values --
 * silently swapping them out would either UAF the original allocation
 * or hand free() a non-malloc pointer.  Sibling-scribble exposure on
 * those fields is handled by the existing inner_ptr_ok_to_free()
 * shape check at free time rather than at sanitise time.
 */
void scrub_msghdr_for_kernel_write(struct msghdr *msg)
{
	if (msg == NULL)
		return;
	if (msg->msg_iov == NULL || msg->msg_iovlen == 0)
		return;

	scrub_iovec_for_kernel_write(msg->msg_iov, msg->msg_iovlen);
}

/*
 * Per-entry iovec shape picker.  Returns a bucket index that the
 * alloc_iovec() loop dispatches on so individual entries get NULL /
 * tiny / page-crossing / shared-base / pool / invalid shapes instead
 * of the original blanket "valid-map + variable length".  The
 * shared-base bucket needs a predecessor entry to mirror, so for the
 * first entry the picker collapses that band into SHAPE_VALID_MAP.
 *
 * Bucket weights for IOV_KERNEL_WRITE callers (sum 100):
 *  10  SHAPE_NULL        — NULL base, zero len; iov_iter skip arm
 *  10  SHAPE_TINY        — valid map base, len=1; page-walk early-exit
 *  10  SHAPE_PAGECROSS   — len > page_size; iov_iter page advance
 *  10  SHAPE_SHARED      — iov[i-1].iov_base with a different length
 *   5  SHAPE_POOL        — get_writable_address() page, half-len
 *   5  SHAPE_INVALID     — 0xdeadbeef, len=1; EFAULT reject arm
 *  50  SHAPE_VALID_MAP   — preserves the original behaviour
 *
 * For IOV_KERNEL_READ callers (writev / sendmsg / vmsplice /
 * process_vm_writev) SHAPE_NULL and SHAPE_INVALID would EFAULT the
 * kernel's copy_from_iter() before any fuzz coverage is reached, so
 * the picker drops both buckets and renormalises the remaining 85
 * units back to 100:
 *  12  SHAPE_TINY
 *  12  SHAPE_PAGECROSS
 *  12  SHAPE_SHARED      — collapses to SHAPE_VALID_MAP for idx == 0
 *   6  SHAPE_POOL
 *  58  SHAPE_VALID_MAP
 */
enum iovec_entry_shape {
	SHAPE_NULL,
	SHAPE_TINY,
	SHAPE_PAGECROSS,
	SHAPE_SHARED,
	SHAPE_POOL,
	SHAPE_INVALID,
	SHAPE_VALID_MAP,
};

static enum iovec_entry_shape pick_iovec_entry_shape(unsigned int idx,
						     enum iov_direction dir)
{
	unsigned int r = rnd_modulo_u32(100);

	if (dir == IOV_KERNEL_READ) {
		if (r < 12)
			return SHAPE_TINY;
		if (r < 24)
			return SHAPE_PAGECROSS;
		if (r < 36)
			return (idx > 0) ? SHAPE_SHARED : SHAPE_VALID_MAP;
		if (r < 42)
			return SHAPE_POOL;
		return SHAPE_VALID_MAP;
	}

	if (r < 10)
		return SHAPE_NULL;
	if (r < 20)
		return SHAPE_TINY;
	if (r < 30)
		return SHAPE_PAGECROSS;
	if (r < 40)
		return (idx > 0) ? SHAPE_SHARED : SHAPE_VALID_MAP;
	if (r < 45)
		return SHAPE_POOL;
	if (r < 50)
		return SHAPE_INVALID;
	return SHAPE_VALID_MAP;
}

static inline void fill_iov_entry_map_backed(struct iovec *iov,
					     unsigned int i,
					     enum iov_direction dir,
					     enum iovec_entry_shape shape)
{
	struct map *map;
	unsigned long base;

	/*
	 * Map-backed shapes share the same base lookup + scrub tail.
	 *
	 * For IOV_KERNEL_READ callers the avoid_shared_buffer_inout()
	 * scrub below memcpy()s the original bytes into the replacement
	 * buffer, which requires the source map to actually be readable.
	 * The initial map pool (mm/maps-initial.c) includes PROT_WRITE-
	 * only, PROT_EXEC-only and PROT_NONE entries, and reading from
	 * any of those SEGVs trinity inside the sanitiser before the
	 * syscall ever fires.  Filter to entries that include PROT_READ
	 * for the read direction; the write direction is content-blind
	 * (kernel overwrites the buffer) so protection diversity remains
	 * the point and plain get_map() is correct there.
	 *
	 * If no readable map is available, fall back to a scratch buffer
	 * from get_writable_address() (PROT_READ|PROT_WRITE backed) so
	 * the entry still produces coverage rather than being silently
	 * dropped.
	 */
	if (dir == IOV_KERNEL_READ)
		map = get_map_with_prot(PROT_READ);
	else
		map = get_map();
	if (map == NULL) {
		if (dir == IOV_KERNEL_READ) {
			void *scratch = get_writable_address(page_size);

			if (scratch != NULL) {
				iov[i].iov_base = scratch;
				iov[i].iov_len = (shape == SHAPE_TINY)
					? 1
					: page_size / 2;
				return;
			}
		}
		iov[i].iov_base = NULL;
		iov[i].iov_len = 0;
		return;
	}

	iov[i].iov_base = map->ptr;
	if (shape == SHAPE_TINY) {
		iov[i].iov_len = 1;
	} else if (shape == SHAPE_PAGECROSS && map->size > page_size) {
		unsigned long len = page_size + RAND_RANGE(1, 64);

		if (len > map->size)
			len = map->size;
		iov[i].iov_len = len;
	} else if (RAND_BOOL()) {
		const unsigned int lens[] = {
			0, 1, page_size - 1, page_size,
			page_size + 1, page_size * 2,
		};
		iov[i].iov_len = lens[rnd_modulo_u32(ARRAY_SIZE(lens))];
	} else {
		iov[i].iov_len = map->size > 0 ? rnd_modulo_u32(map->size) : 0;
	}

	/*
	 * Per-entry relocation away from alloc_shared() regions and
	 * the libc brk arena.  A get_map() pointer can in principle
	 * alias one of trinity's alloc_shared() regions (children
	 * blob, fd_event_ring, shared obj/string heaps) or land in
	 * libc brk, both of which would let the kernel scribble
	 * bookkeeping.
	 *
	 * Both directions use avoid_shared_buffer_out().  For
	 * IOV_KERNEL_WRITE callers (readv, preadv, preadv2,
	 * recvmsg, recvmmsg, process_vm_readv, process_madvise)
	 * the kernel overwrites the buffer, so preserving input
	 * bytes is wasted work.  For IOV_KERNEL_READ callers
	 * (writev, pwritev, pwritev2, sendmsg, sendmmsg, vmsplice,
	 * process_vm_writev) the source pages are anon shmem from
	 * MAP_SHARED|MAP_ANONYMOUS initial maps; their demand-
	 * fault can SIGBUS when the shmem allocator cannot back
	 * the page.  range_readable_user() verifies VMA permission
	 * but cannot predict per-page allocability, so a copy-in
	 * variant would SIGBUS the sanitiser before the syscall
	 * ever fires.  None of the seven IOV_KERNEL_READ post-
	 * handlers deref iov_base after the syscall (only retval
	 * and scalars are consumed), so preserving source bytes
	 * across relocation buys nothing.
	 */
	base = (unsigned long) iov[i].iov_base;
	avoid_shared_buffer_out(&base, iov[i].iov_len);
	iov[i].iov_base = (void *) base;
}

/*
 * Dedicated backing buffer for alloc_iovec()'s iov[] arrays.  The
 * buffer is carved into NR_IOVEC_SLICES disjoint slices of UIO_MAXIOV
 * entries each; alloc_iovec() returns the slice at iovec_pool_cursor
 * and advances the cursor.  Back-to-back alloc_iovec() calls -- e.g.
 * lvec+rvec for process_vm_readv or the two iovec args of
 * process_vm_writev -- therefore land in disjoint arrays, so the
 * second generation call cannot overwrite the first.  With four
 * slices there is 2x headroom over the two-iovec-arg syscalls, which
 * is the current fleet maximum; the ring wraps at slice 4 so any
 * future syscall with more iovec args would need this bumped.
 *
 * The cursor lives per-child via COW: each forked child gets its own
 * copy of the .data page on first advance.  Allocated once in the
 * parent by alloc_iovec_init() and re-used by every forked child.
 * See the comment at alloc_iovec_init() for the rationale on the
 * dedicated mapping over a writable-pool slot.
 */
#define NR_IOVEC_SLICES 4
static struct iovec *iovec_pool;
static unsigned int iovec_pool_cursor;

void writable_pool_init(void)
{
	void *p = mmap(NULL, WRITABLE_POOL_BYTES, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		outputerr("writable_pool_init: mmap %lu failed: %s\n",
			  WRITABLE_POOL_BYTES, strerror(errno));
		exit(EXIT_FAILURE);
	}
	memset(p, 0, WRITABLE_POOL_BYTES);
	track_shared_region((unsigned long)p, WRITABLE_POOL_BYTES);
	writable_pool = p;
}

void alloc_iovec_init(void)
{
	const size_t bytes = NR_IOVEC_SLICES * UIO_MAXIOV * sizeof(struct iovec);
	void *p;

	/*
	 * Dedicated MAP_PRIVATE|MAP_ANON mapping for the iov[] array.
	 *
	 * Earlier iterations of this code drew the buffer from
	 * get_writable_address(), which hands back a slot from the
	 * writable pool of MAP_SHARED / shmem-backed regions.  Those
	 * slots are eligible targets for fuzzed madvise(MADV_REMOVE) /
	 * ftruncate hole-punching, both of which strip the page's
	 * physical backing without changing the VMA's protection bits.
	 * The next write into the slot then SIGBUSes (BUS_ADRERR) at
	 * the freshly-punched page even though the mapping looks fully
	 * writable.  MAP_PRIVATE|MAP_ANON cannot be hole-punched
	 * (MADV_REMOVE / fallocate(PUNCH_HOLE) both reject anonymous
	 * VMAs with EINVAL) and the kernel always supplies a fresh zero
	 * page on the first write to any page in the mapping, so the
	 * SIGBUS class collapses entirely.
	 *
	 * The mapping is registered with the shared-region tracker so
	 * the mm-syscall sanitisers (munmap / mremap / mprotect /
	 * madvise / mmap with MAP_FIXED) refuse fuzzed addresses that
	 * would land inside it -- the buffer's PROT_WRITE can never be
	 * stripped and the VMA can never be torn out from under us, so
	 * the dual SEGV_ACCERR class is killed at the same time.
	 *
	 * Done in the parent before any child forks so the address and
	 * the shared_regions[] entry are inherited by every child via
	 * COW; each child's first write to a page faults in its own
	 * private zero page and subsequent writes stay child-local.
	 * Allocated once and never freed -- this buffer is trinity's
	 * own arg-gen scratch, not a fuzz target.
	 *
	 * Failure to allocate is fatal: without the buffer alloc_iovec()
	 * cannot produce iov[] args at all, matching the fail-loud
	 * posture of the other parent-side shared regions (deferred-
	 * free ring, alloc_track[], inflight_hash, ...).
	 */
	p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		outputerr("alloc_iovec_init: mmap %zu failed: %s\n",
			  bytes, strerror(errno));
		exit(EXIT_FAILURE);
	}
	memset(p, 0, bytes);
	track_shared_region((unsigned long)p, bytes);
	iovec_pool = p;
}

struct iovec * alloc_iovec(unsigned int num, enum iov_direction dir)
{
	struct iovec *iov;
	unsigned int i;

	/*
	 * num == 0 is a legal bucket from handle_arg_iovec (the iov_iter
	 * "no segments" arm).  Both downstream walkers --
	 * scrub_iovec_for_kernel_write() and the deferred-free path --
	 * are already NULL-safe (see the early returns at random-
	 * address.c:487 and the io_uring_register post-handler).
	 */
	if (num == 0)
		return NULL;

	/*
	 * Each slice holds exactly UIO_MAXIOV entries.  generate-args
	 * hands num == UIO_MAXIOV + 1 to exercise the kernel's oversized-
	 * iovcnt EINVAL arm; that count reaches the syscall via publish_
	 * paired_length(), so cap the fill here -- writing iov[UIO_MAXIOV]
	 * runs off the slice into the next slice (or, on the last slice,
	 * into the adjacent unmapped page).
	 */
	iov = iovec_pool + iovec_pool_cursor * UIO_MAXIOV;
	iovec_pool_cursor = (iovec_pool_cursor + 1) % NR_IOVEC_SLICES;
	if (num > UIO_MAXIOV)
		num = UIO_MAXIOV;

	for (i = 0; i < num; i++) {
		enum iovec_entry_shape shape = pick_iovec_entry_shape(i, dir);
		void *pool;

		switch (shape) {
		case SHAPE_NULL:
			iov[i].iov_base = NULL;
			iov[i].iov_len = 0;
			continue;
		case SHAPE_SHARED:
			/*
			 * i > 0 guaranteed by pick_iovec_entry_shape.
			 * Overlap with the previous entry so iov_iter walks
			 * revisit the same userspace bytes -- exercises the
			 * loop's len bookkeeping under range aliasing.  No
			 * avoid_shared_buffer_out scrub: iov[i-1].iov_base
			 * already went through it on the previous iteration.
			 */
			iov[i].iov_base = iov[i - 1].iov_base;
			iov[i].iov_len = 1 + rnd_modulo_u32(page_size);
			continue;
		case SHAPE_POOL:
			pool = get_writable_address(page_size);
			if (pool != NULL) {
				iov[i].iov_base = pool;
				iov[i].iov_len = page_size / 2;
				continue;
			}
			/* Pool exhaustion -- fall through to valid-map. */
			shape = SHAPE_VALID_MAP;
			break;
		case SHAPE_INVALID:
			/*
			 * EFAULT reject arm.  scrub_iovec_for_kernel_write()
			 * leaves this base alone (its overlap checks key off
			 * heap / shared-region bounds, not arbitrary
			 * pointers), so read-side callers like readv/recvmsg
			 * still EFAULT cleanly; write-side callers (vmsplice,
			 * process_madvise, process_vm_readv) get the EFAULT
			 * path directly.  Intentionally asymmetric -- new
			 * coverage, document so a future audit does not mistake
			 * the kernel reject for a trinity regression.
			 */
			iov[i].iov_base = (void *) 0xdeadbeefUL;
			iov[i].iov_len = 1;
			continue;
		case SHAPE_TINY:
		case SHAPE_PAGECROSS:
		case SHAPE_VALID_MAP:
			break;
		}

		fill_iov_entry_map_backed(iov, i, dir, shape);
	}

	return iov;
}
