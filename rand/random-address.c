#include <errno.h>
#include <setjmp.h>	// sigsetjmp for asb_relocate copy-fault recovery
#include <sys/uio.h>
#include <sys/socket.h>	// struct msghdr
#include <sys/mman.h>	// mprotect
#include <sys/ipc.h>
#include <sys/shm.h>
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

void * get_writable_address(unsigned long size)
{
	struct map_handle h;
	/* volatile on map, mincore_retries and tries: all three are
	 * written between sigsetjmp(gwa_bookkeeping_recover) and its
	 * potential longjmp (tries++ at the retry: label,
	 * mincore_retries in the from_mmap branch).
	 * ISO C 7.13.2.1 only guarantees post-longjmp values for objects
	 * with volatile-qualified type, and gcc -Wclobbered flags them
	 * otherwise.  Volatile on the pointer (not the pointee) keeps
	 * map->* field accesses non-volatile; the only cost is reloading
	 * the map pointer from stack on each use, which is well below
	 * the dominant per-call mprotect()/mincore() cost. */
	struct map * volatile map = NULL;
	struct object *obj;
	void *addr = NULL;
	volatile int tries = 0;
	volatile int mincore_retries = 0;
	bool from_mmap = false;

retry:	tries++;
	/*
	 * Reset per-iteration state.  The retry: label can be reached
	 * from anywhere below after from_mmap/map have been set on a
	 * prior iteration; without this reset the later from_mmap branches
	 * see stale values from that earlier iteration.  The RAND_BOOL()
	 * == true arm below sets both fields afresh when taken.
	 */
	from_mmap = false;
	map = NULL;
	if (tries == 100)
		return NULL;

	/*
	 * Defense-in-depth recovery for the map-struct bookkeeping
	 * stores below.  range_overlaps_libc_heap() guards against a
	 * fuzzed mmap(MAP_FIXED, PROT_READ) landing on the brk arena,
	 * but the cached_brk_end snapshot can lag the live break under
	 * cmp-hint / RedQueen pressure; if a fuzzed PROT_READ overlay
	 * slips through and lands on a brk page that hosts a map
	 * struct, the map->prot write later in this function
	 * SEGV_ACCERRs the child.
	 *
	 * Install one sigsetjmp recovery point per retry iteration.  On
	 * SIGSEGV/SIGBUS with si_code > 0 while gwa_bookkeeping_active
	 * is set (set ONLY across each individual map-field store),
	 * child_fault_handler longjmps back here.  Bump the counter so
	 * the rate is visible -- a non-zero number means the brk-overlap
	 * gate above missed a case and we silently survived something
	 * that ought to have been caught upstream -- and goto retry to
	 * pick a different pool slot.  The pre-existing tries == 100
	 * cap above bounds the retry budget so a mostly-RO pool can't
	 * spin here forever.
	 */
	if (sigsetjmp(gwa_bookkeeping_recover, 1) != 0) {
		struct childdata *c;

		gwa_bookkeeping_active = 0;
		c = this_child();
		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_GET_WRITABLE_BOOKKEEPING_RO_FAULT,
					   0, 1);
		else
			parent_stats.get_writable_address_bookkeeping_ro_fault++;
		goto retry;
	}

	if (RAND_BOOL()) {
		from_mmap = true;
		if (!get_map_handle(&h))
			goto retry;
		map = h.map;
		/*
		 * Sanity-guard the map pointer before deref.  Heap pointers
		 * land at >= 0x10000 and below the user/kernel VA boundary;
		 * anything else is a stale or corrupted slot from the
		 * per-child OBJ_MMAP pool and dereferencing it SIGSEGVs.
		 * Log loudly so the corruption source is visible — this
		 * branch ought to be impossible.
		 */
		if ((uintptr_t)map < 0x10000UL ||
		    (uintptr_t)map >= 0x800000000000UL) {
			outputerr("get_writable_address: bogus map pointer %p "
				  "from get_map_handle() — pool corruption?\n",
				  map);
			goto retry;
		}
		/*
		 * If the map struct itself sits in a tracked shared region,
		 * the prot-bookkeeping store below would either SIGSEGV
		 * (post-freeze the OBJ_GLOBAL backing heap is mprotect
		 * PROT_READ) or scribble shared bookkeeping (an OBJ_LOCAL
		 * map pointer that aliased into the shared heap is by
		 * definition a stale slot — OBJ_LOCAL maps live on the
		 * child's private heap, never inside any tracked region).
		 * Either way, retry to pick a different slot.
		 */
		if (range_overlaps_shared((unsigned long)map, sizeof(*map)))
			goto retry;
		/*
		 * Honor the prot=0 invalidation that post_munmap and
		 * post_mprotect stamp onto pool entries when a sibling
		 * syscall hole-punches or downgrades prot on the
		 * underlying VMAs.  Without this skip, a stale entry
		 * sails past every check and the caller faults on first
		 * access (SEGV_MAPERR on hole-punched pages, SEGV_ACCERR
		 * on PROT_NONE pages).  Mirrors the (m->prot & req) == req
		 * filter in get_map_with_prot(); the prot=0 case is the
		 * common ground that catches every consumer.
		 */
		if (map->prot == 0)
			goto retry;
		/*
		 * Skip hugetlb-backed mmap slots, mirroring the SysV-shm
		 * branch's SHM_HUGETLB guard further below.  The mmap slow
		 * path upgrades the whole mapping (mp_len = map->size),
		 * which is hugepage-aligned for a freshly-created hugetlb
		 * VMA -- but an mremap or partial-munmap that shrank
		 * map->size to a non-hugepage-aligned extent makes the
		 * kernel's hugetlb_change_protection reject the mprotect
		 * with -EINVAL, and the retry pool churns on the slot every
		 * pick.  Hugetlb mmap slots stay in the pool for the mmap /
		 * munmap / mremap sanitisers that legitimately want a
		 * hugetlb VMA to fuzz.
		 */
		if (map->flags & MAP_HUGETLB)
			goto retry;
		if (map->size < size)
			goto retry;

		/*
		 * Cheap defense-in-depth NULL re-check before we copy out
		 * map->ptr and fall through to the mprotect() below.  The
		 * OBJ_MMAP_* pools are per-child private heap, so there is
		 * no concurrent destroyer that could recycle the slot under
		 * us; this just catches the handle being clobbered across
		 * the prot/size reads above.  It is a plain NULL check --
		 * no counters are bumped here.
		 */
		if (!validate_map_handle(&h))
			goto retry;

		addr = map->ptr;
	} else {
		unsigned int captured_slot;

		from_mmap = false;
		obj = get_random_object(OBJ_SYSV_SHM, OBJ_GLOBAL);
		if (obj == NULL)
			goto retry;
		/*
		 * Defend the obj-field reads below against the same
		 * slot-recycle race fds/sockets.c:684-712 closes one level
		 * upstream.  get_random_object()'s array-generation gate
		 * already drops a pick whose head->array snapshot raced a
		 * grow / teardown, so this captured stamp covers the
		 * remaining post-pick window: between get_random_object()
		 * returning and obj->sysv_shm.ptr being copied out below,
		 * __destroy_object() could swap-with-last over this slot and
		 * release_obj() the chunk into the deferred-free TTL.  A
		 * captured pre-deref slot_version that no longer matches
		 * after the IPC_STAT probe is the same "stale slot" signal
		 * sockets.c uses, applied to the SysV-SHM hot path that
		 * turns the stale read into a writable kernel-bound pointer.
		 */
		if (!objpool_check(obj, OBJ_SYSV_SHM))
			goto retry;
		captured_slot = obj->slot_version;
		/*
		 * Skip hugetlb-backed slots.  get_writable_address callers
		 * ask for sub-hugepage sizes (struct sizes, single
		 * integers); the kernel's hugetlb_change_protection rejects
		 * mprotect ranges whose end is not a multiple of the VMA's
		 * hugepage size, so PAGE_ALIGN(size) EINVALs for any
		 * reasonable size.  The slot stays in the pool for the
		 * shmctl/shmat/shmdt sanitisers that legitimately want a
		 * hugetlb segment to fuzz.
		 */
		if (obj->sysv_shm.flags & SHM_HUGETLB)
			goto retry;
		if (obj->sysv_shm.size < size)
			goto retry;
		/*
		 * The pool slot was valid when populated, but a sibling
		 * shmctl(IPC_RMID) may have flipped the segment to the
		 * SHM_DEST/zombie state in the meantime.  Touching the
		 * cached ptr after that SIGSEGVs/SIGBUSes the consumer.
		 * Probe the segment with IPC_STAT and retry the slot if
		 * the lookup fails or the destroy bit is set.
		 */
		{
			struct shmid_ds buf;
			if (shmctl(obj->sysv_shm.id, IPC_STAT, &buf) != 0)
				goto retry;
			if (buf.shm_perm.mode & SHM_DEST)
				goto retry;
		}
		/*
		 * Final post-deref re-check: if the slot was destroyed and
		 * the chunk recycled (or rewritten by add_object's swap-
		 * with-last under this index) between get_random_object()
		 * and now, slot_version has been incremented past our
		 * snapshot and obj->sysv_shm reads above were against stale
		 * bytes.  Drop the pick rather than handing the caller a
		 * pointer derived from a destroyed slot.
		 */
		if (!object_slot_alive(obj, captured_slot))
			goto retry;
		addr = obj->sysv_shm.ptr;
		/*
		 * The OBJ_SYSV_SHM branch lacks the OBJ_MMAP branch's
		 * range_overlaps_shared(map, sizeof(*map)) scribble check,
		 * so a scribble that replaced obj->sysv_shm.ptr with a
		 * heap-shaped value sails past the IPC_STAT check above
		 * (the shm segment id is fine; only the cached attached-
		 * ptr is stale).  Reject early before the mprotect below
		 * touches a region that doesn't belong to any tracked
		 * mapping.
		 */
		if (!range_in_tracked_shared((unsigned long) addr,
					     (unsigned long) size)) {
			struct childdata *c = this_child();

			if (c != NULL && c->stats_ring != NULL) {
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_GET_WRITABLE_SCRIBBLED_SHM_RANGE,
						   0, 1);
				c->local_scribbled_slots_caught++;
			} else {
				parent_stats.get_writable_address_scribbled_shm_range++;
			}
			goto retry;
		}
	}

	/*
	 * Upgrade exactly [addr, addr+size) to PROT_READ|PROT_WRITE.
	 * mprotect's all-or-nothing semantics give us the contract we
	 * need: it returns -ENOMEM if any page in the range is not in a
	 * VMA, so a successful return GUARANTEES the full requested size
	 * is contiguous, mapped and writable.  Callers that need a buffer
	 * of @size bytes can rely on that extent without a separate
	 * page-by-page residency probe.
	 *
	 * This used to skip the syscall on a known_rw cache hit and
	 * upgrade the WHOLE mapping on the slow path so the cache could
	 * vouch for any later size <= map->size.  A wide sibling munmap
	 * or MAP_FIXED placement that collaterally tore down THIS slot's
	 * tail pages without firing the per-slot notifier left the cache
	 * lying about pages 2..N of a multi-page slot; the head-page
	 * mincore() probe below couldn't see past page 0, so the caller
	 * (alloc_iovec asking for 16 KB) walked off the writable extent
	 * into a torn-down / PROT_NONE neighbour and SEGV_ACCERR'd.
	 * Always running mprotect over the requested extent makes the
	 * contract the kernel's responsibility instead of a shadow bit.
	 */
	{
		void *mp_addr = addr;
		size_t mp_len = size;

#ifdef CONFIG_GUARD_SHARED
	/*
	 * Investigation hook: get_writable_address upgrades the picked
	 * pool slot to PROT_READ|PROT_WRITE, but a scribbled slot that
	 * aliased onto a registered kcov buffer would mprotect that
	 * buffer instead.  PROT_READ|PROT_WRITE is the requested prot
	 * here, so an overlap warning surfaces the alias before the
	 * syscall fires -- the spec calls this site out as a distinct
	 * mechanism for the trace_buf protection-strip class.
	 */
	internal_mprotect_audit_kcov("get_writable_address",
		(unsigned long)mp_addr, (unsigned long)mp_len,
		PROT_READ | PROT_WRITE);
#endif

	if (mprotect(mp_addr, mp_len, PROT_READ | PROT_WRITE) != 0) {
		log_mprotect_failure(mp_addr, mp_len,
				     PROT_READ | PROT_WRITE,
				     __builtin_return_address(0), errno);
		/*
		 * mprotect failed -- the slot's stored ptr is almost
		 * certainly scribbled (real alloc_shared / SysV shm
		 * mappings stay PROT_READ|PROT_WRITE for their full
		 * lifetime, so an upgrade-to-RW that returns -1 is the
		 * fingerprint of a stale or fabricated pointer).
		 * Returning addr regardless gives the caller a value
		 * that SEGV_ACCERRs on first dereference; retrying
		 * picks a different slot and rolls past the bad one.
		 * ENOMEM here also covers the "sibling tore down tail
		 * pages of a multi-page slot" case the dropped cache
		 * used to silently miss.
		 */
		{
			struct childdata *c = this_child();
			enum stats_field field = from_mmap
				? STATS_FIELD_GET_WRITABLE_SCRIBBLED_MPROTECT_MMAP
				: STATS_FIELD_GET_WRITABLE_SCRIBBLED_MPROTECT_SHM;

			if (c != NULL && c->stats_ring != NULL) {
				stats_ring_enqueue(c->stats_ring,
						   field,
						   0, 1);
				c->local_scribbled_slots_caught++;
			} else {
				if (from_mmap)
					parent_stats.get_writable_address_scribbled_mprotect_mmap++;
				else
					parent_stats.get_writable_address_scribbled_mprotect_shm++;
			}
		}
		goto retry;
	}
	}

	/*
	 * mprotect succeeded on the requested extent.  On the mmap branch
	 * bring the tracked prot in line with what the kernel just applied
	 * so get_map_with_prot() picks see the upgrade.  We only OR in
	 * the bits we know we added -- the cached invariant for any other
	 * bits (PROT_EXEC, PROT_NONE clearance) is owned by the post-
	 * syscall hooks.
	 */
	if (from_mmap) {
		/* See sigsetjmp install at retry: -- a fuzzed PROT_READ overlay
		 * on the brk page hosting map turns this store into
		 * SEGV_ACCERR.  Companion commit widened the brk re-test gate
		 * to close the upstream window; this wrap is the trip-wire if
		 * a case still slips through. */
		gwa_bookkeeping_active = 1;
		map->prot |= PROT_READ | PROT_WRITE;
		gwa_bookkeeping_active = 0;
	}

	/*
	 * Defense: even when mprotect succeeded, validate addr lives in
	 * a mapping the child legitimately owns.  A scribbled slot can
	 * hold a heap-shaped userspace address whose pages are already RW
	 * (libc heap, a stack page, another mmap'd region we don't own)
	 * -- mprotect succeeds as a no-op upgrade and we'd hand back a
	 * pointer that doesn't belong to any trinity-owned mapping.  The
	 * next sanitiser dereference scribbles glibc bookkeeping or some
	 * unrelated mapping, surfacing far from the scribble origin.
	 *
	 * Two acceptance paths because trinity owns mappings in two
	 * distinct registries:
	 *
	 *   - range_in_tracked_shared(): the global shared_regions[]
	 *     tracker.  Holds startup mappings (setup_initial_mappings),
	 *     kcov trace buffers, child-data, the obj/str heaps -- the
	 *     bookkeeping range_overlaps_shared() defends from fuzzed
	 *     kernel writes.  INITIAL_ANON entries in the OBJ_LOCAL pool
	 *     alias these and pass here.
	 *
	 *   - addr_in_local_runtime_map(): runtime mmap() results seeded
	 *     into the per-child OBJ_LOCAL pool by post_mmap().  These are
	 *     not in shared_regions[] (no need -- they belong to one child
	 *     and there is no bookkeeping to protect).  Previously the
	 *     tracked-shared gate dropped every runtime mapping as if it
	 *     were a scribbled slot, reducing writable-buffer diversity
	 *     for sanitisers and inflating the scribbled diagnostic.
	 *
	 * The retry loop's tries==100 cap keeps a mostly-scribbled pool
	 * from spinning forever.
	 */
	if (!range_in_tracked_shared((unsigned long) addr,
				     (unsigned long) size) &&
	    !addr_in_local_runtime_map((unsigned long) addr,
				       (unsigned long) size)) {
		struct childdata *c = this_child();
		enum stats_field field = from_mmap
			? STATS_FIELD_GET_WRITABLE_SCRIBBLED_POSTMP_MMAP
			: STATS_FIELD_GET_WRITABLE_SCRIBBLED_POSTMP_SHM;

		if (c != NULL && c->stats_ring != NULL) {
			stats_ring_enqueue(c->stats_ring,
					   field,
					   0, 1);
			c->local_scribbled_slots_caught++;
		} else {
			if (from_mmap)
				parent_stats.get_writable_address_scribbled_postmp_mmap++;
			else
				parent_stats.get_writable_address_scribbled_postmp_shm++;
		}
		goto retry;
	}

	/*
	 * Residual head-page residency probe.  The all-or-nothing mprotect
	 * above already established that [addr, addr+size) is in a VMA at
	 * the moment of the syscall, so under normal operation this probe
	 * is redundant on both branches.  It survives as a thin TOCTOU
	 * trip-wire for the narrow window between the mprotect return and
	 * this function's return: a sibling sanitiser issuing a raw
	 * syscall(2) munmap on this exact slot in that window leaves no
	 * tracked-state breadcrumb to invalidate, but mincore() on the
	 * head page sees the VMA has gone away (-ENOMEM) and we can
	 * re-pick before handing the caller a pointer that SEGV_MAPERRs
	 * on first store.  EAGAIN/EFAULT/EINVAL etc. fall through; only
	 * ENOMEM is actionable.  Retries are bounded separately from the
	 * outer tries cap so a transient pool-wide unmap storm doesn't
	 * spin.  Once exhausted, honour the NULL-or-valid contract.
	 */
	{
		unsigned char vec;
		void *probe_addr = (void *)((uintptr_t) addr & PAGE_MASK);

		if (mincore(probe_addr, 1, &vec) != 0 && errno == ENOMEM) {
			mincore_retries++;
			if (mincore_retries < 4)
				goto retry;
			{
				struct childdata *c = this_child();

				if (c != NULL && c->stats_ring != NULL) {
					stats_ring_enqueue(c->stats_ring,
							   STATS_FIELD_GET_WRITABLE_ENOMEM_EXHAUSTED,
							   0, 1);
				} else {
					parent_stats.get_writable_address_enomem_exhausted++;
				}
			}
			outputerr("get_writable_address: page residency probe "
				  "exhausted after %d ENOMEM retries — returning "
				  "NULL\n",
				  mincore_retries);
			return NULL;
		}
	}

	return addr;
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

struct iovec * alloc_iovec(unsigned int num, enum iov_direction dir)
{
	struct iovec *iov;
	unsigned int i;

	/*
	 * num == 0 is a legal bucket from handle_arg_iovec (the iov_iter
	 * "no segments" arm).  zmalloc_tracked(0) glibc behaviour varies
	 * by implementation; sidestep by returning NULL.  Both downstream
	 * walkers -- scrub_iovec_for_kernel_write() and the deferred-free
	 * path -- are already NULL-safe (see the early returns at
	 * random-address.c:487 and the io_uring_register post-handler).
	 */
	if (num == 0)
		return NULL;

	/*
	 * Back the iovec array with a writable-pool slot rather than a
	 * libc-heap zmalloc.  The preceding oversize-to-UIO_MAXIOV commit
	 * bounds the sibling-scribble heap-overflow at the chunk edge,
	 * but a scribble of the count field above UIO_MAXIOV still lets
	 * the kernel's iov walk read past the allocation on the paths
	 * that load M into the kernel iov_iter before checking the
	 * UIO_MAXIOV cap.  Move the structural defense one step further:
	 * take the iov array off the libc arena entirely.
	 *
	 * get_writable_address(UIO_MAXIOV * sizeof(struct iovec)) hands
	 * back a 16 KB mmap-backed slot whose neighbours are other pool
	 * slots, not glibc arena metadata, so an arbitrary-size kernel
	 * iov walk past num cannot read libc free-list chunk metadata as
	 * (iov_base, iov_len) pairs.  For IOV_KERNEL_WRITE callers the
	 * phantom-pointer write target falls out of the arena that
	 * glibc's corruption detector watches; for IOV_KERNEL_READ
	 * callers the read target is bounded to pool pages.  Pool
	 * allocations are also never released by trinity, so a kernel
	 * scribble of an iov_base entry to a within-pool offset can no
	 * longer turn into a free() abort either.
	 *
	 * process_madvise's MADV_PAGEOUT / MADV_COLLAPSE phantom-target
	 * scenario (process_madvise.c:24-37) collapses with this: the
	 * iov walk past sanitise-time num reads zeroed pool bytes, and
	 * NULL iov_base + 0 iov_len pairs apply no advice.
	 *
	 * Return NULL on pool exhaustion -- generate-args.c hands NULL
	 * to the kernel as a NULL iov pointer (EFAULT), the recv/send
	 * sanitisers drop msg_iov / msg_iovlen to NULL / 0, and
	 * io_uring_register's BUFFERS arm lets the kernel EFAULT past
	 * io_sqe_buffers_register's user-pointer copy.  Pool slots are
	 * never freed: drop the matching cleanup wiring at the ARG_IOVEC
	 * / ARG_IOVEC_IN argtype-table entries and remove the per-caller
	 * tracked_free_now / deferred_free_enqueue handoffs in the same
	 * commit so no caller hands a pool address to free().
	 */
	iov = get_writable_address(UIO_MAXIOV * sizeof(struct iovec));
	if (iov == NULL)
		return NULL;

	/*
	 * The slot holds exactly UIO_MAXIOV entries.  generate-args hands
	 * num == UIO_MAXIOV + 1 to exercise the kernel's oversized-iovcnt
	 * EINVAL arm; that count reaches the syscall via publish_paired_
	 * length(), so cap the fill here -- writing iov[UIO_MAXIOV] runs off
	 * the slot into the adjacent unwritable pool page (SEGV_ACCERR at the
	 * page boundary).
	 */
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
