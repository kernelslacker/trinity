#ifndef _TRINITY_STATS_SUBSYS_DEFERRED_FREE_H
#define _TRINITY_STATS_SUBSYS_DEFERRED_FREE_H

/*
 * Per-rejection-reason sub-attributions of deferred_free_enqueue()
 * in deferred-free.c.  The function has five distinct early-return
 * rejection clauses; each of the first five counters below is bumped
 * once per call that exits via the corresponding clause.
 * Complementary to (does not replace):
 *   - parent_stats.deferred_free_reject{,_pathname,_iovec,...}, which
 *     attribute the corrupt-shape branch by post-handler argtype.
 *   - parent_stats.snapshot_non_heap_reject, the parent/child shard
 *     mechanism for the non-heap branch.
 *   - the per-PC ring fed by deferred_free_reject_bump(), which
 *     attributes the corrupt-shape and untracked branches by caller.
 * What this block adds: a single shm->stats five-way split that
 * makes the per-branch firing rate trivially comparable.  Lets
 * residual-cores triage attribute observed reject windows (e.g. the
 * 14/8/8-per-window seen at objects/registry.c add_object oldarray
 * enqueue in run 1828) to a specific clause, and validates the
 * alloc_track LRU widen post-rebuild by tracking the untracked
 * branch's rate-of-change on the next live run.  Pure
 * instrumentation -- no behaviour change.
 *
 * Members: the rejection-clause block (reject_*), the four post-state
 * release contract rejects, the VMA-pressure trio + pre-dispatch leak,
 * the rec-owned overflow, the ring-owned / double-admit / tracked-free-
 * unverified-leak family, ring_evict_leaked, and the three alloc_track
 * refresh guards.  The surrounding struct stats_s composes an instance
 * of struct deferred_free_stats as its "deferred_free" member.
 */
struct deferred_free_stats {
	/* ptr low bits set: ((unsigned long)ptr & 0x7) != 0.  glibc malloc
	 * always returns 8-byte aligned chunks on x86_64, so a low-bits-set
	 * candidate cannot be a real allocation start.  libasan CHECK-fails
	 * on misaligned addresses in its poisoning path before its bad-free
	 * reporter ever runs, so dropping these at the enqueue boundary
	 * preserves the symptom triage path.  See deferred-free.c clause 1. */
	unsigned long reject_misaligned;

	/* is_corrupt_ptr_shape(ptr) hit: pid-scribbled / canonical-out-of-
	 * range / heuristically-bad value reaching the enqueue.  Cluster
	 * 1/2/3 root cause (residual-cores triage 2026-05-02): sibling
	 * value-result syscall scribbles a tid/pid into rec->aN, post
	 * handler arrives here, N syscalls later deferred_free_tick() frees
	 * the pid -> SIGSEGV with si_addr==si_pid.  Complementary to the
	 * per-argtype parent_stats.deferred_free_reject_{pathname,iovec,
	 * sockaddr,other} attribution.  See deferred-free.c clause 2. */
	unsigned long reject_corrupt_shape;

	/* !is_in_glibc_heap(ptr): pointer passed shape heuristic but landed
	 * outside the brk arena cached at init (stack, library mapping,
	 * executable mapping, trinity's own MAP_PRIVATE region).  Cannot be
	 * a real malloc result, so the free() is undefined.  Complementary
	 * to parent_stats.snapshot_non_heap_reject (the parent/child shard
	 * mechanism for this same branch); this counter is the headline
	 * shm->stats sum the per-shard mechanism feeds into.  See
	 * deferred-free.c clause 3. */
	unsigned long reject_non_heap;

	/* !alloc_track_consume(ptr): ground-truth check refused a pointer
	 * that __zmalloc() never produced.  Same alloc_track LRU pressure
	 * class as [[maps_reject_alloc_track_miss]]: shared 256-slot LRU
	 * can rotate out legitimate live entries under fd-pressure
	 * cascades, false-rejecting them here.  Tracking this branch in
	 * isolation is the validation gate for the alloc_track 256->4096 widen:
	 * a successful widen should drive this counter's rate-of-change
	 * down on the next live run.  See deferred-free.c clause 4. */
	unsigned long reject_untracked;

	/* nested-address scrub (scrub_struct_addresses) refused to walk a
	 * struct base whose pointer either fails the stateless shape
	 * predicate (is_corrupt_ptr_shape: NULL-ish, non-canonical, or
	 * misaligned) or falls outside the cached glibc brk arena
	 * (is_in_glibc_heap).  Real zmalloc_tracked() struct slots always
	 * satisfy both; a pointer-shaped-but-invalid value scribbled into
	 * rec->aN (or into a nested FT_PTR_STRUCT/FT_PTR_ARRAY base field)
	 * by a sibling stomp in the publish->snapshot window does not, and
	 * dereferencing it would SEGV the sanitiser before the syscall
	 * fires.  Rate-of-change near zero on a clean run is the
	 * regression check that proves the guard is not false-rejecting
	 * legitimate struct bases.  See generate-args.c
	 * scrub_struct_addresses / nested_address_scrub. */
	unsigned long nested_scrub_reject_untracked;

	/* range_overlaps_shared(ptr, 1): pointer fell inside one of
	 * trinity's own mmap'd shared regions.  ASAN catches these as
	 * bad-free ("attempting free on address which was not malloc()-ed");
	 * non-ASAN runs silently corrupt the glibc allocator.  Root cause
	 * is always an arg generator handing back a tracked-mmap pointer
	 * for an arg slot whose argtype (PATHNAME, IOVEC, SOCKADDR) expects
	 * heap.  See deferred-free.c clause 5. */
	unsigned long reject_shared_region;

	/* post_state_release() rejected snap before deferred_freeptr.  The
	 * four-gate reject contract converts what used to be an
	 * abort-in-libc-free into a structured leak + counter bump.  See
	 * utils.c post_state_release for the gate ordering and rationale;
	 * the symmetric headline class is reject_untracked, which catches
	 * the same shape one layer down (post_state_release forwards a
	 * sanitised pointer into deferred_free_enqueue, so a non-zero
	 * counter here is the FIRST wall; the reject_* family is the SECOND
	 * wall for any reject path that still slips through).
	 *
	 *   _untracked      - snap absent from the ownership table.
	 *   _released       - snap already released by a prior call (the
	 *                     idempotency contract).
	 *   _wrong_owner    - snap is live but tagged to a different
	 *                     (syscall_nr, do32bit) than the caller.
	 *                     Skipped for untagged installers
	 *                     (post_state_register-only call sites).
	 *   _bad_magic      - snap is live and tagged to us but the
	 *                     leading-word cookie no longer matches the
	 *                     install-time magic.  Skipped for untagged
	 *                     installers (magic==0). */
	unsigned long post_state_release_reject_untracked;
	unsigned long post_state_release_reject_released;
	unsigned long post_state_release_reject_wrong_owner;
	unsigned long post_state_release_reject_bad_magic;

	/* deferred-free ring exerts pressure on the per-process VMA budget
	 * (/proc/sys/vm/max_map_count) via the mprotect bracket around its
	 * mmap'd ring page -- under fuzz pressure the bracket's RW flip can
	 * return -ENOMEM when the kernel runs out of VMA slots to split the
	 * surrounding mapping, at which point ring_unlock fails and the
	 * enqueue path can't access the slot.  The trio below surfaces the
	 * bound-and-fallback path that keeps the deferred-free instrumen-
	 * tation from killing a child whose VMA table fills up:
	 *
	 *   _outstanding_vmas: cross-fleet high-water mark of in-ring
	 *     deferred-free entries.  Each entry is one held-back free that
	 *     keeps an allocation (and its glibc-arena chunk) alive past its
	 *     natural lifetime; the conceptual model is one outstanding VMA
	 *     per entry, even though today's ring uses a single mprotect-
	 *     bracketed region rather than per-slot redzone mappings.  CAS
	 *     up-only so transient peaks survive a quieter trailing window.
	 *
	 *   _vma_fallback_immediate: soft-cap rejections -- enqueue saw the
	 *     local in-ring count above max_map_count/2 and routed the ptr
	 *     to immediate free() instead of admitting it.  The current
	 *     ring is bounded at 64 slots so the cap only fires on systems
	 *     with a small max_map_count (or if a future hardening pass
	 *     starts arming per-slot redzones), but tracking it keeps the
	 *     defensive bound observable for that case.
	 *
	 *   _enomem_drain: hard-cap events on the enqueue path -- ring_unlock
	 *     returned -ENOMEM despite the soft cap.  The ring is munmap'd
	 *     (releasing the VMA slot the kernel was short of) and the
	 *     current ptr is freed immediately so the caller's "no longer
	 *     your problem" contract holds; the ring stays NULL for the
	 *     rest of the child's life, so subsequent enqueues fall through
	 *     to plain free().  Non-zero is a real VMA-exhaustion event,
	 *     not a soft warning.
	 *
	 *   _rw_restore_enomem: same shape but on the drain path --
	 *     deferred_free_tick or deferred_free_flush couldn't restore RW
	 *     on the ring page before walking it.  The PROT_NONE page would
	 *     otherwise persist as fault-bait for sibling fuzzed value-
	 *     result syscalls, so the
	 *     drain path also munmap's the ring; the entries currently
	 *     queued are leaked (lost forever from glibc's tracking until
	 *     the child exits).  Cost of those leaks is bounded by the
	 *     64-slot ring; benefit is the page goes away instead of
	 *     thrashing on ENOMEM for the rest of the run. */
	unsigned long outstanding_vmas;
	unsigned long vma_fallback_immediate;
	unsigned long enomem_drain;
	unsigned long rw_restore_enomem;

	/* deferred_free_enqueue_or_leak() pressure path fired -- the
	 * queue refused to admit (VMA soft cap, ring==NULL after a prior
	 * ENOMEM dispose, RING_UNLOCK_ENOMEM, RING_UNLOCK_FAIL, or
	 * occupied_mask-saturated full-ring), and the variant
	 * intentionally LEAKED the ptr instead of falling back to a
	 * synchronous free().  The leak is bounded by the child's
	 * max_map_count and reclaimed at child exit; trinity child
	 * lifetimes are short, so a non-zero rate here is the visible
	 * cost of preserving "pre-dispatch caller does not own this
	 * buffer's lifecycle" against the UAF a sync free would
	 * otherwise cause.
	 *
	 * Bumped alongside the existing _vma_fallback_immediate /
	 * _enomem_drain counters (which keep counting the pressure
	 * EVENT) so operators can compare queue success rate against
	 * leak rate without having to subtract pre-dispatch hits out of
	 * a shared counter.  Companion to the pre-dispatch site
	 * migration (io_uring_setup, openat2, perf_event_open,
	 * landlock_create_ruleset, file/sched/mount/open_tree_attr,
	 * get/setxattrat, mq_open, listmount, statmount). */
	unsigned long pre_dispatch_leaked;

	/* rec_own() found rec->owned[] saturated at REC_OWNED_MAX and
	 * routed the overflowing pointer through deferred_free_enqueue()
	 * as the fallback owner.  The per-rec carrier is sized so this
	 * never fires in practice (heaviest in-tree callers own <= 3
	 * buffers; the bound is 8); a non-zero rate means a caller is
	 * registering more pointers per syscall than the carrier
	 * accommodates, and the fallback re-introduces the very
	 * pre-dispatch ring-enqueue shape the owned list was built to
	 * eliminate.  Treat any non-zero rate as a signal to either raise
	 * REC_OWNED_MAX or audit the offending caller -- the fallback is
	 * a safety net, not a steady-state path. */
	unsigned long rec_owned_overflow_to_ring;

	/* tracked_free_now() found @ptr already pinned in the deferred-
	 * free ring (inflight_hash_contains() == true at entry) and
	 * routed it through the ring-as-sole-owner path: alloc_track
	 * drained, free() skipped, inflight membership left intact so
	 * the TTL/evict path frees the chunk exactly once.  Non-zero
	 * empirically proves the ring-as-sole-owner path is engaged and
	 * the reuse-mediated double-free is closed off: an
	 * inflight_hash_remove() + free() here would let address reuse
	 * re-arm the value-keyed membership bit and
	 * ring_evict_oldest_safe() free the same address a second time.
	 * Rate-of-change is
	 * the headline metric: a count proportional to ring throughput
	 * is normal (any pointer admitted to the ring whose post-handler
	 * cleanup also routes through tracked_free_now() lands here);
	 * zero across a full run means either no such overlap occurs
	 * (suspect the gate isn't engaged) or the workload doesn't
	 * exercise it. */
	unsigned long ring_owned_skip;

	/* deferred_free_enqueue_internal() found @ptr already pinned in
	 * an occupied ring slot at admission time and refused to take a
	 * second slot.  Without this gate, an alloc_track_refresh() that
	 * re-admits a ring-resident @ptr lets the next enqueue pass the
	 * alloc_track_consume() check a second time and admit @ptr to
	 * two ring slots.  The reuse-mediated double-free then runs when
	 * the first slot's TTL fires and free()s @ptr; address reuse
	 * binds the same value to a new chunk; the second slot's TTL
	 * fires and free()s the new owner's chunk.  Non-zero proves the
	 * gate is engaged; rate-of-change correlates with refresh
	 * pressure on the maps.c / objects/ hot paths. */
	unsigned long double_admit_skip;

	/* tracked_free_now() could not verify ring residency because
	 * ring_unlock() returned non-OK (typically ENOMEM under VMA
	 * pressure -- same class as enomem_drain).  The chunk is leaked
	 * rather than freed because freeing without having verified the
	 * ring would risk a double-free against an eviction whose guards
	 * happen to pass.  Bounded by child lifetime; the kernel reclaims
	 * at exit.  Non-zero rate indicates VMA-pressure leaking into the
	 * cleanup path -- correlate with enomem_drain. */
	unsigned long tracked_free_unverified_leak;

	/* ring_evict_oldest_safe() reclaimed a full-ring slot WITHOUT
	 * free()ing the evicted chunk.  Interim defense against the
	 * address-reuse window where a stale caller ref to a freed-and-
	 * reused chunk passes every value-keyed gate (heap-bounds,
	 * shared-region, alloc_track_consume) and eviction free()s a
	 * now-live chunk -- the surviving class of bad-free at the
	 * eviction site.  The durable fix is at the caller-lifecycle
	 * root (drop the retained ref).  This counter only fires when
	 * the ring is full (TTL eviction is rare given the 5-50 TTL
	 * range and per-syscall tick), so the leak is bounded; child
	 * exit reclaims it.  Cannot double-free because the site never
	 * free()s.  The RING_DRAIN / flush + immediate-free fallback
	 * paths intentionally KEEP freeing -- leaking everywhere would
	 * be a whole-ring RSS blowup, not a bounded eviction-only
	 * defense.  Expected to read as zero on a fixed caller chain;
	 * the next ASAN run is the validation gate (ring_evict bad-free
	 * count should drop to zero). */
	unsigned long ring_evict_leaked;

	/* alloc_track_refresh() found @ptr currently pinned in the
	 * deferred ring and skipped both the consume + re-add.  The
	 * ring already owns the chunk's lifecycle; re-admitting a
	 * fresh alloc_track entry for a ring-resident @ptr decouples
	 * that entry's lifetime from the original __zmalloc-time entry
	 * the ring's free-time consume gate relies on, leaving the
	 * address-reuse-then-stale-enqueue path through which eviction
	 * matches a fresh consume entry and free()s a now-live chunk
	 * owned by a different allocation.  Non-zero proves the gate
	 * is engaged on a refresh of a ring-resident ptr; rate-of-
	 * change correlates with the maps.c / objects/ refresh
	 * pressure that previously fed double_admit_skip at the
	 * enqueue dedup. */
	unsigned long alloc_track_refresh_ring_owned_skip;

	/* alloc_track_refresh() could not verify ring residency because
	 * ring_unlock() returned non-OK (typically ENOMEM under VMA
	 * pressure -- same class as enomem_drain).  The refresh is
	 * skipped entirely rather than risk re-adding a ring-resident
	 * @ptr; the only cost is the LRU position -- the original
	 * alloc_track entry is untouched, so a follow-up lookup still
	 * resolves and the entry rotates out per the normal alloc_track[]
	 * aging.  Non-zero rate indicates VMA-pressure leaking into the
	 * refresh path -- correlate with enomem_drain and
	 * tracked_free_unverified_leak. */
	unsigned long alloc_track_refresh_unverified_skip;

	/* alloc_track_refresh() found @ptr was not currently tracked
	 * (alloc_track_consume miss) and bailed without re-inserting.
	 * Two indistinguishable causes: @ptr was a legitimate tracked
	 * allocation that rotated out under churn (the LRU bump is
	 * lost, the next deferred_free_enqueue rejects as untracked
	 * and leaks the chunk), or @ptr was never tracked -- a stale
	 * caller ref, an interior pointer derived from a scribbled
	 * head->array / localobj, or a fuzzed value-result syscall
	 * scribble.  The previous shape called deferred_alloc_track
	 * (@ptr, 0) unconditionally, which blessed the latter class
	 * as tracked and let the next tracked_free_checked() free() it
	 * -- ASAN bad-free at deferred-free.c:880 (free_ring_entry /
	 * ring_evict_oldest_safe / tracked_free_now) on an interior
	 * pointer that consume() approved on the falsely-blessed
	 * re-insert.  Non-zero proves the gate is engaged. */
	unsigned long alloc_track_refresh_consume_miss;
};

#endif	/* _TRINITY_STATS_SUBSYS_DEFERRED_FREE_H */
