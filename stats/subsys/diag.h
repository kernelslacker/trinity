#ifndef _TRINITY_STATS_SUBSYS_DIAG_H
#define _TRINITY_STATS_SUBSYS_DIAG_H

/*
 * Diagnostic / canary / corruption-guard residue counters.  These
 * were the last flat scalars in stats_s and share the common shape
 * of "single-signal defense-in-depth counter": each fires when a
 * specific canary / OOB / UAF / TOCTOU guard catches an anomaly.
 * Grouped into one struct so struct stats_s stays a thin table of
 * composed sub-structs; the surrounding struct stats_s composes an
 * instance of struct diag_stats as its "diag" member.
 *
 * Members are NOT semantic siblings -- they document distinct
 * guards.  See the individual bump-site comments for what each
 * counter signals; grouped here for structural reasons only.
 */
struct diag_stats {
	/*
	 * post_mmap clamped new->map.size below the requested length
	 * because the underlying file fd was shorter than
	 * mapping_sizes[i]+offset.  Without the clamp dirty_mapping
	 * (and later get_map() consumers) walk pages past EOF and
	 * SIGBUS with BUS_ADRERR -- a trinity self-bug that burns
	 * the child before it can contribute to coverage.
	 */
	unsigned long mmap_size_clamped;

	/*
	 * sanitise_statmount() bailed before assigning rec->aN
	 * because the csfu mnt_id_req allocation came back NULL.
	 * Without this counter a statmount syscall whose setup
	 * always failed presents as a silently-zero op in the
	 * dispatch histogram -- the syscall path has no other place
	 * to record a pre-syscall abort.  Bumped from
	 * sanitise_statmount; the post handler stays untouched.
	 */
	unsigned long statmount_setup_fail;

	/*
	 * handle_syscall_ret() found rec->_canary !=
	 * REC_CANARY_MAGIC on entry -- the entire syscallrecord was
	 * rewritten between BEFORE and AFTER, including bookkeeping
	 * fields the per-arg snapshot pattern can't shadow.
	 * Distinct from post_handler_corrupt_ptr, which only catches
	 * scribbled rec->aN pointer slots: a wholesale stomp from a
	 * sibling value-result syscall whose buffer aliased the rec
	 * lands here without tripping the snapshot guards.  Bumped
	 * informationally; the child does NOT abort, since the call
	 * has already returned and the mismatched data is past being
	 * trusted anyway.  See pre_crash_ring entry kind
	 * PRE_CRASH_KIND_CANARY for the matching context capture.
	 */
	unsigned long rec_canary_stomped;

	/*
	 * unlock() sampled the lock word pre-release and saw
	 * LOCK_RESERVED_DIRTY(state) non-zero -- the reserved bits
	 * 1..31 carry a stray write from somewhere in the held
	 * window.  Companion to parent_stats.lock_word_scribbled,
	 * which only fires from check_lock()'s periodic walk in main
	 * context.  The walker cannot see scribbles that land +
	 * clear inside a single held window, so without this counter
	 * a transient stomp during the held interval is invisible.
	 * Multi-producer (any child releasing any lock) so it lives
	 * in shm->stats with an atomic RELAXED add-fetch, not in
	 * parent_stats.  unlock() does NOT refuse the release on a
	 * dirty word -- refusing would leave the lock permanently
	 * held and deadlock every waiter; the headline counter is
	 * enough to surface the event.
	 */
	unsigned long lock_held_scribble;

	/*
	 * handle_syscall_ret() observed rec->retval outside the
	 * {0, -1UL} contract on a syscall whose per-call rettype was
	 * RET_ZERO_SUCCESS.  The dispatcher gate fires once per call
	 * and covers every handler advertising that rettype (whether
	 * set statically in syscallentry or overridden per-cmd by a
	 * sanitise hook), so a single chokepoint substitutes for
	 * retval bounds duplicated across the ~85 RET_ZERO_SUCCESS
	 * .post handlers.  Non-zero means a torn or wholesale-
	 * stomped retval slipped past the canary check (different
	 * stomp class -- the canary catches whole-rec rewrites, this
	 * catches an isolated rec->retval scribble).  Distinct bug
	 * class from post_handler_corrupt_ptr (which counts .post
	 * handlers rejecting a pid-shaped pointer in rec->aN): this
	 * is a dispatcher-level rettype-contract violation, no .post
	 * pointer is examined.  rzs_blanket_reject has its own
	 * storage, separate from post_handler_corrupt_ptr, because
	 * sharing would inflate the post_handler_corrupt_ptr
	 * headline ~9x at ~2/s steady-state.
	 */
	unsigned long rzs_blanket_reject;

	/*
	 * handle_syscall_ret() saw reject_corrupt_retfd() flag a
	 * structurally out-of-bound rec->retval on a RET_FD-class
	 * syscall (negative, >= NR_OPEN, or otherwise outside
	 * [0, 1<<20)) BEFORE the success/failure dispatch.  Distinct
	 * from the failures aggregate counter: the latter aggregates
	 * legitimate -1UL returns alongside the coerced corruption
	 * returns, drowning the corruption signal in the noise of
	 * normal failed syscalls (>50% of every fuzz run).  This
	 * counter surfaces only the structurally-corrupt RET_FD
	 * subset, so a quiet window where every failure was a real
	 * -ENOENT/-EBADF/etc still reads as zero corruption -- non-
	 * zero here always means a fabricated fd value reached the
	 * dispatcher.  Sub-attribution by syscall (nr, do32bit)
	 * routes through post_handler_corrupt_ptr_bump's per-handler
	 * ring (already invoked from inside reject_corrupt_retfd()),
	 * so this counter is the headline tally and the per-handler
	 * ring carries the breakdown.
	 */
	unsigned long retfd_blanket_reject;

	/*
	 * handle_syscall_ret() observed a page-aligned, arena-band-
	 * shaped pointer in either an ARG_ADDRESS /
	 * ARG_NON_NULL_ADDRESS slot of rec->aN (..._arg) or in the
	 * rec->post_state tail (..._post_state) that neither
	 * range_in_tracked_shared() nor addr_in_local_runtime_map()
	 * recognised as live.  Distinct bug class from
	 * post_handler_corrupt_ptr, which catches structurally-
	 * broken values (NULL-ish, kernel-VA, misaligned): the
	 * values caught here are structurally valid arena-shaped
	 * pointers whose underlying mapping is gone -- a sibling
	 * munmap landed the page between the syscall returning and
	 * the .post handler about to dereference it, or a sibling
	 * scribbled an arena-shaped value into the slot from outside
	 * the live tracker set.  The is_corrupt_ptr_shape() gate at
	 * include/utils.h:200 cannot distinguish "live arena pointer"
	 * from "stale arena pointer", since the predicate is purely
	 * structural; this counter surfaces the residual STALE class.
	 *
	 * SPLIT into two counters rather than one-with-attribution:
	 * the arg-slot and post_state detection sites have different
	 * stomp vectors (arg slots ride the value-result sibling-
	 * write path, post_state rides the .post handler's snap-
	 * stash convention), and a downstream operator reading the
	 * periodic rate dump benefits from seeing the two rates side
	 * by side instead of having to untangle them from per-PC
	 * attribution.
	 *
	 * Both sites are telemetry-only -- the kernel has already
	 * observed the syscall by the time the probe runs, so post-
	 * dispatch coercion of the slot would just scribble shared
	 * rec state without changing the syscall outcome.  Downstream
	 * consumers must take their own explicit skip path on a
	 * stale slot.
	 */
	unsigned long arena_ptr_stale_caught_arg;
	unsigned long arena_ptr_stale_caught_post_state;

	/*
	 * sanitise_execve() refused to let an execve / execveat fire
	 * because the resolved target inode matched trinity's own
	 * binary -- the path argument was rewritten to a known-bad
	 * value so the kernel returns a clean -ENOENT/-ENOTDIR and
	 * the post handler's argv/envp free walk runs unchanged.
	 * Without this guard a fuzzed pathname that resolves to
	 * /proc/self/exe, /proc/<pid>/exe, the original launch path,
	 * or an inherited fd backed by the trinity binary spawns a
	 * full nested trinity that inherits the parent's cmdline,
	 * cgroup, and namespace state and starts its own child fleet
	 * -- the nested fleets eat the process table fast enough to
	 * trip the parent's fork-retry budget and wedge the main
	 * loop.  Always-on; no CLI knob.  See sanitise_execve() for
	 * the (dev, ino) compare site.
	 */
	unsigned long execve_self_exec_blocked;

	/*
	 * init_child()'s sibling-freeze step issues
	 * mprotect(PROT_READ) on every other child's childdata (and
	 * on the shared pids[] array) so a value-result syscall
	 * buffer in one sibling can't scribble over another sibling's
	 * rec->aN.  Each mprotect can fail with -ENOMEM if the
	 * kernel hits a per-mm VMA-count or address-space limit
	 * while splitting the existing mapping.  A non-zero count
	 * means at least one freeze step silently left a sibling's
	 * childdata (or pids[]) writable -- the cross-child scribble
	 * vector that the post-handler / snapshot guards exist to
	 * defend against is open for that sibling pair.  We don't
	 * abort the child on a single failure (best-effort
	 * hardening), but the counter lets us tell whether the
	 * failure is rare or a real runtime vector.
	 */
	unsigned long sibling_mprotect_failed;

	/*
	 * init_child() bumps shm->sibling_freeze_gen after its
	 * for_each_child mprotect loop completes; each child
	 * re-checks the gen at the top of its child_process loop
	 * and, on mismatch, re-runs the mprotect sweep to pull any
	 * newly-spawned sibling into PROT_READ.  This counter ticks
	 * once per refreeze.  Expected pattern: a burst at startup
	 * (max_children-1 refreezes per child as the fleet fills
	 * in), then occasional bumps as replace_child() respawns
	 * dead slots.  A runaway count (e.g. tens of refreezes per
	 * second long after startup) would indicate constant child
	 * churn -- useful signal when paired with reaper / SEGV
	 * stats.
	 */
	unsigned long sibling_refreeze_count;

	/*
	 * sanitise_io_uring_enter bailed out because the kernel-
	 * shared SQ ring mask read back larger than ring->sq_entries
	 * -- a sibling op had stomped the mask, which would have
	 * steered fill_sqe past the SQE array and faulted on an
	 * unmapped page.
	 */
	unsigned long iouring_enter_mask_corrupt;

	/*
	 * Bumped by prop_ring_push_scalar() each time a typed scalar
	 * return (currently OBJ_KEY_SERIAL from
	 * register_returned_fd's add_key / keyctl path) was
	 * successfully mirrored into the per-child propagation ring
	 * after its own typed registrar accepted it.  Reads as "key
	 * serials made available to untyped consumers via the
	 * prop_ring path" -- distinct from
	 * kcov_shm->hints_flat.propagation_injected, which counts
	 * the consumer-side draws from the ring; this is the
	 * producer-side capture count for the bypass-the-OBJ_NONE-
	 * firewall push variant.  Skipped pushes (dedup against most
	 * recent slot, pointer-shape or fd-alias rejections, out-of-
	 * range) do NOT bump this -- the counter tracks
	 * publications, not call-attempts.
	 */
	unsigned long propagation_injected_key_scalar;

	/*
	 * alloc_shared() / track_shared_region() ran with
	 * nr_shared_regions == MAX_SHARED_ALLOCS and parked the new
	 * region in the bounded overflow tail.  Non-zero means the
	 * static cap is demonstrably undersized -- consult this
	 * counter (not a guess) when deciding whether to raise
	 * MAX_SHARED_ALLOCS or move shared_regions[] to a dynamic
	 * registry.  Untracked-and-silent is no longer an option:
	 * range_overlaps_shared() relies on the bitmap, which the
	 * overflow path still sets, but a tail-exhaust BUG()s rather
	 * than under-protect.
	 */
	unsigned long shared_region_overflow;

	/*
	 * stats_ring_drain_all() found a child->stats_ring pointer
	 * that failed the canonical-address / minimum-address sanity
	 * check.  Same defense-in-depth role as
	 * fd_event_ring_corrupted.
	 */
	unsigned long stats_ring_corrupted;

	/*
	 * stats_ring_drain_all() found a live child->stats_ring that
	 * differed from the canary copy taken at init time.
	 * Indicates the pointer was overwritten after init.
	 */
	unsigned long stats_ring_overwritten;

	/*
	 * __destroy_object() rejected an obj whose array_idx didn't
	 * pass the head->array[array_idx] == obj invariant -- either
	 * the index was out of bounds for the pool, or the slot held
	 * a different pointer.  Both shapes mean the obj's array_idx
	 * is stale or corrupted; following the swap-with-last would
	 * either OOB-write past head->array[num_entries) or destroy
	 * the unrelated object occupying that slot.  The destroy is
	 * dropped (no free, no destructor) and counted here.
	 */
	unsigned long destroy_object_idx_corrupt;

	/*
	 * Bumped by objpool_check() on the bad-VA and wrong-type-
	 * tag rejection paths -- i.e. the picker resolved a slot to
	 * an address that lies outside the user/heap VA window, or
	 * whose obj_type does not match the type the caller asked
	 * for.  Both shapes mean the consumer caught a wild or
	 * recycled obj pointer (release_obj() zeroes the chunk, and
	 * the deferred-free allocator can hand it back under the
	 * lockless reader) before dereferencing it.  The
	 * NULL/empty-pool path is not counted here.
	 */
	unsigned long global_obj_uaf_caught;

	/*
	 * Bumped by childops/mm/pagecache-canary-check.c when a
	 * verifier read returned a byte that did not match the
	 * deterministic canary_expected_byte() pattern.  A non-zero
	 * counter here means a kernel code path mutated a canary
	 * file's contents mid-run via a route that bypassed the
	 * file's normal write-side validation -- the bug class the
	 * oracle exists to catch.  Each bump corresponds to one
	 * verifier invocation that found a divergence (the verifier
	 * logs offset+expected/actual windows and continues, so
	 * multiple invocations against the same corrupted file each
	 * contribute one bump).
	 */
	unsigned long pagecache_canary_corrupt_caught;

	/*
	 * objhead_indexed_read() rejected a pick whose array
	 * snapshot either failed the cheap stateless provenance
	 * check on the captured head->array pointer, or whose
	 * post-load re-read of head->array_generation no longer
	 * matched the value sampled at pick time.  The first case is
	 * wild-pointer noise (early-init or a scribbled head->array);
	 * the second case is the racy-grow / teardown the field
	 * exists to detect -- an indexed read off a container the
	 * deferred-free TTL has handed back to glibc.  Non-zero here
	 * means the array-generation gate caught the same UAF class
	 * the 0117 ASAN run flagged at get_random_object()'s
	 * head->array[idx] load.
	 */
	unsigned long objpool_array_stale_caught;

	/*
	 * Per-call abort counter for random_map_readfn().  Bumped
	 * each time the per-page memcpy in one of the read walks
	 * (read_one_page, read_whole_mapping, read_every_other_page,
	 * read_mapping_reverse, read_random_pages, read_last_page)
	 * takes a SIGBUS or SIGSEGV inside the sigsetjmp-guarded
	 * section and the walk siglongjmps out cleanly instead of
	 * killing the child.  Non-zero values surface the live
	 * truncate / hole-punch / MADV_REMOVE race rate against
	 * file-backed mmaps and the sibling-munmap rate against anon
	 * mappings -- both are TOCTOU windows the local-snapshot+
	 * fstat clamp narrows but cannot fully close.
	 */
	unsigned long read_walk_aborted;

	/*
	 * Per-call abort counter for random_map_writefn().  Bumped
	 * each time the per-page user store in one of the write
	 * walks (dirty_one_page, dirty_first_page,
	 * dirty_whole_mapping, dirty_every_other_page,
	 * dirty_mapping_reverse, dirty_random_pages, dirty_last_page)
	 * takes a SIGBUS or SIGSEGV inside the sigsetjmp-guarded
	 * section and the walk siglongjmps out cleanly instead of
	 * killing the child.  The write side already clamps via
	 * dirty_random_mapping (mm/maps-dirty.c) before dispatch, so this
	 * counter primarily reflects the residual sibling
	 * fallocate(PUNCH_HOLE) / fallocate(COLLAPSE_RANGE) /
	 * madvise(MADV_REMOVE) and ftruncate-shrink race rate that
	 * the pre-dispatch fstat cannot catch (st_size unchanged for
	 * hole punch, shrunk between clamp and store for ftruncate).
	 */
	unsigned long write_walk_aborted;

	/*
	 * init_child()'s pid-handshake loop observed
	 * pid_alive(mainpid) == false -- the parent died (or
	 * otherwise lost its pid slot) before publishing this
	 * child's slot in pids[].  The original shape called
	 * outputerr("BUG!: parent went away!") right after the dup2
	 * redirect to /dev/null, so the diagnostic was lost.
	 * Bumping a shm counter survives the operator-side teardown:
	 * any reader that attaches to the still-mapped shm
	 * post-mortem sees a non-zero value here and knows the
	 * parent-loss path actually fired, distinct from a child
	 * that exited for any other reason.  Cumulative across the
	 * run; expected zero on a healthy fleet.
	 */
	unsigned long child_dead_parent_observed;

	/*
	 * heap_bounds_init() encountered an [anon:NAME] allocator
	 * region after extra_heap_regions[] already held
	 * MAX_EXTRA_HEAP_REGIONS entries, so the region was silently
	 * dropped instead of being captured.  is_in_glibc_heap() and
	 * range_overlaps_libc_heap() will not consider that
	 * allocator region, which can let a fuzzed pointer land
	 * inside it and let the kernel scribble allocator metadata
	 * (the bad-free / asan-self-kill cluster the captured
	 * regions exist to prevent).  The existing one-shot warned-
	 * bool outputerr fires for the first overflow only; this
	 * counter advances for every subsequent dropped region so
	 * the deficit size, not just the existence of a deficit, is
	 * observable post-mortem.  A non-zero value across runs is
	 * the actionable signal to raise MAX_EXTRA_HEAP_REGIONS or
	 * replace the static array with a growable registry.
	 */
	unsigned long heap_extra_regions_overflow;

	/*
	 * mseal_transition_matrix oracle counters.
	 *
	 * mseal_content_oracle_fail -- a per-page canary byte check
	 * detected content corruption after an mseal(2)-prohibited
	 * operation (munmap / MAP_FIXED / mprotect / mremap /
	 * remap_file_pages / destructive madvise) was attempted against
	 * a sealed VMA.  A non-zero value means either the prohibited
	 * operation silently mutated memory it should have rejected, or
	 * an unsealed mprotect spilled the sealed attribute across the
	 * VMA boundary.  The childop also emits an output(0,...) line
	 * for each incident.
	 *
	 * mseal_unexpected_success -- a prohibited operation returned 0
	 * when mseal(2) should have caused it to return EACCES.  A
	 * non-zero value is a direct mseal regression signal.
	 */
	unsigned long mseal_content_oracle_fail;
	unsigned long mseal_unexpected_success;
};

#endif	/* _TRINITY_STATS_SUBSYS_DIAG_H */
