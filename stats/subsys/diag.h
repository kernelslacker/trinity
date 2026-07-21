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
	/* mm/maps.c: pick clamped an oversize mmap/mremap request. */
	unsigned long mmap_size_clamped;

	/* statmount cred/mount setup failed before dispatch. */
	unsigned long statmount_setup_fail;

	/* Local-object registry saw num_entries corrupted between publish/consume. */
	unsigned long local_obj_num_entries_corrupted;

	/* rec_canary_check() detected magic-cookie stomp on the syscall rec. */
	unsigned long rec_canary_stomped;

	/* utils/locks.c: caught a scribble on a held lock word. */
	unsigned long lock_held_scribble;

	/* dispatch: rzs / retfd blanket-reject guards rejected the arg. */
	unsigned long rzs_blanket_reject;
	unsigned long retfd_blanket_reject;

	/* Arena-pointer stale-caught guards (arg-gen + post-state). */
	unsigned long arena_ptr_stale_caught_arg;
	unsigned long arena_ptr_stale_caught_post_state;

	/* execve tried to re-exec our own binary; blocked. */
	unsigned long execve_self_exec_blocked;

	/* Sibling-mprotect / re-freeze accounting on the parent side. */
	unsigned long sibling_mprotect_failed;
	unsigned long sibling_refreeze_count;

	/* io_uring_enter mask-corruption guard fired. */
	unsigned long iouring_enter_mask_corrupt;

	/* Object-registry key-scalar propagation ring canary. */
	unsigned long propagation_injected_key_scalar;

	/* Shared-region tracker overflowed MAX_SHARED_ALLOCS. */
	unsigned long shared_region_overflow;

	/* stats-ring integrity guards. */
	unsigned long stats_ring_corrupted;
	unsigned long stats_ring_overwritten;

	/* Object registry destroy-index / global-UAF sentinels. */
	unsigned long destroy_object_idx_corrupt;
	unsigned long global_obj_uaf_caught;

	/* Pagecache canary check + objpool array-stale guard. */
	unsigned long pagecache_canary_corrupt_caught;
	unsigned long objpool_array_stale_caught;

	/* mm/fault-{read,write}.c: per-call SIGBUS/SIGSEGV siglongjmp aborts. */
	unsigned long read_walk_aborted;
	unsigned long write_walk_aborted;

	/* child-init observed the parent already dead before setup completed. */
	unsigned long child_dead_parent_observed;

	/* heap_bounds tracker overflowed heap_extra_regions[]. */
	unsigned long heap_extra_regions_overflow;
};

#endif	/* _TRINITY_STATS_SUBSYS_DIAG_H */
