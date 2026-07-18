#ifndef _TRINITY_STATS_SUBSYS_HFS_MOUNT_FUZZ_H
#define _TRINITY_STATS_SUBSYS_HFS_MOUNT_FUZZ_H

struct hfs_mount_fuzz_stats {
	/* hfs_mount_fuzz childop counters.  Crafted-image mount fuzzer for
	 * a legacy on-disk filesystem: writes a churned MDB into a memfd,
	 * swaps it onto a scratch_block loop inside a userns_run_in_ns
	 * grandchild, and attempts mount("hfs") with a fuzzed option
	 * string.  Latches CHILDOP_LATCH_UNSUPPORTED on ENODEV
	 * (CONFIG_HFS_FS absent) and CHILDOP_LATCH_NS_UNSUPPORTED on
	 * helper -EPERM, so an operator can spot "kernel can't do it"
	 * runs cheaply. */
	unsigned long runs;			/* total hfs_mount_fuzz invocations */
	unsigned long setup_failed;		/* scratch_block pool empty or memfd build failed */
	unsigned long set_fd_ok;			/* LOOP_SET_FD swapped the loop backing to our memfd */
	unsigned long set_fd_busy;		/* LOOP_SET_FD raced parent-held binding: EBUSY/ENXIO/EPERM */
	unsigned long mount_ok;			/* mount("hfs") returned 0 */
	unsigned long mount_failed;		/* mount("hfs") returned non-zero (usually EINVAL/EIO on garbage) */
	unsigned long ns_unsupported;		/* userns_run_in_ns returned -EPERM — op latched off */
	unsigned long hfs_unsupported;		/* mount() returned ENODEV — CONFIG_HFS_FS absent, op latched off */
};

#endif /* _TRINITY_STATS_SUBSYS_HFS_MOUNT_FUZZ_H */
