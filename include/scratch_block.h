#pragma once

#include "kernel/fcntl.h"
/*
 * Scratch block-device pool.
 *
 * The pool is built by fds/scratch_block.c during open_fds() when the
 * parent has already entered its private mount namespace (i.e. once
 * setup_startup_isolation() has latched shm->isolation.mnt_ready).
 * Each entry describes one writable scratch slot: a loop-backed ext4
 * image (loop_num >= 0, loop_fd held by the parent) or a plain tmpfs
 * (loop_num == -1, loop_fd == -1).  Children inherit loop_fd via
 * fork(); the parent's fd outlives any child close so the loop binding
 * stays alive for the run.
 *
 * The provider hands out the loop fds, and the btrfs and loop ioctl
 * groups match the fd they were handed against the published entries.
 */

/*
 * Hard upper bound on pool entries.  Day-1 fills two: one ext4 image
 * over a kernel-allocated loop number and one tmpfs.  Headroom for the
 * btrfs/xfs/vfat follow-ups without re-touching shm layout.
 */
#define SCRATCH_BLOCK_MAX 4

struct scratch_block_entry {
	/*
	 * /dev/loopN number obtained from LOOP_CTL_GET_FREE.  -1 marks
	 * a tmpfs slot (no backing loop).  Stable for the entry's
	 * lifetime; the parent keeps the loop alive until atexit
	 * teardown.
	 */
	int loop_num;
	/*
	 * Parent-opened loop fd (O_RDWR | O_CLOEXEC) for entries with
	 * loop_num >= 0; -1 for tmpfs.  Inherited by every child via
	 * fork() so the provider's .get() returns the same fd in any
	 * process.  Children should not close this fd via fuzz syscalls
	 * (it lives in the protected-fd registry only insofar as a
	 * fuzzed close drops the child's own ref -- the parent's
	 * reference keeps the loop binding live).
	 */
	int loop_fd;
	/* "/dev/loopN" string, empty for tmpfs. */
	char dev_path[32];
	/*
	 * Absolute mount path under the scratch subtree, empty when
	 * mkfs.ext4 was absent or mount() failed and we publish a
	 * loop-only entry (no filesystem).
	 */
	char mount_path[96];
	/* "ext4", "tmpfs", or "none" (loop without a filesystem). */
	char fs_type[8];
};

/*
 * Load shm->isolation.scratch_block_count clamped to SCRATCH_BLOCK_MAX.
 * The publisher bounds every increment to SCRATCH_BLOCK_MAX, so a
 * value beyond the cap is a stomped shm counter; clamping here keeps
 * subsequent scratch_block[] pool walks (loops and modulo indexing)
 * inside the fixed-size array instead of running off its end.
 */
unsigned int load_scratch_block_count(void);
