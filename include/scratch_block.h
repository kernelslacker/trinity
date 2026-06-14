#pragma once

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
 * The pool is the only block-fd source childops are allowed to draw.
 * Helpers below let migrated childops pull a vetted loop number or fd
 * without re-reading the shm layout; both return -1 when the pool is
 * empty (mnt_ready false, /dev/loop-control unavailable, or every
 * loop allocation failed), and consumers must treat that as "no
 * scratch loop -- fall back to today's per-child tmpfs/ramfs path".
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
 * Return the loop_num field of a random pool entry whose loop_num is
 * >= 0 (i.e. ignore tmpfs-only slots), or -1 if no such entry exists.
 * Safe to call from any process; reads shm->isolation atomically.
 */
int scratch_block_random_loop_num(void);
