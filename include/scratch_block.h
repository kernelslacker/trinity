#pragma once

#include "kernel/fcntl.h"
/*
 * Scratch block-device pool.
 *
 * The pool is built by fds/scratch_block.c during open_fds() when the
 * parent has already entered its private mount namespace (i.e. once
 * setup_startup_isolation() has latched shm->isolation.mnt_ready).
 * Each entry describes one loop-backed scratch image (loop_num >= 0,
 * loop_fd held by the parent), formatted ext4 and mounted when mkfs.ext4
 * and the mount work.  Children inherit loop_fd via fork(); the
 * parent's fd outlives any child close so the loop binding stays alive
 * for the run.
 *
 * The provider hands out the loop fds, which the loop ioctl group
 * matches against the published entries.
 */

/*
 * Hard upper bound on pool entries.  The provider fills one, an ext4
 * image over a kernel-allocated loop number; the rest is headroom for
 * more without re-touching shm layout.
 */
#define SCRATCH_BLOCK_MAX 4

struct scratch_block_entry {
	/*
	 * /dev/loopN number obtained from LOOP_CTL_GET_FREE, -1 in an
	 * unused slot.  Stable for the entry's lifetime; the parent
	 * keeps the loop alive until atexit teardown.
	 */
	int loop_num;
	/*
	 * Parent-opened loop fd (O_RDWR | O_CLOEXEC) for entries with
	 * loop_num >= 0; -1 in an unused slot.  Inherited by every child via
	 * fork() so the provider's .get() returns the same fd in any
	 * process.  Children should not close this fd via fuzz syscalls
	 * (it lives in the protected-fd registry only insofar as a
	 * fuzzed close drops the child's own ref -- the parent's
	 * reference keeps the loop binding live).
	 */
	int loop_fd;
	/* "/dev/loopN" string, empty in an unused slot. */
	char dev_path[32];
	/*
	 * Absolute mount path under the scratch subtree, empty when
	 * mkfs.ext4 was absent or mount() failed and we publish a
	 * loop-only entry (no filesystem).
	 */
	char mount_path[96];
};
