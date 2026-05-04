#pragma once

#include "arch.h"
#include "syscall.h"

/*
 * Per-bit input-significance map (the "effector map").
 *
 * For each (syscall, arg slot, bit position), a one-byte score in [0, 255]
 * estimating how much that single bit's value influences kernel control
 * flow.  Calibrated once via --effector-map by toggling each bit on top of
 * a freshly-generated baseline argument vector and measuring the resulting
 * KCOV trace divergence; consumed by mutators at fuzz time to bias bit
 * selection toward bits the kernel actually branches on.
 *
 * Indexed as [syscall_nr][arg_slot][bit_index]:
 *   - syscall_nr in [0, MAX_NR_SYSCALL): trinity table index, same key
 *     used by kcov_shm->per_syscall_*.  On x86_64 this equals the raw
 *     kernel syscall number; on architectures with SYSCALL_OFFSET != 0
 *     the table index is offset from the kernel number.
 *   - arg_slot in [0, EFFECTOR_NR_ARGS): argnum - 1.
 *   - bit_index in [0, EFFECTOR_BITS_PER_ARG): bit position from LSB.
 *
 * A score of 0 means "no measurable effect" (calibration didn't probe the
 * bit, or the flip produced an indistinguishable trace fingerprint).
 * Higher scores correspond to more KCOV trace bits that diverged when
 * the single bit was toggled, saturated at 255.
 */

#define EFFECTOR_NR_ARGS	6
#define EFFECTOR_BITS_PER_ARG	(sizeof(unsigned long) * 8)

/* One-shot calibration entry point.  Walks the active 64-bit syscall
 * table, generates a fresh baseline arg vector per syscall, and probes
 * EFFECTOR_NR_ARGS * EFFECTOR_BITS_PER_ARG single-bit toggles per
 * syscall against KCOV.  Returns 0 on success, non-zero if KCOV is not
 * available.  Runs in the parent process; expected to be invoked once
 * after init_shm / open_fds / freeze_global_objects, in lieu of the
 * normal fuzz loop.  On success the populated map is persisted via
 * effector_map_save_file() to the path returned by
 * effector_map_default_path(). */
int effector_map_calibrate(void);

/* Persist the in-memory effector map to @path.  Writes via a per-pid
 * .tmp file and renames atomically — same pattern as minicorpus_save_file.
 * Returns true on success, false on any I/O failure. */
bool effector_map_save_file(const char *path);

/* Load a previously-persisted effector map from @path into the in-memory
 * table.  Returns true if the file was loaded; false if missing,
 * truncated, magic/version mismatched, dimensions disagreed with the
 * compiled-in MAX_NR_SYSCALL / EFFECTOR_NR_ARGS / EFFECTOR_BITS_PER_ARG,
 * the kernel utsname differed from the running kernel, or the payload
 * CRC failed.  All failures leave the in-memory map unchanged. */
bool effector_map_load_file(const char *path);

/* Default per-arch effector-map path, parallel to
 * minicorpus_default_path().  Builds and mkdir -p's
 * $XDG_CACHE_HOME/trinity/effector/ (or $HOME/.cache/...).  Returns
 * NULL if no suitable path can be derived.  Returned pointer is owned
 * by a static buffer and remains valid until the next call. */
const char *effector_map_default_path(void);

/* Read-only accessor for the in-memory map.  Returns the saturated
 * significance byte for (nr, arg, bit), or 0 if any index is out of
 * range.  Used by argument mutators to bias bit selection toward
 * effective bits. */
unsigned char effector_map_score(unsigned int nr, unsigned int arg,
		unsigned int bit);

/* Pick a bit index in [0, EFFECTOR_BITS_PER_ARG) weighted by the
 * effector-map row for (nr, arg).  A +1 floor on every bit's weight
 * keeps zero-significance bits in rotation (calibration is noisy; a
 * row that all measured zero degrades cleanly to a uniform pick).
 * Used by mutate_arg's bit-flip case to bias toward bits the kernel
 * actually branches on. */
unsigned int effector_pick_bit(unsigned int nr, unsigned int arg);

/* Pick an array index in [0, n) weighted by per-bit effector-map
 * significance for (nr, arg).  Each entry's weight is 1 + the sum of
 * effector_map_score(nr, arg, b) over bits b set in vals[i] — the
 * same +1 floor effector_pick_bit uses, so an uncalibrated row
 * degrades cleanly to a uniform pick.
 *
 * For childops with hand-rolled curated bitmask arrays whose chosen
 * entry feeds a syscall arg directly: routes the array-index pick
 * through the same per-bit significance signal that drives
 * random_syscall's bit-flip mutator, so flag combinations the kernel
 * branches harder on get more replay weight per invocation.
 *
 * Caps n at EFFECTOR_BITS_PER_ARG to keep the on-stack weights
 * buffer fixed-size; n above the cap and out-of-range (nr, arg) fall
 * back to a uniform pick.  n == 0 returns 0. */
unsigned int effector_pick_array_index(unsigned int nr, unsigned int arg,
		const unsigned long *vals, unsigned int n);

/* Convert a libc __NR_* macro to the trinity table index that the
 * effector_map_score / effector_pick_bit / effector_pick_array_index
 * accessors expect.  No-op on x86_64 (SYSCALL_OFFSET == 0); on archs
 * with a non-zero offset (mips o32/n32/n64) the subtraction folds the
 * raw kernel number back into the table-index space the calibrator
 * indexes the map by. */
#define EFFECTOR_NR(nr)	((unsigned int)((int)(nr) - SYSCALL_OFFSET))
