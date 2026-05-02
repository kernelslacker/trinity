#pragma once

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
 * normal fuzz loop. */
int effector_map_calibrate(void);
