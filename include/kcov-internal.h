#pragma once

/*
 * Internal header for the kcov/ cluster.  Holds cross-cluster helper
 * prototypes and extern decls for formerly-static state that had to
 * cross a TU boundary during the kcov.c carve.
 *
 * The public API for kcov lives in include/kcov.h; anything callers
 * outside kcov/ need continues to be declared there.  This header is
 * private to the kcov/ subdirectory and kcov.c itself.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kcov.h"	/* public kcov API */

struct kcov_child;
struct childdata;

/*
 * Cached KASLR base of the running kernel (_text address as reported by
 * /proc/kallsyms).  Zero when the writer could not resolve it, so callers
 * that stamp or compare the value only need the "!= 0" bit to know
 * whether canonicalisation is in effect.  Defined in kcov.c alongside
 * the KASLR lookup helpers; the persist and (later) collection clusters
 * read the value directly so the on-disk header records the same base
 * the hot path canonicalises against.
 */
extern uint64_t kcov_kaslr_base;

/*
 * Record a KCOV PC or remote enable/disable failure into the parent-
 * visible pc_diag / cmp_diag slots.  Lives in kcov/diag.c alongside
 * the other diag helpers; the enable / lifecycle clusters call it
 * from the ioctl error arms so the failure surfaces in the periodic
 * stats dump.  First failure wins for the errno slot; the count slot
 * bumps unconditionally so aggregate failure rates are visible even
 * when everyone hits the same errno.
 */
void kcov_diag_record(int *errno_slot, unsigned int *count_slot, int err);

/*
 * One-shot chronicle latch for the first EBADF ever observed on a
 * PC-enable ioctl.  Lives in kcov/diag.c so the ring-walk helpers
 * that classify which fuzzed syscall plausibly aliased the kcov fd
 * stay next to their diag formatter.  Called from both PC-enable
 * error arms in kcov/enable.c; CAS-from-zero on first_ebadf_op_nr
 * makes the latch fire at most once per run.
 */
void kcov_latch_first_ebadf(struct kcov_child *kc, struct childdata *c);
