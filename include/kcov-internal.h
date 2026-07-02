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
