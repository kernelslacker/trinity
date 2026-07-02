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
