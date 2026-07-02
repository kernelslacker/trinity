#pragma once

/*
 * Internal header for the args/ cluster.  Holds prototypes and shared
 * constants for helpers that cross cluster boundaries within the
 * generate-args carve but are not part of the public argtype-ops /
 * sanitise API.
 *
 * The public API lives in include/argtype-ops.h, include/sanitise.h,
 * and include/arg-len-semantics.h; anything callers outside args/
 * need continues to be declared there.  This header is private to the
 * args/ subdirectory and the generate-args driver.
 */

#include <stdbool.h>
#include <stdint.h>

#include "cmp_hints.h"		/* enum cmp_hint_callsite */
#include "syscall.h"		/* struct syscallentry, struct syscallrecord, enum argtype */
