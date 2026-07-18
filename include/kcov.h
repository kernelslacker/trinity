#pragma once

/* Facade over the split KCOV headers.  Existing consumers include
 * "kcov.h" and continue to see the full public surface -- constants
 * and non-shared types (kcov-types.h), struct kcov_shared and its
 * accessors (kcov-shared.h), and the KCOV lifecycle/collect API
 * (kcov-api.h).  New code that only needs one layer may include
 * the specific sub-header instead. */

#include "kcov-types.h"
#include "kcov-shared.h"
#include "kcov-api.h"
