#pragma once
#include <linux/mempolicy.h>

/* linux/mempolicy.h — MPOL_PREFERRED_MANY and MPOL_WEIGHTED_INTERLEAVE are
 * enum members of the mempolicy mode enum, not preprocessor macros, so the
 * #ifndef guards always fire and the fallback values must match the upstream
 * enum literal-for-literal.  Older kernel-headers packages stop the enum at
 * MPOL_LOCAL = 4; MPOL_PREFERRED_MANY (5) landed in 5.15, MPOL_WEIGHTED_INTERLEAVE
 * (6) in 6.9.  This header pulls <linux/mempolicy.h> first so the canonical
 * enum body is parsed before the fallback macros become live, regardless of
 * the consumer's include order. */
#ifndef MPOL_PREFERRED_MANY
#define MPOL_PREFERRED_MANY		5
#endif
#ifndef MPOL_WEIGHTED_INTERLEAVE
#define MPOL_WEIGHTED_INTERLEAVE	6
#endif
