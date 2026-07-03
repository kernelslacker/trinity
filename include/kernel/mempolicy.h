#pragma once
#include <linux/mempolicy.h>

/* linux/mempolicy.h — MPOL_DEFAULT..MPOL_LOCAL, MPOL_PREFERRED_MANY, and
 * MPOL_WEIGHTED_INTERLEAVE are enum members of the mempolicy mode enum, not
 * preprocessor macros, so the #ifndef guards always fire and the fallback
 * values must match the upstream enum literal-for-literal.  Older
 * kernel-headers packages stop the enum at MPOL_LOCAL = 4;
 * MPOL_PREFERRED_MANY (5) landed in 5.15, MPOL_WEIGHTED_INTERLEAVE (6) in 6.9.
 * The MPOL_F_* and MPOL_MF_* flags below are ordinary preprocessor macros in
 * <linux/mempolicy.h>, so their #ifndef guards behave normally.  This header
 * pulls <linux/mempolicy.h> first so the canonical enum body is parsed before
 * the fallback macros become live, regardless of the consumer's include order. */
#ifndef MPOL_DEFAULT
#define MPOL_DEFAULT		0
#define MPOL_PREFERRED		1
#define MPOL_BIND		2
#define MPOL_INTERLEAVE		3
#define MPOL_LOCAL		4
#endif
#ifndef MPOL_PREFERRED_MANY
#define MPOL_PREFERRED_MANY		5
#endif
#ifndef MPOL_WEIGHTED_INTERLEAVE
#define MPOL_WEIGHTED_INTERLEAVE	6
#endif
#ifndef MPOL_F_NUMA_BALANCING
#define MPOL_F_NUMA_BALANCING	(1 << 13)	/* 5.12+ */
#endif
#ifndef MPOL_F_RELATIVE_NODES
#define MPOL_F_RELATIVE_NODES	(1 << 14)
#endif
#ifndef MPOL_F_STATIC_NODES
#define MPOL_F_STATIC_NODES	(1 << 15)
#endif
#ifndef MPOL_MF_LAZY
#define MPOL_MF_LAZY		(1 << 3)	/* lazy migrate-on-fault */
#endif
