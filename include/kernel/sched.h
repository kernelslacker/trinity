#pragma once

#include <linux/sched.h>

#ifndef CLONE_ARGS_SIZE_VER0
#define CLONE_ARGS_SIZE_VER0 64
#endif
#ifndef CLONE_ARGS_SIZE_VER1
#define CLONE_ARGS_SIZE_VER1 80
#endif
#ifndef CLONE_ARGS_SIZE_VER2
#define CLONE_ARGS_SIZE_VER2 88
#endif

#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif
/*
 * CLONE_AUTOREAP / CLONE_NNP / CLONE_PIDFD_AUTOKILL / CLONE_EMPTY_MNTNS
 * are mainline as of Linux v7.1, and the encodings used here match
 * the upstream uapi.  The umbrella #ifndef below is a forward-compat
 * shim so the build still works on older build hosts whose
 * <linux/sched.h> predates these symbols.  All four landed together
 * with these encodings, so a single guard on the first symbol is
 * sufficient.  If a future uapi change renumbers any of them or
 * defines only a subset, this block must be split into per-symbol
 * ifndefs to avoid a redefinition warning on the symbols that the
 * system header already provides.
 */
#ifndef CLONE_AUTOREAP
#define CLONE_AUTOREAP		(1ULL << 34)
#define CLONE_NNP		(1ULL << 35)
#define CLONE_PIDFD_AUTOKILL	(1ULL << 36)
#define CLONE_EMPTY_MNTNS	(1ULL << 37)
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP		0x02000000
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME		0x00000080
#endif

