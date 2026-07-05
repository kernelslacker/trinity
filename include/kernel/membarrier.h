#pragma once

/*
 * Wrapper around <linux/membarrier.h> that ships #ifndef-guarded
 * fallbacks for the MEMBARRIER_CMD_* values touched by
 * syscalls/membarrier.c.  Per-symbol #ifndef so a sysroot that ships
 * only a subset of the membarrier.h symbols (older LTS, stripped
 * headers) still compiles.
 */
#include <linux/membarrier.h>

#ifndef MEMBARRIER_CMD_FLAG_CPU
#define MEMBARRIER_CMD_FLAG_CPU				(1 << 0)
#endif

#ifndef MEMBARRIER_CMD_QUERY
#define MEMBARRIER_CMD_QUERY				0
#endif
#ifndef MEMBARRIER_CMD_GLOBAL
#define MEMBARRIER_CMD_GLOBAL				(1 << 0)
#endif
#ifndef MEMBARRIER_CMD_GLOBAL_EXPEDITED
#define MEMBARRIER_CMD_GLOBAL_EXPEDITED			(1 << 1)
#endif
#ifndef MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
#define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED	(1 << 2)
#endif
#ifndef MEMBARRIER_CMD_PRIVATE_EXPEDITED
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED		(1 << 3)
#endif
#ifndef MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED	(1 << 4)
#endif
#ifndef MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE	(1 << 5)
#endif
#ifndef MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1 << 6)
#endif

#ifndef MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ		(1 << 7)
#endif
#ifndef MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ	(1 << 8)
#endif

#ifndef MEMBARRIER_CMD_GET_REGISTRATIONS
#define MEMBARRIER_CMD_GET_REGISTRATIONS		(1 << 9)
#endif
