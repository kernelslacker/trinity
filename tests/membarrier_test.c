/*
 * Self-check for membarrier's sanitiser: MEMBARRIER_CMD_FLAG_CPU goes out
 * only beside MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, the one cmd the
 * kernel takes it with (-EINVAL beside any other).  The sanitiser asks the
 * running kernel which cmds it supports, which changes nothing.
 */

#include <string.h>

#include "debug.h"		/* BUG */
#include "kernel/membarrier.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_membarrier */

#define MEMBARRIER_ROUNDS	4000

void membarrier_self_check(void);
void membarrier_self_check(void)
{
	unsigned int i, flagged = 0;

	for (i = 0; i < MEMBARRIER_ROUNDS; i++) {
		struct syscallrecord rec;

		memset(&rec, 0, sizeof(rec));
		syscall_membarrier.sanitise(&rec);
		if (rec.a2 != MEMBARRIER_CMD_FLAG_CPU)
			continue;
		flagged++;
		if (rec.a1 != MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ)
			BUG("membarrier: MEMBARRIER_CMD_FLAG_CPU beside a cmd that refuses it");
	}
	if (flagged == 0)
		BUG("membarrier: MEMBARRIER_CMD_FLAG_CPU never goes out");
}
