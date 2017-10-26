/*
 * SYSCALL_DEFINE3(madvise, unsigned long, start, size_t, len_in, int, behavior)
 */
#include <stdlib.h>
#include <sys/mman.h>
#include "maps.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_madvise(__unused__ struct syscallrecord *rec)
{
	(void) common_set_mmap_ptr_len();
}

static unsigned long madvise_advices[] = {
	MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED,
	MADV_DONTNEED,
	MADV_FREE, MADV_REMOVE, MADV_DONTFORK, MADV_DOFORK,
	MADV_MERGEABLE, MADV_UNMERGEABLE, MADV_HUGEPAGE, MADV_NOHUGEPAGE,
	MADV_DONTDUMP, MADV_DODUMP,
	MADV_WIPEONFORK, MADV_KEEPONFORK,
};

struct syscallentry syscall_madvise = {
	.name = "madvise",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "len_in",
	.arg3name = "advice",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(madvise_advices),
	.group = GROUP_VM,
	.sanitise = sanitise_madvise,
};
