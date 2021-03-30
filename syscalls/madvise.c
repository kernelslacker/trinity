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
	MADV_WIPEONFORK, MADV_KEEPONFORK, MADV_COLD, MADV_PAGEOUT,
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

static unsigned long process_madvise_behaviours[] = {
	MADV_COLD, MADV_PAGEOUT,
};
static unsigned long process_madvise_flags[] = {
	0,
};

struct syscallentry syscall_process_madvise = {
	.name = "process_madvise",
	.num_args = 5,
	.arg1name = "pidfd",
	.arg1type = ARG_FD,
	.arg2name = "vec",
	.arg3name = "vlen",
	.arg3type = ARG_LEN,
	.arg4name = "behaviour",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(process_madvise_behaviours),
	.arg5name = "flags",
	.arg5type = ARG_OP,
	.arg5list = ARGLIST(process_madvise_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_madvise,
};
