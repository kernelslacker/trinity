/*
 * SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
 */
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

#if !defined(MS_ASYNC)
#define MS_ASYNC        1               /* Sync memory asynchronously.  */
#endif
#if !defined(MS_SYNC)
#define MS_SYNC         4               /* Synchronous memory sync.  */
#endif
#if !defined(MS_INVALIDATE)
#define MS_INVALIDATE   2               /* Invalidate the caches.  */
#endif

static void sanitise_msync(struct syscallrecord *rec)
{
       (void) common_set_mmap_ptr_len();

	if (RAND_BOOL())
		rec->a3 |= MS_INVALIDATE;
}

static unsigned long msync_flags[] = {
	MS_ASYNC, MS_SYNC,
};

struct syscallentry syscall_msync = {
	.name = "msync",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.arg3name = "flags",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(msync_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_msync,
};
