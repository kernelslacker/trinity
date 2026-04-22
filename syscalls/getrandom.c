/*
 * SYSCALL_DEFINE3(getrandom, char __user *, buf, size_t, count, unsigned int, flags)
 */
#include <errno.h>
#include "maps.h"
#include "sanitise.h"
#include "trinity.h"

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK  0x0001
#endif
#ifndef GRND_RANDOM
#define GRND_RANDOM    0x0002
#endif
#ifndef GRND_INSECURE
#define GRND_INSECURE  0x0004
#endif

static void sanitise_getrandom(struct syscallrecord *rec)
{
	(void) common_set_mmap_ptr_len();
	avoid_shared_buffer(&rec->a1, rec->a2);
}

static unsigned long getrandom_flags[] = {
	GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE,
};

struct syscallentry syscall_getrandom = {
	.name = "getrandom",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "buf", [1] = "count", [2] = "flags" },
	.arg_params[2].list = ARGLIST(getrandom_flags),
	.sanitise = sanitise_getrandom,
	.group = GROUP_PROCESS,
};
