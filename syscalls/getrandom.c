/*
 * SYSCALL_DEFINE3(getrandom, char __user *, buf, size_t, count, unsigned int, flags)
 */
#include <errno.h>
#include "maps.h"
#include "sanitise.h"
#include "trinity.h"

#define GRND_NONBLOCK  0x0001
#define GRND_RANDOM    0x0002

static void sanitise_getrandom(__unused__ struct syscallrecord *rec)
{
	(void) common_set_mmap_ptr_len();
}

static unsigned long getrandom_flags[] = {
	GRND_NONBLOCK, GRND_RANDOM,
};

struct syscallentry syscall_getrandom = {
	.name = "getrandom",
	.num_args = 3,
	.arg1name = "buf",
	.arg1type = ARG_MMAP,
	.arg2name = "count",
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(getrandom_flags),
	.sanitise = sanitise_getrandom,
};
