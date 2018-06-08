/*
 * SYSCALL_DEFINE1(setuid, uid_t, uid)
 */
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "syscall.h"
#include "trinity.h"

static void sanitise_setuid(struct syscallrecord *rec)
{
	rec->a1 = rand32();
}

struct syscallentry syscall_setuid = {
	.name = "setuid",
	.num_args = 1,
	.arg1name = "uid",
	.sanitise = sanitise_setuid,
};

/*
 * SYSCALL_DEFINE1(setuid16, old_uid_t, uid)
 */

struct syscallentry syscall_setuid16 = {
	.name = "setuid16",
	.num_args = 1,
	.arg1name = "uid",
	.sanitise = sanitise_setuid,
};
