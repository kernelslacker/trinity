/*
 * SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
 *
 * For a successful call, the return value depends on the operation:
 *
 *     F_DUPFD The new descriptor.
 *     F_GETFD Value of file descriptor flags.
 *     F_GETFL Value of file status flags.
 *     F_GETLEASE Type of lease held on file descriptor.
 *     F_GETOWN Value of descriptor owner.
 *     F_GETSIG Value of signal sent when read or write becomes possible, or zero for traditional SIGIO behavior.
 *     F_GETPIPE_SZ The pipe capacity.
 *
 *     All other commands
 *              Zero.
 *
 *     On error, -1 is returned, and errno is set appropriately.
 */

#include <fcntl.h>
#include <signal.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscalls.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

#if F_GETLK64 != F_GETLK
#define HAVE_LK64
#endif

static const unsigned long fcntl_o_flags[] = {
	O_APPEND, O_ASYNC, O_DIRECT, O_NOATIME, O_NONBLOCK,
};

unsigned int random_fcntl_setfl_flags(void)
{
	return set_rand_bitmask(ARRAY_SIZE(fcntl_o_flags), fcntl_o_flags);
}

static void sanitise_fcntl(struct syscallrecord *rec)
{
	switch (rec->a2) {
	/* arg = fd */
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
	case F_SETLEASE:
		rec->a3 = (unsigned long) get_random_fd();
		break;

	/* no arg */
	case F_GETFD:
	case F_GETFL:
	case F_GETOWN:
	case F_GETSIG:
	case F_GETLEASE:
	case F_GETPIPE_SZ:
	case F_GETOWNER_UIDS:
		break;

	case F_SETFD:	/* arg = flags */
		rec->a3 = (unsigned int) rand32();
		break;

	case F_SETFL:
		rec->a3 = (unsigned long) random_fcntl_setfl_flags();
		break;

	/* arg = (struct flock *) */
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		break;
#ifdef HAVE_LK64
	case F_GETLK64:
		break;
	case F_SETLK64:
		break;
	case F_SETLKW64:
		break;
#endif

	case F_SETOWN:
		rec->a3 = (unsigned long) get_pid();
		break;

	/* arg = struct f_owner_ex *) */
	case F_GETOWN_EX:
	case F_SETOWN_EX:
		break;

	case F_SETSIG:
		rec->a3 = (unsigned long) rand32();
		if (rec->a3 == SIGINT)
			rec->a3 = 0; /* restore default (SIGIO) */
		break;

	case F_NOTIFY:
		rec->a3 = 0L;
		if (RAND_BOOL())
			rec->a3 |= DN_ACCESS;
		if (RAND_BOOL())
			rec->a3 |= DN_MODIFY;
		if (RAND_BOOL())
			rec->a3 |= DN_CREATE;
		if (RAND_BOOL())
			rec->a3 |= DN_DELETE;
		if (RAND_BOOL())
			rec->a3 |= DN_RENAME;
		if (RAND_BOOL())
			rec->a3 |= DN_ATTRIB;
		break;

	case F_SETPIPE_SZ:
		rec->a3 = rand32();
		break;

	default:
		break;
	}

}

static unsigned long fcntl_flags[] = {
	F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETLK, F_SETLK,
	F_SETLKW, F_GETOWN, F_SETOWN, F_GETOWN_EX, F_SETOWN_EX, F_GETSIG, F_SETSIG, F_GETLEASE,
	F_SETLEASE, F_NOTIFY, F_SETPIPE_SZ, F_GETPIPE_SZ, F_GETOWNER_UIDS,
#ifdef HAVE_LK64
	F_GETLK64, F_SETLK64, F_SETLKW64,
#endif
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
};

struct syscallentry syscall_fcntl = {
	.name = "fcntl",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(fcntl_flags),
	.arg3name = "arg",
	.rettype = RET_FD,	//FIXME: Needs to mutate somehow depending on 'cmd'
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fcntl,
};
