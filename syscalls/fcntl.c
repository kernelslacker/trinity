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
#include "trinity.h"
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

/*
 * Stratified cmd picker.  Uniform sampling across the full cmd list under-
 * exercises the rarer kernel paths (lease/OFD-lock/owner_ex/seals/notify),
 * because most of the cmds in fcntl_flags[] route into a small set of common
 * file_struct accessors.  Bias the picker so the rare paths get hit ~30% of
 * the time, and also drop in a fully random cmd ~10% of the time to cover
 * out-of-table values that exercise the kernel's input validation.
 */
static const unsigned long fcntl_cmds_common[] = {
	F_GETFD, F_SETFD, F_DUPFD, F_GETFL, F_SETFL,
};

static const unsigned long fcntl_cmds_rare[] = {
	F_SETLEASE, F_GETLEASE,
	F_GETOWN_EX, F_SETOWN_EX,
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	F_NOTIFY,
	F_ADD_SEALS, F_GET_SEALS,
	F_SETSIG, F_GETSIG,
	F_SETPIPE_SZ,
};

static unsigned long pick_fcntl_cmd(void)
{
	unsigned int r = rand() % 100;

	if (r < 60)
		return fcntl_cmds_common[rand() % ARRAY_SIZE(fcntl_cmds_common)];
	if (r < 90)
		return fcntl_cmds_rare[rand() % ARRAY_SIZE(fcntl_cmds_rare)];
	return (unsigned long) rand32();
}

static void sanitise_fcntl(struct syscallrecord *rec)
{
	rec->a2 = pick_fcntl_cmd();

	switch (rec->a2) {
	/* arg = fd */
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
		rec->a3 = (unsigned long) get_random_fd();
		break;

	case F_SETLEASE: {
		int lease_types[] = { F_RDLCK, F_WRLCK, F_UNLCK };
		rec->a3 = lease_types[rand() % 3];
		break;
	}

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

	switch (rec->a2) {
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
		rec->rettype = RET_FD;
		break;
	default:
		rec->rettype = RET_ZERO_SUCCESS;
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
	F_DUPFD_QUERY, F_CREATED_QUERY, F_CANCELLK,
	F_ADD_SEALS, F_GET_SEALS,
	F_GET_RW_HINT, F_SET_RW_HINT, F_GET_FILE_RW_HINT, F_SET_FILE_RW_HINT,
	F_GETDELEG, F_SETDELEG,
};

static void post_fcntl(struct syscallrecord *rec)
{
	long got;

	if ((long) rec->retval < 0)
		return;

	switch (rec->a2) {
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
		__atomic_add_fetch(&shm->stats.fd_duped, 1, __ATOMIC_RELAXED);
		break;

	case F_SETFL:
		/*
		 * Oracle: flags we just set must survive a round-trip through
		 * F_GETFL.  A missing bit means the kernel silently dropped a
		 * status flag — a sign of fd-table or file-struct corruption.
		 */
		got = fcntl((int) rec->a1, F_GETFL);
		if (got >= 0 && (got & rec->a3) != rec->a3) {
			output(0, "fd oracle: fcntl(%lu, F_SETFL, 0x%lx) "
			       "but F_GETFL=0x%lx (missing bits: 0x%lx)\n",
			       rec->a1, rec->a3, (unsigned long) got,
			       rec->a3 & ~(unsigned long) got);
			__atomic_add_fetch(&shm->stats.fd_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
		break;
	}
}

struct syscallentry syscall_fcntl = {
	.name = "fcntl",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_OP },
	.argname = { [0] = "fd", [1] = "cmd", [2] = "arg" },
	.arg_params[1].list = ARGLIST(fcntl_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fcntl,
	.post = post_fcntl,
};
