/*
 * SYSCALL_DEFINE2(flock, unsigned int, fd, unsigned int, cmd)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/file.h>
#include "fd.h"
#include "files.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static const unsigned int flock_base_ops[] = {
	LOCK_SH, LOCK_EX, LOCK_UN,
};

static unsigned long flock_cmds[] = {
	LOCK_SH, LOCK_EX, LOCK_UN,
	LOCK_SH | LOCK_NB, LOCK_EX | LOCK_NB, LOCK_UN | LOCK_NB,
	LOCK_NB,
};

/*
 * flock() is defined for regular files and block devices; other fd
 * types (sockets, pipes, eventfds, ...) trip the file->f_op->lock
 * NULL check and return -EINVAL before any lock-state code runs.  A
 * plain ARG_FD draw hits the accept path almost exclusively because
 * the general fd pool is dominated by pathname-opened regular files,
 * so bias half the draws toward known-lockable pagecache fds while
 * reserving a slice for each of the non-lockable typed pools -- the
 * validation branch is small but it is the entry point for every
 * flock() call.
 *
 * cmd: shape rec->a2 as a base op {LOCK_SH, LOCK_EX, LOCK_UN} with a
 * coin-flip LOCK_NB modifier so LOCK_UN | LOCK_NB is reachable in
 * addition to the SH/EX non-blocking pair, and reserve ~10% for cmd
 * == LOCK_NB alone.  The bare-LOCK_NB case takes a distinct EINVAL
 * arm in flock_translate_cmd() (no base bit set) that a fixed arglist
 * cannot express, since ARG_OP picks one list value verbatim.
 *
 * Re-exec safe: rewrites two fixed-size scalar args, no allocations,
 * no INOUT / output buffers, no post_state.
 */
static void sanitise_flock(struct syscallrecord *rec)
{
	unsigned int fd_pick = rnd_modulo_u32(100);
	unsigned int cmd_pick = rnd_modulo_u32(100);
	unsigned int cmd;

	if (fd_pick < 50) {
		int fd = get_rand_pagecache_fd();

		if (fd >= 0)
			rec->a1 = (unsigned long) fd;
	} else if (fd_pick < 65) {
		rec->a1 = (unsigned long) get_typed_fd(ARG_FD_SOCKET);
	} else if (fd_pick < 80) {
		rec->a1 = (unsigned long) get_typed_fd(ARG_FD_PIPE);
	} else if (fd_pick < 90) {
		rec->a1 = (unsigned long) get_typed_fd(ARG_FD_EVENTFD);
	}
	/* else: leave the ARG_FD-derived fd untouched */

	if (cmd_pick < 10) {
		cmd = LOCK_NB;
	} else {
		cmd = flock_base_ops[rnd_modulo_u32(ARRAY_SIZE(flock_base_ops))];
		if (RAND_BOOL())
			cmd |= LOCK_NB;
	}
	rec->a2 = (unsigned long) cmd;
}

struct syscallentry syscall_flock = {
	.name = "flock",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_OP },
	.argname = { [0] = "fd", [1] = "cmd" },
	.arg_params[1].list = ARGLIST(flock_cmds),
	.sanitise = sanitise_flock,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_VFS,
};
