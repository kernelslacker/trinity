/*
 * SYSCALL_DEFINE3(signalfd, int, ufd, sigset_t __user *, user_mask, size_t, sizemask)
 */
#include <signal.h>
#include <unistd.h>
#include "publish_resource.h"
#include "rnd.h"
#include "sanitise.h"

#define KERNEL_SIGSET_SIZE	8

/*
 * Populate the user_mask the four signalfd shapes care about:
 *   - empty mask: drives the accept-no-signals path
 *   - single RT signal: hits the per-signal queued-info path
 *   - mixed standard set: classic SIGUSR1/2 + SIGCHLD/SIGALRM mix
 *   - sigfillset minus uncatchables: exercises the mask-sanitisation
 *     path where the kernel silently drops SIGKILL/SIGSTOP
 */
static void fill_signalfd_mask(sigset_t *set)
{
	int signo;

	switch (rnd_modulo_u32(4)) {
	case 0:
		sigemptyset(set);
		break;
	case 1:
		sigemptyset(set);
		signo = SIGRTMIN + (int) rnd_modulo_u32(SIGRTMAX - SIGRTMIN + 1);
		sigaddset(set, signo);
		break;
	case 2:
		sigemptyset(set);
		sigaddset(set, SIGUSR1);
		sigaddset(set, SIGUSR2);
		sigaddset(set, SIGCHLD);
		sigaddset(set, SIGALRM);
		break;
	default:
		sigfillset(set);
		sigdelset(set, SIGKILL);
		sigdelset(set, SIGSTOP);
		break;
	}
}

static void sanitise_signalfd(struct syscallrecord *rec)
{
	sigset_t *set;

	set = (sigset_t *) get_writable_struct(sizeof(*set));
	if (!set)
		return;
	fill_signalfd_mask(set);

	rec->a2 = (unsigned long) set;
	avoid_shared_buffer_inout(&rec->a2, sizeof(sigset_t));
	rec->a3 = KERNEL_SIGSET_SIZE;

	/* Occasionally pass a mismatched sizemask to hit the EINVAL gate
	 * the kernel uses to reject anything other than KERNEL_SIGSET_SIZE. */
	if (rnd_modulo_u32(10) == 0)
		rec->a3 = sizeof(sigset_t) - 8;
}

static void post_signalfd(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd < 0 || fd >= (1 << 20))
		return;

	if (publish_resource(OBJ_FD_SIGNALFD, fd, NULL) == NULL)
		close(fd);
}

struct syscallentry syscall_signalfd = {
	.name = "signalfd",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_FD_SIGNALFD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "ufd", [1] = "user_mask", [2] = "sizemask" },
	.sanitise = sanitise_signalfd,
	.post = post_signalfd,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SIGNALFD,
	.flags = NEED_ALARM,
};

/*
 * SYSCALL_DEFINE4(signalfd4, int, ufd, sigset_t __user *, user_mask,
	 size_t, sizemask, int, flags)
 */

#define SFD_CLOEXEC 02000000
#define SFD_NONBLOCK 04000

/*
 * Pick an explicit flag combination instead of the single-flag-at-a-
 * time ARG_LIST shape.  Buckets cover the four legal combinations and
 * reserve a small slice for an invalid high bit so the kernel's
 * unknown-flag reject path gets exercised.
 */
static unsigned long pick_signalfd4_flags(void)
{
	uint32_t r = rnd_modulo_u32(100);

	if (r < 25)
		return 0;
	if (r < 50)
		return SFD_CLOEXEC;
	if (r < 75)
		return SFD_NONBLOCK;
	if (r < 95)
		return SFD_CLOEXEC | SFD_NONBLOCK;
	return SFD_CLOEXEC | 0x80000000UL;
}

static void sanitise_signalfd4(struct syscallrecord *rec)
{
	sigset_t *set;

	set = (sigset_t *) get_writable_struct(sizeof(*set));
	if (!set)
		return;
	fill_signalfd_mask(set);

	rec->a2 = (unsigned long) set;
	avoid_shared_buffer_inout(&rec->a2, sizeof(sigset_t));
	rec->a3 = KERNEL_SIGSET_SIZE;

	if (rnd_modulo_u32(10) == 0)
		rec->a3 = sizeof(sigset_t) - 8;

	rec->a4 = pick_signalfd4_flags();
}

struct syscallentry syscall_signalfd4 = {
	.name = "signalfd4",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_SIGNALFD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "ufd", [1] = "user_mask", [2] = "sizemask", [3] = "flags" },
	.sanitise = sanitise_signalfd4,
	.post = post_signalfd,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SIGNALFD,
	.flags = NEED_ALARM,
};
