/*
 * SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
 *                          const char __user *, uargs)
 */
#include <errno.h>
#include <linux/filter.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"

#define SECCOMP_SET_MODE_STRICT		0
#define SECCOMP_SET_MODE_FILTER		1
#define SECCOMP_GET_ACTION_AVAIL	2
#define SECCOMP_GET_NOTIF_SIZES		3

#define SECCOMP_FILTER_FLAG_TSYNC		(1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG			(1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW		(1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH		(1UL << 4)
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV	(1UL << 5)

static void sanitise_seccomp(struct syscallrecord *rec)
{
	if (rec->a1 == SECCOMP_SET_MODE_STRICT) {
		rec->a2 = 0;
		rec->a3 = 0;
	}

	if (rec->a1 == SECCOMP_SET_MODE_FILTER) {
		/*
		 * FILTER mode needs uargs pointing to a valid struct sock_fprog
		 * containing a BPF program.  Use bpf_gen_seccomp() which builds
		 * seccomp-flavoured cBPF programs with the Markov chain generator.
		 */
#ifdef USE_BPF
		unsigned long *addr = NULL;
		unsigned long len = 0;

		bpf_gen_seccomp(&addr, &len);
		rec->a3 = (unsigned long) addr;
#endif
	}
}

static void post_seccomp(struct syscallrecord *rec)
{
#ifdef USE_BPF
	if (rec->a1 == SECCOMP_SET_MODE_FILTER && rec->a3) {
		struct sock_fprog *fprog = (struct sock_fprog *) rec->a3;

		free(fprog->filter);
		deferred_freeptr(&rec->a3);
	}
#endif
}

static unsigned long seccomp_ops[] = {
	SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER,
	SECCOMP_GET_ACTION_AVAIL, SECCOMP_GET_NOTIF_SIZES,
};

static unsigned long seccomp_flags[] = {
	SECCOMP_FILTER_FLAG_TSYNC,
	SECCOMP_FILTER_FLAG_LOG,
	SECCOMP_FILTER_FLAG_SPEC_ALLOW,
	SECCOMP_FILTER_FLAG_NEW_LISTENER,
	SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
	SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
};

struct syscallentry syscall_seccomp = {
	.name = "seccomp",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_LIST, [2] = ARG_ADDRESS },
	.argname = { [0] = "op", [1] = "flags", [2] = "uargs" },
	.arg_params[0].list = ARGLIST(seccomp_ops),
	.arg_params[1].list = ARGLIST(seccomp_flags),
	.sanitise = sanitise_seccomp,
	.post = post_seccomp,
	.group = GROUP_PROCESS,
};
