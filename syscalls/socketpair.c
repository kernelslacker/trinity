/*
 * SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol, int __user *, usockvec)
 */
#include <stdlib.h>
#include <sys/socket.h>
#include "sanitise.h"
#include "utils.h"

static void sanitise_socketpair(struct syscallrecord *rec)
{
	rec->a1 = AF_UNIX;
	rec->a4 = (unsigned long) malloc(sizeof(int) * 2);
}

static void post_socketpair(struct syscallrecord *rec)
{
	//TODO: on success we should put the fd's that
	// were created into a child-local fd array.

	freeptr(&rec->a4);
}

struct syscallentry syscall_socketpair = {
	.name = "socketpair",
	.num_args = 4,
	.arg1name = "family",
	.arg2name = "type",
	.arg3name = "protocol",
	.arg4name = "usockvec",
	.arg4type = ARG_ADDRESS,
	.sanitise = sanitise_socketpair,
	.post = post_socketpair,
};
