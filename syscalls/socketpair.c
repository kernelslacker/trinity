/*
 * SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol, int __user *, usockvec)
 */
#include <stdlib.h>
#include <sys/socket.h>
#include "net.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_socketpair(struct syscallrecord *rec)
{
	struct socket_triplet st = { .family = 0, .type = 0, .protocol = 0 };

	gen_socket_args(&st);

	rec->a1 = st.family;
	rec->a2 = st.type;
	rec->a3 = st.protocol;
	rec->a4 = (unsigned long) malloc(sizeof(int) * 2);
	if (!rec->a4)
		return;
	/* Snapshot for the post handler -- a4 may be scribbled by a sibling
	 * syscall before post_socketpair() runs. */
	rec->post_state = rec->a4;
}

static void post_socketpair(struct syscallrecord *rec)
{
	void *usockvec = (void *) rec->post_state;

	if (usockvec == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, usockvec)) {
		outputerr("post_socketpair: rejected suspicious usockvec=%p (pid-scribbled?)\n", usockvec);
		rec->a4 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a4 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_socketpair = {
	.name = "socketpair",
	.num_args = 4,
	.argtype = { [3] = ARG_ADDRESS },
	.argname = { [0] = "family", [1] = "type", [2] = "protocol", [3] = "usockvec" },
	.group = GROUP_NET,
	.sanitise = sanitise_socketpair,
	.post = post_socketpair,
};
