/*
 * SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol, int __user *, usockvec)
 */
#include <stdlib.h>
#include <sys/socket.h>
#include "child.h"
#include "fd-event.h"
#include "net.h"
#include "objects.h"
#include "sanitise.h"

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
}

static void post_socketpair(struct syscallrecord *rec)
{
	int *sv;
	struct childdata *child;

	if (rec->retval != 0)
		goto out;

	sv = (int *) rec->a4;
	if (sv == NULL)
		goto out;

	/* Register both new fds in the object pool via the event queue.
	 * socketpair creates AF_UNIX sockets, so use OBJ_FD_SOCKET. */
	child = this_child();
	if (child != NULL && child->fd_event_ring != NULL) {
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_CREATED,
				 sv[0], -1, OBJ_FD_SOCKET);
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_CREATED,
				 sv[1], -1, OBJ_FD_SOCKET);
	}

out:
	freeptr(&rec->a4);
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
