/*
 * SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol, int __user *, usockvec)
 */
#include <stdlib.h>
#include <sys/socket.h>
#include "net.h"
#include "objects.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void register_socketpair_fd(int fd, struct syscallrecord *rec)
{
	struct object *new;

	if (fd <= 2)
		return;
	if (find_local_object_by_fd(OBJ_FD_SOCKET, fd) != NULL)
		return;

	new = alloc_object();
	new->sockinfo.fd = fd;
	new->sockinfo.triplet.family = rec->a1;
	new->sockinfo.triplet.type = rec->a2;
	new->sockinfo.triplet.protocol = rec->a3;
	add_object(new, OBJ_LOCAL, OBJ_FD_SOCKET);
}

static void sanitise_socketpair(struct syscallrecord *rec)
{
	struct socket_triplet st = { .family = 0, .type = 0, .protocol = 0 };

	gen_socket_args(&st);

	rec->a1 = st.family;
	rec->a2 = st.type;
	rec->a3 = st.protocol;
	rec->a4 = (unsigned long) zmalloc(sizeof(int) * 2);
	if (!rec->a4)
		return;

	avoid_shared_buffer(&rec->a4, 2 * sizeof(int));

	/* Snapshot for the post handler -- a4 may be scribbled by a sibling
	 * syscall before post_socketpair() runs. */
	rec->post_state = rec->a4;
}

static void post_socketpair(struct syscallrecord *rec)
{
	int *usockvec = (int *) rec->post_state;

	if (usockvec == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, usockvec)) {
		outputerr("post_socketpair: rejected suspicious usockvec=%p (pid-scribbled?)\n", usockvec);
		rec->a4 = 0;
		rec->post_state = 0;
		return;
	}

	if ((long) rec->retval == 0) {
		register_socketpair_fd(usockvec[0], rec);
		register_socketpair_fd(usockvec[1], rec);
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
	.rettype = RET_ZERO_SUCCESS,
};
