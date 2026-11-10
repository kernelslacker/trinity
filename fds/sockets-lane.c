/*
 * Netlink sockets a userns-admin lane child opens for itself.
 * netlink_ns_capable() checks the user namespace owning the sending
 * socket's netns: the parent's pooled sockets sit in a netns the lane
 * child holds no capability over, while one it opens after the lane's
 * unshare sits in a netns its own user namespace owns.
 */

#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "child-api.h"
#include "net.h"
#include "objects.h"
#include "random.h"
#include "socketinfo.h"

/*
 * The socket a sendmsg drawn onto @si (never NULL) goes out on.  In a
 * lane child a netlink @si is swapped, seven draws in eight, for the
 * socket of its protocol the child opened, kept in its OBJ_LOCAL pool;
 * the eighth keeps the parent's, for the refused path and the parent
 * netns's devices (the lane's has only lo).  The pool is the record of
 * what is open: a fuzzed close() retires the object, and the next swap
 * opens another.
 */
struct socketinfo *lane_netlink_socketinfo(struct socketinfo *si)
{
	/*
	 * Protocols a lane socket cannot serve: those whose kernel socket
	 * exists in init_net alone, so that one in the lane's netns has no
	 * peer (ECONNREFUSED), and those socket() has refused in this child
	 * for as long as it lives.
	 */
	static bool no_lane_socket[MAX_LINKS] = {
		[NETLINK_SELINUX] = true,
		[NETLINK_ISCSI] = true,
		[NETLINK_CONNECTOR] = true,
		[NETLINK_SCSITRANSPORT] = true,
	};
	/*
	 * The slot_version add_object() stamped on each protocol's socket,
	 * 0 for none.  Matching the triplet is not enough: a dup of one of
	 * the parent's sockets joins the pool under the parent's triplet,
	 * in the parent's netns.
	 */
	static unsigned int own_version[MAX_LINKS];
	unsigned int protocol = si->triplet.protocol;
	struct objhead *head;
	struct object *obj;
	unsigned int idx;
	int fd;

	if (si->triplet.family != PF_NETLINK || !child_userns_lane_is_active())
		return si;
	if (protocol >= MAX_LINKS || no_lane_socket[protocol] || ONE_IN(8))
		return si;

	if (own_version[protocol] != 0) {
		head = get_objhead(OBJ_LOCAL, OBJ_FD_SOCKET);
		for_each_obj(head, obj, idx) {
			if (objpool_check(obj, OBJ_FD_SOCKET) &&
			    obj->slot_version == own_version[protocol])
				return &obj->sockinfo;
		}
	}

	fd = socket(PF_NETLINK, si->triplet.type, protocol);
	if (fd < 0) {
		/* A bad type (ESOCKTNOSUPPORT) or no fds says nothing about
		 * the protocol. */
		if (errno == EPROTONOSUPPORT)
			no_lane_socket[protocol] = true;
		return si;
	}

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		return si;
	}
	obj->sockinfo.fd = fd;
	obj->sockinfo.triplet.family = PF_NETLINK;
	obj->sockinfo.triplet.type = si->triplet.type;
	obj->sockinfo.triplet.protocol = protocol;

	/* A local object still under the fresh number names a file that
	 * is gone. */
	remove_local_objects_by_fd(fd);
	add_object(obj, OBJ_LOCAL, OBJ_FD_SOCKET);

	/* add_object() can give obj back rather than pool it, and the prune
	 * that follows a publish can destroy it, so what was kept is looked
	 * up again. */
	obj = find_local_object_by_fd(OBJ_FD_SOCKET, fd);
	if (obj == NULL)
		return si;
	own_version[protocol] = obj->slot_version;
	return &obj->sockinfo;
}
