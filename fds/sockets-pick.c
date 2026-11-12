/*
 * A pooled socket of one of the shapes a taker names, for a request that
 * hands the kernel the fd of a socket whose family, type and protocol it
 * checks, as l2tp_validate_socket() does a managed tunnel's.
 */

#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "net.h"
#include "objects.h"
#include "rnd.h"
#include "socketinfo.h"
#include "utils.h"

/*
 * socket() keeps an inet protocol of 0 as given, where inet_create() makes
 * 0 the first protocol registered for the type: UDP for a datagram socket,
 * TCP for a stream one and SCTP for a seqpacket one, SCTP's being the only
 * seqpacket protosw (a socket of that shape opens only once it is loaded).
 */
unsigned int triplet_protocol(const struct socket_triplet *triplet)
{
	unsigned int type = triplet->type & SOCK_TYPE_MASK;

	if (triplet->protocol == 0 &&
	    (triplet->family == PF_INET || triplet->family == PF_INET6)) {
		if (type == SOCK_DGRAM)
			return IPPROTO_UDP;
		if (type == SOCK_STREAM)
			return IPPROTO_TCP;
		if (type == SOCK_SEQPACKET)
			return IPPROTO_SCTP;
	}
	return triplet->protocol;
}

/*
 * Whether si is a socket of one of the n shapes, which name the protocol
 * the kernel records.  socket() keeps the type with its SOCK_CLOEXEC and
 * SOCK_NONBLOCK flags.
 */
static bool socket_has_shape(const struct socketinfo *si,
			     const struct socket_triplet *shapes, unsigned int n)
{
	unsigned int family = si->triplet.family;
	unsigned int type = si->triplet.type & SOCK_TYPE_MASK;
	unsigned int protocol = triplet_protocol(&si->triplet);
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (family == shapes[i].family && type == shapes[i].type &&
		    protocol == shapes[i].protocol)
			return true;
	}
	return false;
}

/*
 * The child's own sockets go first: they were opened in its netns, which
 * in a lane child is the one netns its requests hold CAP_NET_ADMIN over,
 * where the parent's sit in the parent's.  The global pool is the
 * fallback, for a child that has opened none of the shapes.
 */
int get_rand_socket_fd_of_triplet(const struct socket_triplet *triplets,
				  unsigned int n_triplets)
{
	static const enum obj_scope scopes[] = { OBJ_LOCAL, OBJ_GLOBAL };
	unsigned int i, idx;

	for (i = 0; i < ARRAY_SIZE(scopes); i++) {
		struct objhead *head = get_objhead(scopes[i], OBJ_FD_SOCKET);
		unsigned int matches = 0;
		struct object *obj;
		int fd = -1;

		for_each_obj(head, obj, idx) {
			if (!objpool_check(obj, OBJ_FD_SOCKET) ||
			    obj->sockinfo.fd < 0 ||
			    !socket_has_shape(&obj->sockinfo, triplets, n_triplets))
				continue;
			/* The nth match takes the pick one time in n, so
			 * each is as likely as another. */
			if (rnd_modulo_u32(++matches) == 0)
				fd = obj->sockinfo.fd;
		}
		if (fd >= 0)
			return fd;
	}
	return -1;
}
