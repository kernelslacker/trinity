#pragma once

#include <sys/socket.h>
#include <stdbool.h>

struct socket_triplet {
	unsigned int family;
	unsigned int type;
	unsigned int protocol;
};

/* We create one of these per socket fd we open, and store them in shm->sockets */
struct socketinfo {
	struct socket_triplet triplet;
	int fd;
	/*
	 * Listener-state cache populated by add_socket() before the obj is
	 * published into the shared (post-init read-only) pool.  Most pooled
	 * sockets are fresh socket()s and report SO_ACCEPTCONN == 0 here; the
	 * cache fires for sockets that were already in LISTEN at registration
	 * time and lets the accept-unblocker connector skip its lazy
	 * getsockopt+getsockname re-probe.  Sockets that transition to LISTEN
	 * later (via socket_child_ops()'s bind/listen) cannot write back into
	 * the read-only slot — the connector falls back to a lazy probe of
	 * the live fd in that case.
	 */
	bool is_listener;
	socklen_t local_len;
	struct sockaddr_storage local;
};

struct object;
struct object * add_socket(int fd, unsigned int domain, unsigned int type, unsigned int protocol);
