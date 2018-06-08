#pragma once

struct socket_triplet {
	unsigned int family;
	unsigned int type;
	unsigned int protocol;
};

/* We create one of these per socket fd we open, and store them in shm->sockets */
struct socketinfo {
	struct socket_triplet triplet;
	int fd;
};
