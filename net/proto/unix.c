#include <sys/socket.h>
#include <sys/un.h>
#include "net.h"
#include "random.h"
#include "utils.h"
#include "rnd.h"

#include "kernel/socket.h"

static void unix_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_un *unixsock;
	unsigned int len;

	unixsock = zmalloc_tracked(sizeof(struct sockaddr_un));

	unixsock->sun_family = PF_UNIX;

	switch (rnd_modulo_u32(4)) {
	case 0:
		/* Pathname socket — random path */
		len = RAND_RANGE(1, 20);
		generate_rand_bytes((unsigned char *)unixsock->sun_path, len);
		*addrlen = sizeof(sa_family_t) + len;
		break;

	case 1:
		/* Abstract namespace — NUL byte prefix */
		unixsock->sun_path[0] = '\0';
		len = RAND_RANGE(1, 20);
		generate_rand_bytes((unsigned char *)unixsock->sun_path + 1, len);
		*addrlen = sizeof(sa_family_t) + 1 + len;
		break;

	case 2:
		/* Unnamed socket — zero-length path */
		*addrlen = sizeof(sa_family_t);
		break;

	case 3:
		/* Varying addrlen to exercise edge cases */
		len = rnd_modulo_u32(20);
		generate_rand_bytes((unsigned char *)unixsock->sun_path, len);
		*addrlen = sizeof(sa_family_t) + len;
		break;
	}

	*addr = (struct sockaddr *) unixsock;
}

/* getsockopt() draws its option from this list too, which is what
 * SO_PEERPIDFD and SO_PEERPIDFD_THREAD are here for: only AF_UNIX records
 * the peer's connecting thread, and its pidfds alone can be PIDFD_STALE. */
static const unsigned int unix_opts[] = {
	SO_PASSCRED, SO_PEEK_OFF, SO_PASSPIDFD, SO_PASSSEC,
	SO_PASSRIGHTS, SO_INQ, SO_RIGHTS_NOTRUNC,
	SO_PASSPIDFD_THREAD, SO_PEERPIDFD, SO_PEERPIDFD_THREAD,
};

static void unix_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	int *optval32;

	so->level = SOL_SOCKET;
	so->optname = RAND_ARRAY(unix_opts);

	switch (so->optname) {
	case SO_PASSCRED:
	case SO_PASSPIDFD:
	case SO_PASSPIDFD_THREAD:
	case SO_PASSSEC:
	case SO_PASSRIGHTS:
	case SO_INQ:
	case SO_RIGHTS_NOTRUNC:
		optval32 = (int *) so->optval;
		*optval32 = RAND_BOOL();
		so->optlen = sizeof(int);
		break;

	case SO_PEEK_OFF:
		optval32 = (int *) so->optval;
		switch (rnd_modulo_u32(4)) {
		case 0: *optval32 = -1; break;		/* disable */
		case 1: *optval32 = 0; break;		/* start of queue */
		case 2: *optval32 = rnd_modulo_u32(4096); break;
		case 3: *optval32 = rnd_u32(); break;
		}
		so->optlen = sizeof(int);
		break;

	default:
		break;
	}
}

static struct socket_triplet unix_triplet[] = {
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_unix = {
	.name = "unix",
	.gen_sockaddr = unix_gen_sockaddr,
	.setsockopt = unix_setsockopt,
	.valid_triplets = unix_triplet,
	.nr_triplets = ARRAY_SIZE(unix_triplet),
};
