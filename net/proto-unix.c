#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include "fd.h"
#include "random.h"
#include "compat.h"
#include "utils.h"

#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF	42
#endif

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD	77
#endif

#ifndef SO_PASSSEC
#define SO_PASSSEC	34
#endif

#ifndef SCM_RIGHTS
#define SCM_RIGHTS	0x01
#endif

#ifndef SCM_CREDENTIALS
#define SCM_CREDENTIALS	0x02
#endif

static void unix_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_un *unixsock;
	unsigned int len;

	unixsock = zmalloc(sizeof(struct sockaddr_un));

	unixsock->sun_family = PF_UNIX;

	switch (rand() % 4) {
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
		len = rand() % 20;
		generate_rand_bytes((unsigned char *)unixsock->sun_path, len);
		*addrlen = sizeof(sa_family_t) + rand() % (sizeof(unixsock->sun_path) + 1);
		break;
	}

	*addr = (struct sockaddr *) unixsock;
}

static const unsigned int unix_opts[] = {
	SO_PASSCRED, SO_PEEK_OFF, SO_PASSPIDFD, SO_PASSSEC,
};

static void unix_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	int *optval32;

	so->level = SOL_SOCKET;
	so->optname = RAND_ARRAY(unix_opts);

	switch (so->optname) {
	case SO_PASSCRED:
	case SO_PASSPIDFD:
	case SO_PASSSEC:
		optval32 = (int *) so->optval;
		*optval32 = RAND_BOOL();
		so->optlen = sizeof(int);
		break;

	case SO_PEEK_OFF:
		optval32 = (int *) so->optval;
		switch (rand() % 4) {
		case 0: *optval32 = -1; break;		/* disable */
		case 1: *optval32 = 0; break;		/* start of queue */
		case 2: *optval32 = rand() % 4096; break;
		case 3: *optval32 = rand(); break;
		}
		so->optlen = sizeof(int);
		break;

	default:
		break;
	}
}

/*
 * Build a sendmsg buffer containing SCM_RIGHTS or SCM_CREDENTIALS
 * ancillary data.  Called via the gen_msg hook — the returned buffer
 * becomes the iov, but we also stash a well-formed cmsg control
 * block in the first bytes so the kernel sees structured ancillary
 * data when Trinity's sendmsg sanitiser copies it into msg_control.
 *
 * Even when the sendmsg ultimately fails (wrong socket state, etc.),
 * this exercises the kernel's scm_fp_copy / scm_check_creds paths
 * which are historically rich in bugs.
 */
static void unix_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len)
{
	unsigned char *p;
	size_t cmsg_space;
	struct cmsghdr *cmsg;

	(void) triplet;

	if (RAND_BOOL()) {
		/* SCM_RIGHTS — pass 1–4 random fds */
		unsigned int nr_fds = RAND_RANGE(1, 4);
		int fds[4];
		unsigned int i;

		for (i = 0; i < nr_fds; i++) {
			fds[i] = get_random_fd();
			if (fds[i] < 0)
				fds[i] = 0;	/* stdin as fallback */
		}

		cmsg_space = CMSG_SPACE(nr_fds * sizeof(int));
		p = zmalloc(cmsg_space);
		cmsg = (struct cmsghdr *) p;
		cmsg->cmsg_len = CMSG_LEN(nr_fds * sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), fds, nr_fds * sizeof(int));

		*buf = p;
		*len = cmsg_space;
	} else {
		/* SCM_CREDENTIALS — pass pid/uid/gid */
		struct ucred cred;

		switch (rand() % 4) {
		case 0:
			/* Real credentials */
			cred.pid = getpid();
			cred.uid = getuid();
			cred.gid = getgid();
			break;
		case 1:
			/* Random pid, real uid/gid */
			cred.pid = rand();
			cred.uid = getuid();
			cred.gid = getgid();
			break;
		case 2:
			/* All random */
			cred.pid = rand();
			cred.uid = rand();
			cred.gid = rand();
			break;
		case 3:
			/* Zero — exercise the "unset" path */
			cred.pid = 0;
			cred.uid = 0;
			cred.gid = 0;
			break;
		}

		cmsg_space = CMSG_SPACE(sizeof(struct ucred));
		p = zmalloc(cmsg_space);
		cmsg = (struct cmsghdr *) p;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_CREDENTIALS;
		memcpy(CMSG_DATA(cmsg), &cred, sizeof(struct ucred));

		*buf = p;
		*len = cmsg_space;
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
	.gen_msg = unix_gen_msg,
	.valid_triplets = unix_triplet,
	.nr_triplets = ARRAY_SIZE(unix_triplet),
};
