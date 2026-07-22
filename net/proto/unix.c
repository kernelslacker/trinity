#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "net.h"
#include "fd.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "utils.h"
#include "pids.h"
#include "rnd.h"

#include "kernel/socket.h"
#ifndef SO_PASSSEC
#define SO_PASSSEC	34
#endif

#ifndef SCM_RIGHTS
#define SCM_RIGHTS	0x01
#endif

#ifndef SCM_CREDENTIALS
#define SCM_CREDENTIALS	0x02
#endif

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

/*
 * grammar_unix — coherent walk for AF_UNIX driven by the per-family
 * grammar dispatcher (net/socket-family-grammar.c).
 *
 * walk_setsockopts fires the SO_PASS* toggle sequence in order:
 *   SO_PASSCRED -> SO_PASSPIDFD -> SO_PASSSEC -> SO_PASSRIGHTS.
 * Each option is a boolean and the kernel's unix_set_peek_off /
 * unix_sock_table_lock paths run differently depending on which
 * combination of these flags is set when the cmsg-bearing sendmsg
 * lands.  Random per-syscall fuzzing rolls one of these per call —
 * the conditional probability of all four being toggled in a
 * coherent order on the same fd before sendmsg is effectively zero.
 *
 * gen_cmsg attaches a real SCM_RIGHTS or SCM_CREDENTIALS ancillary
 * block on the sendmsg.  Random fds are pulled from the global pool
 * for SCM_RIGHTS so the kernel's scm_fp_copy / unix_attach_fds paths
 * see live struct file references.  SCM_CREDENTIALS exercises
 * scm_check_creds across four credential shapes (real/random-pid/
 * fully-random/zero) — historically a bug-rich path under the
 * SO_PASS* combinations the walk has just installed.
 *
 * The random per-syscall sendmsg path no longer carries a
 * .gen_msg hook for AF_UNIX: the generic sanitiser in
 * syscalls/send.c copies gen_msg bytes into msg_iov[0], not
 * msg_control, so cmsg-shaped payload there is just opaque
 * iov bytes.  Real ancillary coverage comes from gen_cmsg
 * below, which writes directly into msg_control.
 */

static const unsigned int unix_pass_opts_seq[] = {
	SO_PASSCRED,
	SO_PASSPIDFD,
	SO_PASSSEC,
#ifdef SO_PASSRIGHTS
	SO_PASSRIGHTS,
#endif
};

static void unix_grammar_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_LOCAL;
	out->protocol = 0;
	switch (rnd_modulo_u32(3)) {
	case 0:	out->type = SOCK_STREAM;	break;
	case 1:	out->type = SOCK_SEQPACKET;	break;
	default:out->type = SOCK_DGRAM;		break;
	}
}

static void unix_grammar_configure_pre_bind(int fd, struct socket_triplet *t)
{
	int flags;

	(void) t;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void unix_grammar_walk_setsockopts(int fd, struct socket_triplet *t,
					  unsigned int n)
{
	unsigned int step;
	int val;

	(void) t;

	for (step = 0; step < n; step++) {
		unsigned int opt = unix_pass_opts_seq[step %
				    ARRAY_SIZE(unix_pass_opts_seq)];

		/* Alternate enable/disable so we exercise both the
		 * install and tear-down paths of each flag. */
		val = step & 1;
		(void) setsockopt(fd, SOL_SOCKET, opt, &val, sizeof(val));
	}
}

static void unix_grammar_gen_cmsg(int fd, struct socket_triplet *t,
				  struct msghdr *msg, void *cmsgbuf,
				  size_t cmsgbuflen)
{
	struct cmsghdr *cmsg;

	(void) fd;
	(void) t;

	if (RAND_BOOL()) {
		unsigned int nr_fds = RAND_RANGE(1, 4);
		int fds[4];
		unsigned int i;
		size_t need = CMSG_SPACE(nr_fds * sizeof(int));

		if (cmsgbuflen < need)
			return;

		for (i = 0; i < nr_fds; i++) {
			fds[i] = get_random_fd();
			/* No usable fd from the pool — skip the cmsg
			 * entirely.  Attaching fd 0 (stdin = /dev/null in
			 * children) via SCM_RIGHTS adds zero coverage. */
			if (fds[i] < 0)
				return;
		}

		msg->msg_control = cmsgbuf;
		msg->msg_controllen = need;

		cmsg = CMSG_FIRSTHDR(msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(nr_fds * sizeof(int));
		memcpy(CMSG_DATA(cmsg), fds, nr_fds * sizeof(int));
	} else {
		struct ucred cred;
		size_t need = CMSG_SPACE(sizeof(struct ucred));

		if (cmsgbuflen < need)
			return;

		switch (rnd_modulo_u32(4)) {
		case 0:
			cred.pid = mypid();
			cred.uid = getuid();
			cred.gid = getgid();
			break;
		case 1:
			cred.pid = rnd_u32();
			cred.uid = getuid();
			cred.gid = getgid();
			break;
		case 2:
			cred.pid = rnd_u32();
			cred.uid = rnd_u32();
			cred.gid = rnd_u32();
			break;
		default:
			cred.pid = 0;
			cred.uid = 0;
			cred.gid = 0;
			break;
		}

		msg->msg_control = cmsgbuf;
		msg->msg_controllen = need;

		cmsg = CMSG_FIRSTHDR(msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_CREDENTIALS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
		memcpy(CMSG_DATA(cmsg), &cred, sizeof(struct ucred));
	}
}

static bool unix_grammar_can_run(void)
{
	return sfg_can_run_default(PF_UNIX);
}

const struct socket_family_grammar grammar_unix = {
	.family			= PF_UNIX,
	.name			= "unix",
	.can_run		= unix_grammar_can_run,
	.pick_triplet		= unix_grammar_pick_triplet,
	.configure_pre_bind	= unix_grammar_configure_pre_bind,
	.walk_setsockopts	= unix_grammar_walk_setsockopts,
	.gen_cmsg		= unix_grammar_gen_cmsg,
};
