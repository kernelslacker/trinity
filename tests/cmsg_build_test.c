/*
 * Self-check for the cmsg builder's AF_UNIX and AF_NETLINK pools: both
 * families' sendmsg parse control messages in __scm_send(), which takes
 * SCM_RIGHTS and SCM_CREDENTIALS at SOL_SOCKET and refuses any other
 * SOL_SOCKET type, so with --cmsg-richness on, every message built for
 * them carries those two and nothing else.
 */

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cmsg-richness.h"	/* cmsg_richness_mode */
#include "cmsg_build.h"		/* enum cmsg_kind */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* get_writable_struct, get_random_pid_from_pool */

enum cmsg_kind __real_pick_cmsg_kind(unsigned int family);
int __real_cmsg_build(struct msghdr *m, enum cmsg_kind k, unsigned int family);

extern int fake_random_fd;	/* fake_stubs.c */

/* Messages built per family; one in four is the packer's. */
#define BUILDS	256

/* dispatch/pids.c is not linked; a ucred names this process. */
pid_t get_random_pid_from_pool(void)
{
	return getpid();
}

static void check_family(unsigned int family)
{
	unsigned int i, rights = 0, creds = 0;

	for (i = 0; i < BUILDS; i++) {
		struct msghdr m;
		struct cmsghdr *cmsg;

		/* With an fd to pass and the pool up, every draw builds. */
		memset(&m, 0, sizeof(m));
		if (__real_cmsg_build(&m, __real_pick_cmsg_kind(family),
				      family) != 0)
			BUG("cmsg_build: a draw for a __scm_send() family built nothing");

		for (cmsg = CMSG_FIRSTHDR(&m); cmsg != NULL;
		     cmsg = CMSG_NXTHDR(&m, cmsg)) {
			if (cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_RIGHTS)
				rights++;
			else if (cmsg->cmsg_level == SOL_SOCKET &&
				 cmsg->cmsg_type == SCM_CREDENTIALS)
				creds++;
			else
				BUG("cmsg_build: a cmsg __scm_send() does not take");
		}
	}
	if (rights == 0 || creds == 0)
		BUG("cmsg_build: SCM_RIGHTS or SCM_CREDENTIALS was never built");
}

void cmsg_build_self_check(void);
void cmsg_build_self_check(void)
{
	if (get_writable_struct(1) == NULL)
		writable_pool_init();

	cmsg_richness_mode = CMSG_RICHNESS_ON;
	fake_random_fd = STDIN_FILENO;
	check_family(AF_UNIX);
	check_family(AF_NETLINK);
	fake_random_fd = -1;
	cmsg_richness_mode = CMSG_RICHNESS_OFF;
}
