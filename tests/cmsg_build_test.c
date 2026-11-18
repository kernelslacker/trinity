/*
 * Self-check for the cmsg builder's family pools, with --cmsg-richness on.
 * AF_UNIX and AF_NETLINK parse control messages in __scm_send(), which
 * takes SCM_RIGHTS and SCM_CREDENTIALS at SOL_SOCKET and refuses any other
 * SOL_SOCKET type, so every message built for them carries those two and
 * nothing else.  INET, INET6 and PACKET hand SOL_SOCKET ones to
 * __sock_cmsg_send(), which also takes SO_PRIORITY, SO_MARK and
 * SCM_TS_OPT_ID.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cmsg-richness.h"	/* cmsg_richness_mode */
#include "cmsg_build.h"		/* enum cmsg_kind */
#include "debug.h"		/* BUG */
#include "kernel/socket.h"	/* SCM_TS_OPT_ID */
#include "sanitise.h"		/* get_writable_struct, get_random_pid_from_pool */

enum cmsg_kind __real_pick_cmsg_kind(unsigned int family);
int __real_cmsg_build(struct msghdr *m, enum cmsg_kind k, unsigned int family);

extern int fake_random_fd;	/* fake_stubs.c */
extern bool fake_lane_active;	/* lane_socket_test.c */

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

/*
 * __sock_cmsg_send() reads each of its u32 cmsgs only at CMSG_LEN(4).
 * SO_PRIORITY is drawn mostly at most TC_PRIO_INTERACTIVE (6), which
 * sk_set_prio_allowed() takes from anyone; SO_MARK, which needs
 * CAP_NET_RAW or CAP_NET_ADMIN over the socket's netns, only in a lane
 * child.
 */
static void check_sock_u32_cmsgs(unsigned int family, bool lane)
{
	unsigned int i, prio = 0, prio_open = 0, mark = 0, opt_id = 0;

	fake_lane_active = lane;
	for (i = 0; i < BUILDS * 4; i++) {
		struct msghdr m;
		struct cmsghdr *cmsg;

		memset(&m, 0, sizeof(m));
		if (__real_cmsg_build(&m, __real_pick_cmsg_kind(family),
				      family) != 0)
			continue;

		for (cmsg = CMSG_FIRSTHDR(&m); cmsg != NULL;
		     cmsg = CMSG_NXTHDR(&m, cmsg)) {
			uint32_t v;

			if (cmsg->cmsg_level != SOL_SOCKET ||
			    (cmsg->cmsg_type != SO_PRIORITY &&
			     cmsg->cmsg_type != SO_MARK &&
			     cmsg->cmsg_type != SCM_TS_OPT_ID))
				continue;
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(v)))
				BUG("cmsg_build: a u32 SOL_SOCKET cmsg is not CMSG_LEN(4) long");
			memcpy(&v, CMSG_DATA(cmsg), sizeof(v));
			if (cmsg->cmsg_type == SO_PRIORITY) {
				prio++;
				prio_open += v <= 6;
			} else if (cmsg->cmsg_type == SO_MARK) {
				mark++;
			} else {
				opt_id++;
			}
		}
	}
	fake_lane_active = false;

	if (prio == 0 || opt_id == 0)
		BUG("cmsg_build: SO_PRIORITY or SCM_TS_OPT_ID was never built");
	if (prio_open < prio / 2 || prio_open == prio)
		BUG("cmsg_build: SO_PRIORITY is not mostly one anyone may set, with others among them");
	if (lane ? mark == 0 : mark != 0)
		BUG("cmsg_build: SO_MARK is built outside a lane child, or never in one");
}

void cmsg_build_self_check(void);
void cmsg_build_self_check(void)
{
	static const unsigned int sock_families[] = {
		AF_INET, AF_INET6, AF_PACKET,
	};
	unsigned int i;

	if (get_writable_struct(1) == NULL)
		writable_pool_init();

	cmsg_richness_mode = CMSG_RICHNESS_ON;
	fake_random_fd = STDIN_FILENO;
	check_family(AF_UNIX);
	check_family(AF_NETLINK);
	for (i = 0; i < sizeof(sock_families) / sizeof(sock_families[0]); i++) {
		check_sock_u32_cmsgs(sock_families[i], false);
		check_sock_u32_cmsgs(sock_families[i], true);
	}
	fake_random_fd = -1;
	cmsg_richness_mode = CMSG_RICHNESS_OFF;
}
