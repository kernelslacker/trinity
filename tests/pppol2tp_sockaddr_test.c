/*
 * Self-check for the PPPoL2TP sockaddrs: pppol2tp_connect()
 * (net/l2tp/l2tp_ppp.c) makes a tunnel only when both session ids are 0,
 * over the UDP socket the fd names, and otherwise wants a tunnel that the
 * ids name, so most connects carry the socket the picker hands out and
 * small ids, about half of them no session.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/if_ether.h>	/* ETH_ALEN, for if_pppox.h */
#include <linux/if_pppox.h>

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_pppol2tp, L2TP_ID_MAX */

extern int fake_socket_fd;	/* fake_fds.c */
extern int fake_random_fd;	/* fake_stubs.c */
extern bool fake_pid_draws;	/* dup_pool_test.c */

#define PPPOL2TP_ROUNDS		4000
#define PPPOL2TP_UDP_FD		37
#define PPPOL2TP_OTHER_FD	38

#define PPPOL2TP_IDS(sa)						\
	do {								\
		fd = (sa)->pppol2tp.fd;					\
		tunnel = (sa)->pppol2tp.s_tunnel;			\
		session = (sa)->pppol2tp.s_session;			\
		peer_session = (sa)->pppol2tp.d_session;		\
	} while (0)

void pppol2tp_sockaddr_self_check(void);
void pppol2tp_sockaddr_self_check(void)
{
	unsigned int i, l2tp = 0, manage = 0, join = 0;

	fake_socket_fd = PPPOL2TP_UDP_FD;
	fake_random_fd = PPPOL2TP_OTHER_FD;
	fake_pid_draws = true;
	for (i = 0; i < PPPOL2TP_ROUNDS; i++) {
		struct sockaddr *addr = NULL;
		socklen_t len = 0;
		unsigned int tunnel, session, peer_session;
		int fd;

		proto_pppol2tp.gen_sockaddr(NULL, &addr, &len);
		switch (len) {
		case sizeof(struct sockaddr_pppol2tp):
			PPPOL2TP_IDS((const struct sockaddr_pppol2tp *) addr);
			break;
#ifdef USE_PPPOL2TPIN6
		case sizeof(struct sockaddr_pppol2tpin6):
			PPPOL2TP_IDS((const struct sockaddr_pppol2tpin6 *) addr);
			break;
		case sizeof(struct sockaddr_pppol2tpv3in6):
			PPPOL2TP_IDS((const struct sockaddr_pppol2tpv3in6 *) addr);
			break;
#endif
#ifdef USE_PPPOL2TPV3
		case sizeof(struct sockaddr_pppol2tpv3):
			PPPOL2TP_IDS((const struct sockaddr_pppol2tpv3 *) addr);
			break;
#endif
		default:
			/* PPPoE or PPTP */
			free(addr);
			continue;
		}
		free(addr);

		l2tp++;
		if (fd != PPPOL2TP_UDP_FD || tunnel == 0 || tunnel > L2TP_ID_MAX)
			continue;
		if (session == 0 && peer_session == 0)
			manage++;
		else if (session <= L2TP_ID_MAX && peer_session <= L2TP_ID_MAX)
			join++;
	}
	fake_socket_fd = -1;
	fake_random_fd = -1;
	fake_pid_draws = false;

	if (manage < l2tp / 4)
		BUG("pppol2tp: a connect that can make a tunnel is rare");
	if (join < l2tp / 4)
		BUG("pppol2tp: a connect that names a tunnel and session a connect made is rare");
}
