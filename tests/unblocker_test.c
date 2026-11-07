/*
 * Self-check for the accept unblocker (net/unblocker.c): its connector
 * takes the listener's own socket type, so a unix SOCK_SEQPACKET
 * listener, which a SOCK_STREAM connect cannot reach (an abstract name's
 * lookup is hashed on the type and misses it), gets a connection queued
 * for its accept().
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "socketinfo.h"		/* struct socketinfo */

/* dup_pool_test.c wraps the connector for the sanitisers that fire it. */
void __real_accept_unblocker_fire(int fd, const struct socketinfo *si);

void unblocker_self_check(void);
void unblocker_self_check(void)
{
	struct sockaddr_un sun;
	socklen_t len;
	int fd, afd;

	/* An abstract name, so nothing is left on disk. */
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path + 1, sizeof(sun.sun_path) - 1,
		 "trinity-unblocker-test-%d", (int) getpid());
	len = offsetof(struct sockaddr_un, sun_path) + 1 +
	      strlen(sun.sun_path + 1);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0 || bind(fd, (struct sockaddr *) &sun, len) != 0 ||
	    listen(fd, 4) != 0)
		BUG("unblocker: cannot make a SOCK_SEQPACKET listener");

	__real_accept_unblocker_fire(fd, NULL);

	afd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (afd < 0)
		BUG("unblocker: a SOCK_SEQPACKET listener gets no connection");
	close(afd);
	close(fd);
}
