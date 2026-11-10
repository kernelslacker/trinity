/*
 * Self-check for the accept unblocker (net/unblocker.c): its connector
 * takes the listener's own socket type, so a unix SOCK_SEQPACKET
 * listener, which a SOCK_STREAM connect cannot reach (an abstract name's
 * lookup is hashed on the type and misses it), gets a connection queued
 * for its accept(); and it passes over a listener in another netns that a
 * connect from its own cannot reach, counting it.
 */

#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "shm.h"
#include "socketinfo.h"		/* struct socketinfo */
#include "utils.h"		/* waitpid_eintr */

#include "kernel/socket.h"	/* SO_NETNS_COOKIE */

/* dup_pool_test.c wraps the connector for the sanitisers that fire it. */
void __real_accept_unblocker_fire(int fd, const struct socketinfo *si);

/* How the netns helper exits when it cannot run the check, or when the
 * connector got a listener wrong. */
#define NO_NETNS	77
#define NETNS_FIRED	1
#define NETNS_MISSED	2

static int listen_on(int type, const void *addr, socklen_t len)
{
	const struct sockaddr *sa = addr;
	int fd = socket(sa->sa_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

	if (fd < 0 || bind(fd, sa, len) != 0 || listen(fd, 4) != 0)
		BUG("unblocker: cannot make a listener");
	return fd;
}

/* An abstract name, so nothing is left on disk. */
static socklen_t abstract_name(struct sockaddr_un *sun, const char *what)
{
	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_UNIX;
	snprintf(sun->sun_path + 1, sizeof(sun->sun_path) - 1,
		 "trinity-unblocker-%s-%d", what, (int) getpid());
	return offsetof(struct sockaddr_un, sun_path) + 1 +
	       strlen(sun->sun_path + 1);
}

/*
 * Make a TCP listener on 127.0.0.1, an abstract unix one and one bound to
 * @path, then unshare a netns, with a user namespace for the capability,
 * and fire the connector at each.  A SYN from the new netns finds nothing
 * listening on the TCP port there, and an abstract name is looked up in
 * the connector's netns alone, so both are passed over and counted; a
 * pathname is found through the filesystem, from any netns, so that
 * listener gets a connection queued.  Returns the helper's exit status.
 */
static int other_netns_status(const char *path)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("unblocker: fork failed");
	if (pid == 0) {
		struct accept_unblocker_stats *st = &shm->stats.accept_unblocker;
		struct sockaddr_in sin;
		struct sockaddr_un sun;
		socklen_t len = sizeof(uint64_t);
		uint64_t cookie;
		int inet, abstract, named, afd;

		/* Don't outlive the test binary if the check aborts. */
		prctl(PR_SET_PDEATHSIG, SIGKILL);

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		inet = listen_on(SOCK_STREAM, &sin, sizeof(sin));
		/* Without the cookie the connector cannot tell netns apart. */
		if (getsockopt(inet, SOL_SOCKET, SO_NETNS_COOKIE, &cookie, &len) != 0)
			_exit(NO_NETNS);
		abstract = listen_on(SOCK_STREAM, &sun, abstract_name(&sun, "netns"));
		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);
		named = listen_on(SOCK_STREAM, &sun, sizeof(sun));

		if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0)
			_exit(NO_NETNS);
		memset(st, 0, sizeof(*st));
		__real_accept_unblocker_fire(inet, NULL);
		__real_accept_unblocker_fire(abstract, NULL);
		if (st->other_netns_skipped != 2 || st->connects_fired != 0 ||
		    st->probe_failed != 0)
			_exit(NETNS_FIRED);
		__real_accept_unblocker_fire(named, NULL);
		afd = accept4(named, NULL, NULL, SOCK_CLOEXEC);
		if (st->connects_fired != 1 || afd < 0)
			_exit(NETNS_MISSED);
		_exit(0);
	}
	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("unblocker: cannot reap the netns helper");
	if (!WIFEXITED(status))
		BUG("unblocker: the netns helper died");
	return WEXITSTATUS(status);
}

static void other_netns_check(void)
{
	char dir[] = "/tmp/trinity-unblocker-test.XXXXXX";
	char path[sizeof(dir) + sizeof("/listener")];
	int status;

	if (mkdtemp(dir) == NULL)
		BUG("unblocker: mkdtemp failed");
	snprintf(path, sizeof(path), "%s/listener", dir);
	status = other_netns_status(path);
	unlink(path);
	rmdir(dir);

	if (status == NO_NETNS) {
		printf("(no network namespaces or netns cookies, skipping the netns check) ");
		return;
	}
	if (status == NETNS_FIRED)
		BUG("unblocker: the connector fired at a listener in another netns");
	if (status != 0)
		BUG("unblocker: the connector passed over a pathname listener in another netns");
}

void unblocker_self_check(void);
void unblocker_self_check(void)
{
	struct sockaddr_un sun;
	int fd, afd;

	fd = listen_on(SOCK_SEQPACKET, &sun, abstract_name(&sun, "test"));

	__real_accept_unblocker_fire(fd, NULL);

	afd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (afd < 0)
		BUG("unblocker: a SOCK_SEQPACKET listener gets no connection");
	close(afd);
	close(fd);

	other_netns_check();
}
