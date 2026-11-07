/*
 * Self-check for the getsockname and getpeername re-call oracles: each runs
 * its sanitiser and post handler as shipped on sockets of the test's own,
 * handed the address the fuzzed call answered, and counts the anomalies its
 * sampled re-call reports.  A RedQueen pin can hand the kernel another fd
 * than the sanitiser drew, and the re-call has to ask the socket the kernel
 * answered for.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "deferred-free.h"	/* deferred_free_flush */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "socketinfo.h"		/* struct socketinfo */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_getsockname, syscall_getpeername */
#include "utils.h"		/* ARRAY_SIZE */

extern bool fake_socketinfo_fds;		/* post_oracle_test.c */

static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "sockname recall: %s\n", what);
	failed++;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

/* @entry's calls the sanitiser built on the socket @built, which the kernel
 * ran on @ran, each answering the @len bytes at @answer; *@counter counts
 * their anomalies. */
static unsigned long sockname_anomalies(struct syscallentry *entry,
					const unsigned long *counter,
					int built, int ran,
					const struct sockaddr_un *answer,
					socklen_t len)
{
	unsigned long before = *counter;
	static struct syscallrecord rec;
	struct socketinfo si = { .fd = built };
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int i, k;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) &si;
		entry->sanitise(&rec);

		memcpy((void *) rec.a2, answer, len);
		*(socklen_t *) rec.a3 = len;
		rec.a1 = (unsigned long) ran;
		/* The shadow __do_syscall() takes of what the kernel was handed. */
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec.arg_shadow[k] = *slots[k];
		rec.arg_snapshot_mask = entry->arg_snapshot_mask;
		rec.retval = 0;
		entry->post(&rec);
		/* The post handler hands the value-result buffers to deferred
		 * free, whose ring is short: drain it every call. */
		deferred_free_flush();
	}
	return *counter - before;
}

/* A datagram socket bound to the abstract name @name, its address as
 * getsockname() gives it in @addr and @addrlen. */
static int bound_socket(const char *name, struct sockaddr_un *addr,
			socklen_t *addrlen)
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	memcpy(addr->sun_path + 1, name, strlen(name));
	*addrlen = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 +
				strlen(name));
	if (fd < 0 || bind(fd, (struct sockaddr *) addr, *addrlen) != 0)
		BUG("sockname recall: cannot bind a socket");
	*addrlen = sizeof(*addr);
	if (getsockname(fd, (struct sockaddr *) addr, addrlen) != 0)
		BUG("sockname recall: cannot read a socket's name back");
	return fd;
}

/* A datagram socket connected to the one bound at @addr. */
static int connected_socket(const struct sockaddr_un *addr, socklen_t addrlen)
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	if (fd < 0 || connect(fd, (const struct sockaddr *) addr, addrlen) != 0)
		BUG("sockname recall: cannot connect a socket");
	return fd;
}

void sockname_recall_self_check(void);
void sockname_recall_self_check(void)
{
	struct sockaddr_un addr_a, addr_b;
	socklen_t len_a, len_b;
	char name[32];
	int a, b, to_a, to_b;

	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(page_size) == NULL)
		writable_pool_init();

	/* Two names of one length, the test's own. */
	snprintf(name, sizeof(name), "trinity-sockname-a-%d", (int) getpid());
	a = bound_socket(name, &addr_a, &len_a);
	snprintf(name, sizeof(name), "trinity-sockname-b-%d", (int) getpid());
	b = bound_socket(name, &addr_b, &len_b);
	to_a = connected_socket(&addr_a, len_a);
	to_b = connected_socket(&addr_b, len_b);

	fake_socketinfo_fds = true;
	check("getsockname: a call pinned onto another socket was judged on the first",
	      sockname_anomalies(&syscall_getsockname,
				 &shm->stats.oracle.getsockname_oracle_anomalies,
				 a, b, &addr_b, len_b) == 0);
	check("getsockname: a pinned call answering the first socket's name was not reported",
	      sockname_anomalies(&syscall_getsockname,
				 &shm->stats.oracle.getsockname_oracle_anomalies,
				 a, b, &addr_a, len_a) > 0);
	check("getpeername: a call pinned onto another socket was judged on the first",
	      sockname_anomalies(&syscall_getpeername,
				 &shm->stats.oracle.getpeername_oracle_anomalies,
				 to_a, to_b, &addr_b, len_b) == 0);
	check("getpeername: a pinned call answering the first socket's peer was not reported",
	      sockname_anomalies(&syscall_getpeername,
				 &shm->stats.oracle.getpeername_oracle_anomalies,
				 to_a, to_b, &addr_a, len_a) > 0);
	fake_socketinfo_fds = false;

	close(to_a);
	close(to_b);
	close(a);
	close(b);

	if (failed != 0)
		BUG("a socket name re-call asked the wrong socket");
}
