/*
 * Self-check for the getsockname and getpeername re-call oracles: each runs
 * its sanitiser and post handler as shipped on sockets of the test's own,
 * handed the address the fuzzed call answered, and counts the anomalies its
 * sampled re-call reports.  A RedQueen pin can hand the kernel another fd
 * than the sanitiser drew, and the re-call has to ask the socket the kernel
 * answered for.  An IPv6 socket's address is compared, its port not.  Only
 * a socket of the child's own pool is judged.
 */

#include <netinet/in.h>
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
#include "objects.h"		/* struct object */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "socketinfo.h"		/* struct socketinfo */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_getsockname, syscall_getpeername */
#include "utils.h"		/* ARRAY_SIZE */

extern bool fake_socketinfo_fds;		/* post_oracle_test.c */
extern struct object *(*fake_find_local_object_by_fd)(enum objecttype type,
						      int fd);	/* fake_objects.c */

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
					const void *answer, socklen_t len)
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

/* The child's own pool, as find_local_object_by_fd() answers: every socket
 * of the test's but @shared_fd, which stands for one of the parent's. */
static int shared_fd = -1;

static struct object *own_socket(enum objecttype type, int fd)
{
	static struct object obj;

	if (type != OBJ_FD_SOCKET || fd == shared_fd)
		return NULL;
	return &obj;
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

/* A datagram socket bound to the IPv6 loopback, its name as getsockname()
 * gives it in @addr and @addrlen, or -1 on a host without IPv6. */
static int bound_inet6_socket(struct sockaddr_in6 *addr, socklen_t *addrlen)
{
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr = in6addr_loopback;
	if (bind(fd, (struct sockaddr *) addr, sizeof(*addr)) != 0) {
		close(fd);
		return -1;
	}
	*addrlen = sizeof(*addr);
	if (getsockname(fd, (struct sockaddr *) addr, addrlen) != 0)
		BUG("sockname recall: cannot read an IPv6 socket's name back");
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
	struct sockaddr_in6 addr6, other6;
	struct sockaddr_un addr_a, addr_b;
	socklen_t len_a, len_b, len6;
	char name[32];
	int a, b, to_a, to_b, v6;

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
	v6 = bound_inet6_socket(&addr6, &len6);

	fake_socketinfo_fds = true;
	fake_find_local_object_by_fd = own_socket;
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
	/* Every child holds a socket of the parent's, and a sibling can
	 * rename one between the two calls. */
	shared_fd = b;
	check("getsockname: a call on a socket siblings share was judged",
	      sockname_anomalies(&syscall_getsockname,
				 &shm->stats.oracle.getsockname_oracle_anomalies,
				 a, b, &addr_a, len_a) == 0);
	shared_fd = -1;
	/* The local name of an IPv6 socket holds still between two calls
	 * too; its address, not its port, is what the oracle compares. */
	if (v6 >= 0) {
		other6 = addr6;
		other6.sin6_addr.s6_addr[15] ^= 0x02;
		check("getsockname: an IPv6 socket answering its own name was reported",
		      sockname_anomalies(&syscall_getsockname,
					 &shm->stats.oracle.getsockname_oracle_anomalies,
					 v6, v6, &addr6, len6) == 0);
		check("getsockname: an IPv6 socket answering another address was not reported",
		      sockname_anomalies(&syscall_getsockname,
					 &shm->stats.oracle.getsockname_oracle_anomalies,
					 v6, v6, &other6, len6) > 0);
		close(v6);
	}
	fake_find_local_object_by_fd = NULL;
	fake_socketinfo_fds = false;

	close(to_a);
	close(to_b);
	close(a);
	close(b);

	if (failed != 0)
		BUG("a socket name re-call misjudged a call");
}
