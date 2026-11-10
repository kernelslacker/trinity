/*
 * sockmap_fin -- take a sockmap'd TCP socket through its peer's FIN with
 * data still queued, which the random-syscall path almost never lines up.
 * A pooled SK_SKB program is linked to a pooled sockmap or sockhash as
 * its verdict, one end of a TCP pair made here goes into the map, the
 * other end sends and shuts down, and the inserted end is read until the
 * FIN.  tcp_bpf_recvmsg_parser() (net/ipv4/tcp_bpf.c) finds the FIN in a
 * zero-length message of its own, whose copy fails, and is_next_msg_fin()
 * turns that into end of file.  The pair is the child's own, over its
 * loopback: the pooled sockets sit in the parent's netns and meet the
 * other children's calls.
 */

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "bpf.h"
#include "child.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "syscall-gate.h"
#include "utils-macros.h"	/* ARRAY_SIZE, RAND_ARRAY */

#ifdef USE_BPF
/* Waits, kept inside the 200 ms the looping childops hold to: the
 * handshake, then each read that finds the psock's queue still empty. */
#define PAIR_WAIT_MS	50
#define READ_WAIT_MS	10
#define READS		8

/*
 * A connected TCP pair over the child's loopback: *cfd connected to *afd,
 * which accept() took off the listener *lfd.  The connect does not block,
 * since a fuzzed netfilter rule in the child's netns can drop the
 * handshake.  False on any failure, lo down among them.
 */
static bool tcp_pair(int *lfd, int *cfd, int *afd, unsigned long *calls)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	struct pollfd pfd;
	int err = 0;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	(*calls)++;
	*lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (*lfd < 0)
		return false;
	(*calls)++;
	if (bind(*lfd, (struct sockaddr *) &sin, sizeof(sin)) != 0)
		return false;
	(*calls)++;
	if (listen(*lfd, 1) != 0)
		return false;
	(*calls)++;
	if (getsockname(*lfd, (struct sockaddr *) &sin, &len) != 0)
		return false;

	(*calls)++;
	*cfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (*cfd < 0)
		return false;
	(*calls)++;
	if (connect(*cfd, (struct sockaddr *) &sin, sizeof(sin)) != 0 &&
	    errno != EINPROGRESS)
		return false;
	pfd.fd = *cfd;
	pfd.events = POLLOUT;
	(*calls)++;
	if (poll(&pfd, 1, PAIR_WAIT_MS) != 1)
		return false;
	len = sizeof(err);
	(*calls)++;
	if (getsockopt(*cfd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0)
		return false;

	(*calls)++;
	*afd = accept4(*lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	return *afd >= 0;
}

/*
 * Put @in into the map, then send from @peer, shut it down and read @in
 * until the FIN.  False when the map would not take @in.  The key stays
 * below max_entries, past which a sockmap has no slot and a full
 * sockhash takes only a key it already holds; the value is the fd as a
 * u32 or a u64 by value_size.
 */
static bool insert_and_finish(int map_fd, const struct bpf_map_info *info,
			      int in, int peer, unsigned long *calls)
{
	static const char payload[] = "trinity sockmap fin";
	union bpf_attr attr;
	uint32_t key = rnd_modulo_u32(info->max_entries);
	uint32_t value32 = (uint32_t) in;
	uint64_t value64 = (uint64_t) in;
	char buf[64];
	unsigned int i;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (uintptr_t) &key;
	attr.value = info->value_size == sizeof(value32) ?
		(uintptr_t) &value32 : (uintptr_t) &value64;
	attr.flags = BPF_ANY;
	(*calls)++;
	if (trinity_raw_syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr,
				sizeof(attr)) != 0)
		return false;

	(*calls)++;
	if (send(peer, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL) < 0)
		return true;
	(*calls)++;
	if (shutdown(peer, SHUT_WR) != 0)
		return true;

	/*
	 * The data and then the FIN reach the psock's queue through the
	 * verdict, from softirq, so a read can come early: wait a little
	 * for each.
	 */
	for (i = 0; i < READS; i++) {
		struct pollfd pfd = { .fd = in, .events = POLLIN };
		ssize_t n;

		(*calls)++;
		n = recv(in, buf, sizeof(buf), MSG_DONTWAIT);
		if (n == 0 || (n < 0 && errno != EAGAIN))
			break;
		if (n < 0) {
			(*calls)++;
			(void) poll(&pfd, 1, READ_WAIT_MS);
		}
	}
	return true;
}

static void sockmap_fin_run(enum child_op_type op, bool valid_op,
			    unsigned long *calls)
{
	static const unsigned int sockmaps[] = {
		BPF_MAP_TYPE_SOCKMAP, BPF_MAP_TYPE_SOCKHASH,
	};
	static const unsigned int verdicts[] = {
		BPF_SK_SKB_STREAM_VERDICT, BPF_SK_SKB_VERDICT,
	};
	struct bpf_map_info info;
	union bpf_attr attr;
	int map_fd, prog_fd, link_fd = -1, lfd = -1, cfd = -1, afd = -1;
	bool swap;

	/* Only a root run's init pools either, and no child can make one. */
	map_fd = get_rand_bpf_map_fd_of_types(sockmaps, ARRAY_SIZE(sockmaps));
	prog_fd = get_rand_bpf_prog_fd_of_type(BPF_PROG_TYPE_SK_SKB);
	if (map_fd < 0 || prog_fd < 0)
		return;

	memset(&info, 0, sizeof(info));
	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = map_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uintptr_t) &info;
	(*calls)++;
	if (trinity_raw_syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr,
				sizeof(attr)) != 0 ||
	    info.key_size != sizeof(uint32_t) ||
	    (info.value_size != sizeof(uint32_t) &&
	     info.value_size != sizeof(uint64_t)) ||
	    info.max_entries == 0)
		return;

	/*
	 * tcp_bpf_update_proto() gives the socket the parser's recvmsg only
	 * if a verdict is on the map when the socket goes in.  EBUSY says
	 * one already is: another link holds this slot, or the other
	 * verdict type's.  Closing our link takes the verdict back off.
	 */
	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = prog_fd;
	attr.link_create.target_fd = map_fd;
	attr.link_create.attach_type = RAND_ARRAY(verdicts);
	(*calls)++;
	link_fd = trinity_raw_syscall(__NR_bpf, BPF_LINK_CREATE, &attr,
				      sizeof(attr));
	if (link_fd < 0 && errno != EBUSY)
		return;

	if (!tcp_pair(&lfd, &cfd, &afd, calls))
		goto out;
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	swap = RAND_BOOL();
	if (insert_and_finish(map_fd, &info, swap ? cfd : afd,
			      swap ? afd : cfd, calls) && valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

out:
	/* Closing the inserted end also takes it out of the map. */
	if (afd >= 0) {
		(*calls)++;
		close(afd);
	}
	if (cfd >= 0) {
		(*calls)++;
		close(cfd);
	}
	if (lfd >= 0) {
		(*calls)++;
		close(lfd);
	}
	if (link_fd >= 0) {
		(*calls)++;
		close(link_fd);
	}
}
#endif	/* USE_BPF */

bool sockmap_fin(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned long direct_calls = 0;

#ifdef USE_BPF
	sockmap_fin_run(op, valid_op, &direct_calls);
#endif
	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return true;
}
