/*
 * Self-check for the sockmap_fin childop (childops/net/sockmap-fin.c).
 * bpf() is answered through landlock_test.c's syscall() hook, which keeps
 * no map, so the TCP pair is real and runs as plain TCP.  The op links
 * the pooled program to the pooled map as a verdict before any socket
 * goes in, puts in an established end of the pair with nothing queued
 * yet, under a key below max_entries and a value of the map's size, and
 * leaves that end, of which the hook keeps a copy, read through to the
 * FIN.  A link refused with EBUSY still has a verdict on the map; one
 * refused otherwise, or no pooled map or program, puts nothing in.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/tcp.h>		/* struct tcp_info with tcpi_bytes_received */

#include "bpf.h"
#include "child.h"		/* struct childdata */
#include "child-api.h"		/* sockmap_fin, CHILD_OP_SOCKMAP_FIN */
#include "debug.h"		/* BUG */

#ifdef USE_BPF
extern bool (*fake_syscall)(long number, const unsigned long a[6], long *ret);	/* landlock_test.c */
extern int (*fake_get_rand_bpf_map_fd_of_types)(const unsigned int *map_types,
						 unsigned int n_types);	/* fake_fds.c */
extern int (*fake_get_rand_bpf_prog_fd_of_type)(unsigned int prog_type);	/* fake_fds.c */

#define MAP_FD		70
#define PROG_FD		71
#define MAX_ENTRIES	16
#define RUNS		16

/* tcpi_state of an established socket (include/net/tcp_states.h). */
#define STATE_ESTABLISHED	1

/* What the hook answers with, and what it saw of the op's calls. */
static struct {
	unsigned int map_type;
	unsigned int value_size;
	int link_errno;
	unsigned int calls, links, updates;
	int link_fd;
	int inserted;
} hook;

static int pooled_map(const unsigned int *map_types, unsigned int n_types)
{
	unsigned int i;

	for (i = 0; i < n_types; i++) {
		if (map_types[i] == hook.map_type)
			return MAP_FD;
	}
	return -1;
}

static int pooled_prog(unsigned int prog_type)
{
	return prog_type == BPF_PROG_TYPE_SK_SKB ? PROG_FD : -1;
}

static void check_link(const union bpf_attr *attr)
{
	if (attr->link_create.prog_fd != PROG_FD ||
	    attr->link_create.target_fd != MAP_FD)
		BUG("sockmap_fin: linked something other than the pooled program to the pooled map");
	if (attr->link_create.attach_type != BPF_SK_SKB_STREAM_VERDICT &&
	    attr->link_create.attach_type != BPF_SK_SKB_VERDICT)
		BUG("sockmap_fin: linked the program as something other than a verdict");
	if (attr->link_create.flags != 0)
		BUG("sockmap_fin: link flags, which sock_map_link_create() refuses");
}

/* The socket an update names: an established TCP end with nothing
 * queued on it yet, kept as a dup for the check after the op. */
static void check_update(const union bpf_attr *attr)
{
	const void *value = (const void *) (uintptr_t) attr->value;
	struct tcp_info ti;
	socklen_t len = sizeof(ti);
	char c;
	int fd;

	if (hook.links == 0)
		BUG("sockmap_fin: a socket went in before a verdict was linked");
	if (attr->map_fd != MAP_FD || attr->flags != BPF_ANY)
		BUG("sockmap_fin: an update to another map, or with flags");
	if (*(const uint32_t *) (uintptr_t) attr->key >= MAX_ENTRIES)
		BUG("sockmap_fin: a key past max_entries");
	fd = hook.value_size == sizeof(uint32_t) ?
		(int) *(const uint32_t *) value : (int) *(const uint64_t *) value;
	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0 ||
	    ti.tcpi_state != STATE_ESTABLISHED)
		BUG("sockmap_fin: the value names no established TCP socket");
	if (recv(fd, &c, 1, MSG_PEEK | MSG_DONTWAIT) != -1 || errno != EAGAIN)
		BUG("sockmap_fin: data was queued before the socket went in");
	hook.inserted = dup(fd);
	if (hook.inserted < 0)
		BUG("sockmap_fin: dup failed");
}

static bool answer_bpf(long number, const unsigned long a[6], long *ret)
{
	const union bpf_attr *attr = (const union bpf_attr *) a[1];

	if (number != __NR_bpf)
		return false;
	hook.calls++;
	switch (a[0]) {
	case BPF_OBJ_GET_INFO_BY_FD: {
		struct bpf_map_info *info =
			(struct bpf_map_info *) (uintptr_t) attr->info.info;

		if (attr->info.bpf_fd != MAP_FD)
			BUG("sockmap_fin: asked about a map it was not given");
		memset(info, 0, attr->info.info_len);
		info->type = hook.map_type;
		info->key_size = sizeof(uint32_t);
		info->value_size = hook.value_size;
		info->max_entries = MAX_ENTRIES;
		*ret = 0;
		return true;
	}
	case BPF_LINK_CREATE:
		check_link(attr);
		hook.links++;
		if (hook.link_errno != 0) {
			*ret = -hook.link_errno;
			return true;
		}
		hook.link_fd = eventfd(0, EFD_CLOEXEC);
		if (hook.link_fd < 0)
			BUG("sockmap_fin: eventfd failed");
		*ret = hook.link_fd;
		return true;
	case BPF_MAP_UPDATE_ELEM:
		check_update(attr);
		hook.updates++;
		*ret = 0;
		return true;
	default:
		BUG("sockmap_fin: a bpf() command the op has no use for");
	}
}

/* Run the op RUNS times against a map of @map_type and @value_size,
 * with the link refused with @link_errno when it is set. */
static void run_op(unsigned int map_type, unsigned int value_size, int link_errno)
{
	static struct childdata child;
	unsigned int i;

	memset(&hook, 0, sizeof(hook));
	hook.map_type = map_type;
	hook.value_size = value_size;
	hook.link_errno = link_errno;
	child.op_type = CHILD_OP_SOCKMAP_FIN;

	for (i = 0; i < RUNS; i++) {
		struct tcp_info ti;
		socklen_t len = sizeof(ti);
		char c;

		hook.link_fd = -1;
		hook.inserted = -1;
		sockmap_fin(&child);

		if (hook.link_fd >= 0 && fcntl(hook.link_fd, F_GETFD) != -1)
			BUG("sockmap_fin: the link was left open");
		if (hook.inserted < 0)
			continue;
		/* What is left on the inserted end: end of file, after a
		 * peer that sent something.  bytes_received counts sequence
		 * space, the FIN's one included (tcp_rcv_nxt_update()). */
		if (recv(hook.inserted, &c, 1, MSG_DONTWAIT) != 0)
			BUG("sockmap_fin: the inserted end was not read through to the FIN");
		if (getsockopt(hook.inserted, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0 ||
		    ti.tcpi_bytes_received < 2)
			BUG("sockmap_fin: the peer sent nothing before its FIN");
		close(hook.inserted);
	}
}
#endif

void sockmap_fin_self_check(void);
void sockmap_fin_self_check(void)
{
#ifdef USE_BPF
	fake_syscall = answer_bpf;
	fake_get_rand_bpf_map_fd_of_types = pooled_map;
	fake_get_rand_bpf_prog_fd_of_type = pooled_prog;

	run_op(BPF_MAP_TYPE_SOCKMAP, sizeof(uint64_t), 0);
	if (hook.updates != RUNS)
		BUG("sockmap_fin: a pooled sockmap did not get the socket");
	run_op(BPF_MAP_TYPE_SOCKHASH, sizeof(uint32_t), 0);
	if (hook.updates != RUNS)
		BUG("sockmap_fin: a pooled sockhash did not get the socket");
	run_op(BPF_MAP_TYPE_SOCKMAP, sizeof(uint64_t), EBUSY);
	if (hook.updates != RUNS)
		BUG("sockmap_fin: a verdict another link holds kept the socket out");
	run_op(BPF_MAP_TYPE_SOCKMAP, sizeof(uint64_t), EINVAL);
	if (hook.links != RUNS || hook.updates != 0)
		BUG("sockmap_fin: a socket went in with no verdict linked");
	run_op(BPF_MAP_TYPE_DEVMAP, sizeof(uint64_t), 0);
	if (hook.calls != 0)
		BUG("sockmap_fin: it called bpf() with no pooled sockmap");

	fake_syscall = NULL;
	fake_get_rand_bpf_map_fd_of_types = NULL;
	fake_get_rand_bpf_prog_fd_of_type = NULL;
#endif
}
