/*
 * Self-check for setsockopt's sanitiser: an option that reads its optval
 * fails a NULL one with -EFAULT in copy_from_sockptr(), before its handler
 * runs, so the call gets the buffer the builders filled all but now and
 * then; a level the socket does not answer is -ENOPROTOOPT, so a unix
 * socket's curated draws keep to SOL_SOCKET all but now and then; and a
 * filter's instructions are freed on every path.
 */

#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/filter.h>	/* struct sock_fprog */

#include "debug.h"		/* BUG */
#include "deferred-free.h"	/* deferred_free_flush */
#include "net.h"		/* struct socketinfo, struct sockopt */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_setsockopt */

extern bool fake_random_fd_empty;	/* fake_stubs.c */
extern bool fake_zmalloc_tracks;	/* fake_stubs.c */

#define SETSOCKOPT_ROUNDS	2000
#define FILTER_ROUNDS		30000

/* The filter bpf_gen_filter() last made, its instructions, and whether
 * each has been handed to free() since. */
static struct sock_fprog *last_filter;
static struct sock_filter *last_insns;
static bool filter_freed, insns_freed;

void __real_bpf_gen_filter(unsigned long **addr, unsigned long *addrlen);
void __wrap_bpf_gen_filter(unsigned long **addr, unsigned long *addrlen);
void __wrap_bpf_gen_filter(unsigned long **addr, unsigned long *addrlen)
{
	__real_bpf_gen_filter(addr, addrlen);
	last_filter = (struct sock_fprog *) *addr;
	last_insns = last_filter != NULL ? last_filter->filter : NULL;
	filter_freed = false;
	insns_freed = false;
}

void __real_free(void *p);
void __wrap_free(void *p);
void __wrap_free(void *p)
{
	if (p != NULL && p == last_filter)
		filter_freed = true;
	if (p != NULL && p == last_insns)
		insns_freed = true;
	__real_free(p);
}

void __real_do_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void __real_release_sockopt_optval(struct sockopt *so);

/* An SO_ATTACH_FILTER optval is a sock_fprog whose instructions are a
 * second allocation, which the release paths free by the option's name:
 * a call handed a NULL optval, or the filter under another name, must
 * still give both back. */
static void filters_freed_whole(struct socket_triplet *triplet)
{
	unsigned int i, built = 0;

	fake_zmalloc_tracks = true;
	for (i = 0; i < FILTER_ROUNDS; i++) {
		struct sockopt so = { 0, 0, 0, 0 };

		last_filter = NULL;
		__real_do_setsockopt(&so, triplet);
		__real_release_sockopt_optval(&so);
		if (last_filter == NULL)
			continue;
		built++;
		deferred_free_flush();
		if (!filter_freed || !insns_freed)
			BUG("setsockopt: a filter's sock_fprog is not freed whole");
	}
	deferred_free_flush();
	fake_zmalloc_tracks = false;

	if (built == 0)
		BUG("setsockopt: no draw built a filter");
}

/* Runs the sanitiser over a socket of the given shape: how many calls
 * got a NULL optval, and how many a level other than SOL_SOCKET. */
static void draw_options(const struct socket_triplet *triplet,
			 unsigned int *unfilled, unsigned int *not_socket_level)
{
	struct socketinfo si;
	unsigned int i;

	memset(&si, 0, sizeof(si));
	si.triplet = *triplet;
	si.fd = -1;
	*unfilled = 0;
	*not_socket_level = 0;

	/* One call in a thousand asks the fd pool for any fd instead of
	 * the socket's: there is none.  The sanitiser frees what it
	 * replaces, and the post handler what it leaves, through the
	 * deferred-free paths, which free only tracked allocations. */
	fake_random_fd_empty = true;
	fake_zmalloc_tracks = true;
	for (i = 0; i < SETSOCKOPT_ROUNDS; i++) {
		struct syscallrecord rec;

		memset(&rec, 0, sizeof(rec));
		rec.entry = &syscall_setsockopt;
		rec.a1 = (unsigned long) &si;
		syscall_setsockopt.sanitise(&rec);
		if (rec.a4 == 0)
			(*unfilled)++;
		if (rec.a2 != SOL_SOCKET)
			(*not_socket_level)++;
		syscall_setsockopt.post(&rec);
	}
	deferred_free_flush();
	fake_zmalloc_tracks = false;
	fake_random_fd_empty = false;
}

void setsockopt_self_check(void);
void setsockopt_self_check(void)
{
	struct socket_triplet tcp = {
		.family = PF_INET, .type = SOCK_STREAM, .protocol = IPPROTO_TCP,
	};
	struct socket_triplet unix_stream = {
		.family = PF_UNIX, .type = SOCK_STREAM | SOCK_CLOEXEC,
	};
	unsigned int unfilled, not_socket_level;

	draw_options(&tcp, &unfilled, &not_socket_level);
	if (unfilled == 0 || unfilled > SETSOCKOPT_ROUNDS / 8)
		BUG("setsockopt: a NULL optval is drawn too often, or never");

	draw_options(&unix_stream, &unfilled, &not_socket_level);
	if (not_socket_level > SETSOCKOPT_ROUNDS * 2 / 5)
		BUG("setsockopt: a unix socket is mostly drawn levels it does not answer");

	filters_freed_whole(NULL);
	filters_freed_whole(&tcp);
}
