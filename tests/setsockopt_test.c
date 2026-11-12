/*
 * Self-check for setsockopt's sanitiser: an option that reads its optval
 * fails a NULL one with -EFAULT in copy_from_sockptr(), before its handler
 * runs, so the call gets the buffer the builders filled all but now and
 * then.
 */

#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "debug.h"		/* BUG */
#include "deferred-free.h"	/* deferred_free_flush */
#include "net.h"		/* struct socketinfo */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_setsockopt */

extern bool fake_random_fd_empty;	/* fake_stubs.c */
extern bool fake_zmalloc_tracks;	/* fake_stubs.c */

#define SETSOCKOPT_ROUNDS	2000

void setsockopt_self_check(void);
void setsockopt_self_check(void)
{
	struct socketinfo si;
	unsigned int i, unfilled = 0;

	memset(&si, 0, sizeof(si));
	si.triplet.family = PF_INET;
	si.triplet.type = SOCK_STREAM;
	si.triplet.protocol = IPPROTO_TCP;
	si.fd = -1;

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
			unfilled++;
		syscall_setsockopt.post(&rec);
	}
	deferred_free_flush();
	fake_zmalloc_tracks = false;
	fake_random_fd_empty = false;

	if (unfilled == 0 || unfilled > SETSOCKOPT_ROUNDS / 8)
		BUG("setsockopt: a NULL optval is drawn too often, or never");
}
