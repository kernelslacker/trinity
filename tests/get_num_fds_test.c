/*
 * Self-check for get_num_fds() (utils/utils.c), the parent's count of
 * its own open fds that spawn_child() weighs against RLIMIT_NOFILE
 * before every fork.
 */

#include <fcntl.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "utils.h"		/* get_num_fds */

#define NR_EXTRA	3

/* The count follows the fds the process holds: it sees fds opened and
 * closed.  The directory handle it opens to count with is in every
 * count, so only differences mean anything. */
static void count_follows_open_fds(void)
{
	int fds[NR_EXTRA];
	int base = get_num_fds();
	unsigned int i;

	if (base < 1)
		BUG("get_num_fds: did not count even its own directory handle");

	for (i = 0; i < NR_EXTRA; i++) {
		fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (fds[i] < 0)
			BUG("get_num_fds: cannot open /dev/null");
	}
	if (get_num_fds() != base + NR_EXTRA)
		BUG("get_num_fds: did not see the fds opened");

	for (i = 0; i < NR_EXTRA; i++)
		close(fds[i]);
	if (get_num_fds() != base)
		BUG("get_num_fds: did not see the fds closed");
}

void get_num_fds_self_check(void);
void get_num_fds_self_check(void)
{
	count_follows_open_fds();
}
