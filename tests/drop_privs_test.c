/*
 * Self-check that a child whose drop_privs() fails leaves through
 * trinity_exit(), without running the atexit handlers it inherited from
 * the parent.  A non-root caller cannot take gid 0, which provokes the
 * failure; root can, so the check is skipped as root.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "uid.h"		/* drop_privs, nobody_gid */
#include "utils.h"		/* waitpid_eintr */

static pid_t test_parent;
static int marker[2];
static bool armed;

static void note_child_atexit(void)
{
	ssize_t n;

	if (!armed || getpid() == test_parent)
		return;
	n = write(marker[1], "x", 1);
	(void) n;
}

void drop_privs_self_check(void);
void drop_privs_self_check(void)
{
	gid_t saved_gid = nobody_gid;
	int status;
	pid_t pid;
	char c;

	if (geteuid() == 0)
		return;

	test_parent = getpid();
	if (pipe2(marker, O_CLOEXEC) != 0 || atexit(note_child_atexit) != 0)
		BUG("drop_privs: cannot set up the atexit marker");
	armed = true;
	nobody_gid = 0;

	pid = fork();
	if (pid < 0)
		BUG("drop_privs: fork failed");
	if (pid == 0) {
		drop_privs();
		_exit(0);
	}
	close(marker[1]);
	if (waitpid_eintr(pid, &status, 0) != pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_FAILURE)
		BUG("drop_privs: the child did not fail to drop privileges");
	if (read(marker[0], &c, 1) != 0)
		BUG("drop_privs: a child ran the parent's atexit handlers");
	close(marker[0]);

	armed = false;
	nobody_gid = saved_gid;
}
