/*
 * Self-check for the userns-admin lane's identity: a lane child maps its
 * uid to 0 in a user namespace of its own, and check_uid() has to take
 * that 0 for what it is, not for a root escalation.
 */

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "exit.h"		/* EXIT_UID_CHANGED */
#include "uid.h"		/* check_uid, orig_uid, nobody_uid */
#include "utils.h"		/* waitpid_eintr */

extern bool fake_lane_active;	/* lane_socket_test.c */

/* How the helper exits when it cannot map itself to uid 0. */
#define NO_USERNS	77

/*
 * Map the caller's uid to 0 in a new user namespace, as
 * maybe_enter_userns_admin_lane() does, and run check_uid() there with the
 * lane flag at @in_lane.  Returns the helper's exit status, 0 if
 * check_uid() came back.
 */
static int check_uid_as_lane_root(bool in_lane)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("userns lane: fork failed");
	if (pid == 0) {
		uid_t uid = geteuid();
		char map[32];
		int fd, len;

		/* Don't outlive the test binary if the check aborts. */
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (unshare(CLONE_NEWUSER) != 0)
			_exit(NO_USERNS);
		len = snprintf(map, sizeof(map), "0 %u 1\n", (unsigned int) uid);
		fd = open("/proc/self/uid_map", O_WRONLY);
		if (fd < 0 || write(fd, map, (size_t) len) != len)
			_exit(NO_USERNS);
		close(fd);

		orig_uid = uid;
		nobody_uid = 65534;
		fake_lane_active = in_lane;
		check_uid();
		_exit(0);
	}
	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("userns lane: cannot reap the helper");
	if (!WIFEXITED(status))
		BUG("userns lane: the helper died");
	return WEXITSTATUS(status);
}

void userns_lane_self_check(void);
void userns_lane_self_check(void)
{
	int status = check_uid_as_lane_root(true);

	if (status == NO_USERNS) {
		printf("(no unprivileged user namespaces, skipping check_uid) ");
		return;
	}
	if (status != 0)
		BUG("userns lane: check_uid() bailed on a lane child's uid 0");
	if (check_uid_as_lane_root(false) != EXIT_UID_CHANGED)
		BUG("userns lane: check_uid() let uid 0 pass outside the lane");
}
