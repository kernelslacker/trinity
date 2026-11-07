/*
 * Self-check for the userns-admin lane: a run asks for it when an active
 * entry in any of its tables wants it, and a lane child maps its uid to 0
 * in a user namespace of its own, which check_uid() has to take for what
 * it is, not for a root escalation.
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

#include "arch.h"		/* biarch */
#include "debug.h"		/* BUG */
#include "exit.h"		/* EXIT_UID_CHANGED */
#include "syscall.h"
#include "tables.h"		/* userns_lane_requested */
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

/*
 * Each table as sendmsg sits in it: the entry that asks for the lane, one
 * above an entry that does not.  Activation stamps an entry's
 * active_number, which is all the lookup reads.
 */
static struct syscall_runtime rt[2][2];
static struct syscallentry entries[2][2] = {
	{ { .name = "shutdown", .rt = &rt[0][0] },
	  { .name = "sendmsg", .userns_admin_lane = true, .rt = &rt[0][1] } },
	{ { .name = "shutdown", .rt = &rt[1][0] },
	  { .name = "sendmsg", .userns_admin_lane = true, .rt = &rt[1][1] } },
};
static const struct syscalltable tables[2][3] = {
	{ { NULL }, { &entries[0][0] }, { &entries[0][1] } },
	{ { NULL }, { &entries[1][0] }, { &entries[1][1] } },
};

/* Activates the entries @mask0 and @mask1 name in each table. */
static bool lane_requested_with(unsigned int mask0, unsigned int mask1)
{
	unsigned int i;

	for (i = 0; i < 2; i++) {
		rt[0][i].active_number = (mask0 >> i) & 1;
		rt[1][i].active_number = (mask1 >> i) & 1;
	}
	return userns_lane_requested();
}

static void lane_entry_lookup(void)
{
	biarch = true;
	syscalls_64bit = tables[0];
	syscalls_32bit = tables[1];
	max_nr_64bit_syscalls = 3;
	max_nr_32bit_syscalls = 3;
	if (!lane_requested_with(2, 0) || !lane_requested_with(0, 2) ||
	    !lane_requested_with(3, 3))
		BUG("userns lane: an active lane entry did not ask for the lane");
	if (lane_requested_with(1, 1) || lane_requested_with(0, 0))
		BUG("userns lane: a run without an active lane entry asked for it");

	biarch = false;
	syscalls = tables[0];
	max_nr_syscalls = 3;
	if (!lane_requested_with(2, 0))
		BUG("userns lane: an active lane entry did not ask for the lane");
	if (lane_requested_with(1, 2))
		BUG("userns lane: a uniarch run read the other table");

	/* Back to the empty tables fake_parent.c provides. */
	syscalls = NULL;
	syscalls_64bit = NULL;
	syscalls_32bit = NULL;
	max_nr_syscalls = 0;
	max_nr_64bit_syscalls = 0;
	max_nr_32bit_syscalls = 0;
}

void userns_lane_self_check(void);
void userns_lane_self_check(void)
{
	int status;

	lane_entry_lookup();

	status = check_uid_as_lane_root(true);

	if (status == NO_USERNS) {
		printf("(no unprivileged user namespaces, skipping check_uid) ");
		return;
	}
	if (status != 0)
		BUG("userns lane: check_uid() bailed on a lane child's uid 0");
	if (check_uid_as_lane_root(false) != EXIT_UID_CHANGED)
		BUG("userns lane: check_uid() let uid 0 pass outside the lane");
}
