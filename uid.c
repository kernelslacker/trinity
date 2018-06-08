#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "child.h"
#include "debug.h"
#include "exit.h"
#include "params.h"
#include "trinity.h"
#include "uid.h"

uid_t orig_uid;
gid_t orig_gid;

uid_t nobody_uid;
gid_t nobody_gid;

void dump_uids(void)
{
	uid_t uid, euid, suid;
	gid_t gid, egid, sgid;

	getresuid(&uid, &euid, &suid);
	getresgid(&gid, &egid, &sgid);

	outputstd("initial uid:%u gid:%u euid:%u egid:%u suid:%u sgid:%u\n",
		uid, gid, euid, egid, suid, sgid);
}

bool drop_privs(struct childdata *child)
{
	if (setresgid(nobody_gid, nobody_gid, nobody_gid) < 0) {
		output(0, "Error setting nobody gid (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setgroups(0, NULL) == -1) {
		;
	}

	if (setresuid(nobody_uid, nobody_uid, nobody_uid) < 0) {
		output(0, "Error setting nobody uid (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

//	debugf("set uid to %u and gid to %d (nobody)\n", nobody_uid, nobody_gid);
	child->dropped_privs = TRUE;
	return TRUE;
}

void init_uids(void)
{
	struct passwd *passwd;

	orig_uid = getuid();
	orig_gid = getgid();

	if (dropprivs == FALSE)
		return;

	passwd = getpwnam("nobody");
	if (passwd == NULL) {
		outputerr("Error getting nobody pwent (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	nobody_uid = passwd->pw_uid;
	nobody_gid = passwd->pw_gid;
}


void do_uid0_check(void)
{
	unsigned int i;

	/* if we're already unprivileged, then don't worry. */
	if (orig_uid != 0)
		return;

	if (dangerous == TRUE) {
		outputstd("DANGER: RUNNING AS ROOT.\n");
		outputstd("Unless you are running in a virtual machine, this could cause serious problems such as overwriting CMOS\n");
		outputstd("or similar which could potentially make this machine unbootable without a firmware reset.\n");
		outputstd("You might want to check out running with --dropprivs (currently experimental).\n\n");
	} else {

		if (dropprivs == FALSE) {
			outputstd("Don't run as root (or pass --dangerous, or --dropprivs if you know what you are doing).\n");
			exit(EXIT_FAILURE);
		} else {
			outputstd("--dropprivs is still in development, and really shouldn't be used unless you're helping development. Expect crashes.\n");
			outputstd("Going to run as user nobody (uid:%d gid:%d)\n", nobody_uid, nobody_gid);
		}
	}

	if (clowntown == TRUE) {
		printf("THIS CLOWN GOES TO 11.\n");
		return;
	}

	outputstd("ctrl-c now unless you really know what you are doing.\n");
	for (i = 10; i > 0; i--) {
		outputstd("Continuing in %u seconds.\r", i);
		(void)fflush(stdout);
		sleep(1);
	}
}

void check_uid(void)
{
	uid_t myuid;

	/* If we were root, then obviously setuid() will change us, so don't even check. */
	if (orig_uid == 0)
		return;

	myuid = getuid();

	/* we should be 'nobody' if we ran with --dropprivs */
	if (dropprivs == TRUE) {
		if (myuid == nobody_uid)
			return;
		else
			goto changed;
	}

	if (myuid != orig_uid) {

changed:
		/* unshare() can change us to /proc/sys/kernel/overflowuid */
		if (myuid == 65534)
			return;

		output(0, "uid changed! Was: %u, now %u\n", orig_uid, myuid);

		panic(EXIT_UID_CHANGED);
		_exit(EXIT_FAILURE);
	}
}
