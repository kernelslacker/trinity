#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "log.h"
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

	outputstd("initial uid:%d gid:%d euid:%d egid:%d suid:%d sgid:%d\n",
		uid, gid, euid, egid, suid, sgid);
}

void drop_privs(void)
{
	if (setresgid(nobody_gid, nobody_gid, nobody_gid) < 0) {
		outputerr("Error setting nobody gid (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setgroups(0, NULL) == -1) {
		outputerr("Error dropping supplemental groups (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setresuid(nobody_uid, nobody_uid, nobody_uid) < 0) {
		outputerr("Error setting nobody uid (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	outputstd("set uid to %d and gid to %d (nobody)\n", nobody_uid, nobody_gid);
}

void init_uids(void)
{
	struct passwd *passwd;

	orig_uid = getuid();
	orig_gid = getgid();

	passwd = getpwnam("nobody");
	if (passwd == NULL) {
		outputerr("Error getting nobody pwent (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	nobody_uid = passwd->pw_uid;
	nobody_gid = passwd->pw_gid;
}
