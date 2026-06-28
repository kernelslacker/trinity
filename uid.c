#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "debug.h"
#include "exit.h"
#include "params.h"
#include "shm.h"
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

	if (getresuid(&uid, &euid, &suid) == -1) {
		perror("getresuid");
		return;
	}
	if (getresgid(&gid, &egid, &sgid) == -1) {
		perror("getresgid");
		return;
	}

	outputstd("initial uid:%u gid:%u euid:%u egid:%u suid:%u sgid:%u\n",
		uid, gid, euid, egid, suid, sgid);
}

void drop_privs(void)
{
	if (setresgid(nobody_gid, nobody_gid, nobody_gid) < 0) {
		output(0, "Error setting nobody gid (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setgroups(0, NULL) == -1) {
		output(0, "Error setting setgroups (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setresuid(nobody_uid, nobody_uid, nobody_uid) < 0) {
		output(0, "Error setting nobody uid (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void init_uids(void)
{
	struct passwd *passwd;

	orig_uid = getuid();
	orig_gid = getgid();

	if (orig_uid != 0)
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

	/* Already unprivileged; no UID/GID drop is needed. */
	if (orig_uid != 0)
		return;

	if (dangerous == true) {
		outputstd("DANGER: RUNNING AS ROOT.\n");
		outputstd("Unless you are running in a virtual machine, this could cause serious problems such as overwriting CMOS\n");
		outputstd("or similar which could potentially make this machine unbootable without a firmware reset.\n");
	} else {
		output(0, "Detected running as root -- children will drop privileges to nobody (uid:%u gid:%u)\n",
			nobody_uid, nobody_gid);
	}

	if (clowntown == true) {
		output(0, "THIS CLOWN GOES TO 11.\n");
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
	uid_t myuid, expected_uid;
	uid_t overflowuid = 65534;
	FILE *fp;

	/* init_uids() loaded nobody_uid when we started as root; child
	 * init then dropped to it.  Otherwise we expect to still be the
	 * uid we were invoked under. */
	expected_uid = (orig_uid == 0) ? nobody_uid : orig_uid;
	myuid = getuid();
	if (myuid == expected_uid)
		return;

	/* unshare() can change us to /proc/sys/kernel/overflowuid */
	fp = fopen("/proc/sys/kernel/overflowuid", "r");
	if (fp) {
		if (fscanf(fp, "%u", &overflowuid) != 1)
			overflowuid = 65534;
		fclose(fp);
	}
	if (myuid == overflowuid)
		return;

	/* uid drifted to root: this is the ONLY case that's actually
	 * dangerous -- subsequent fuzz syscalls would run with root
	 * privileges and could damage the host.  Hard bail. */
	if (myuid == 0) {
		output(0, "uid changed to ROOT! Was: %u, now %u -- bailing for safety\n",
			expected_uid, myuid);

		/* Release-store the offending uid before panic() writes
		 * exit_reason, so a reader who observes
		 * exit_reason==EXIT_UID_CHANGED is guaranteed to see
		 * uid_at_exit too. */
		__atomic_store_n(&shm->uid_at_exit, myuid, __ATOMIC_RELEASE);

		panic(EXIT_UID_CHANGED);
		_exit(EXIT_UID_CHANGED);
	}

	/* Any other drift: log + bump counter + continue.  Most often
	 * this is a fuzzed setresuid/setreuid/setfsuid succeeding
	 * inside an unshared user namespace -- interesting coverage,
	 * not a danger.  Verbose-only because at high fuzz rates this
	 * can fire frequently. */
	output(1, "uid changed (continuing): was %u, now %u (overflowuid=%u)\n",
		expected_uid, myuid, overflowuid);
	__atomic_fetch_add(&shm->stats.uid_change_logged, 1, __ATOMIC_RELAXED);
}
