/*
 * Self-check for the xattr getters' re-call oracles: each runs its
 * sanitiser and post handler as shipped on files of the test's own, handed
 * the bytes the fuzzed call wrote, and counts the anomalies its sampled
 * re-call reports.  Chain substitution can hand the kernel another fd than
 * the sanitiser drew, and the re-call has to go to that one.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_fgetxattr */
#include "utils.h"
#include "xattr.h"		/* XATTR_NAME_BUFSZ */

extern bool fake_snapshot_str_copies;		/* arg_coupling_test.c */

static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "xattr recall: %s\n", what);
	failed++;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

/* The size the calls are handed, which the sanitisers keep half the time. */
#define RECALL_SIZE	64

static const char recall_name[] = "user.trinity_recall";

/* fgetxattr() calls the sanitiser built on @fd, which the kernel ran on
 * @final, each answering @answer; the anomalies its re-call reports. */
static unsigned long fgetxattr_anomalies(int fd, int final, const char *answer)
{
	unsigned long before = shm->stats.oracle.fgetxattr_oracle_anomalies;
	static struct syscallrecord rec;
	static char name[XATTR_NAME_BUFSZ];
	unsigned int i, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		for (tries = 0; tries < 4096; tries++) {
			memset(&rec, 0, sizeof(rec));
			strcpy(name, recall_name);
			rec.a1 = (unsigned long) fd;
			rec.a2 = (unsigned long) name;
			rec.a3 = (unsigned long) get_writable_address(page_size);
			rec.a4 = RECALL_SIZE;
			syscall_fgetxattr.sanitise(&rec);
			if (rec.a4 == RECALL_SIZE)
				break;
			free((void *) rec.post_state);
		}
		if (tries == 4096)
			BUG("fgetxattr's sanitiser never kept the size it was handed");

		memcpy((void *) rec.a3, answer, strlen(answer));
		rec.a1 = (unsigned long) final;
		rec.arg_snapshot_mask = syscall_fgetxattr.arg_snapshot_mask;
		rec.arg_shadow[0] = rec.a1;
		rec.arg_shadow[3] = rec.a4;
		rec.retval = strlen(answer);
		syscall_fgetxattr.post(&rec);
	}
	return shm->stats.oracle.fgetxattr_oracle_anomalies - before;
}

static char scratch[2][sizeof("/tmp/trinity-xattr-recall-test.XXXXXX")];

/* A scratch file whose recall_name holds @value, open read-only, or -1
 * where the filesystem keeps no user xattrs. */
static int scratch_file(unsigned int n, const char *value)
{
	int fd;

	strcpy(scratch[n], "/tmp/trinity-xattr-recall-test.XXXXXX");
	fd = mkstemp(scratch[n]);
	if (fd < 0)
		BUG("xattr recall: cannot make a scratch file");
	if (fsetxattr(fd, recall_name, value, strlen(value), 0) == 0)
		return fd;
	if (errno != ENOTSUP)
		BUG("xattr recall: cannot set the scratch file's xattr");
	close(fd);
	unlink(scratch[n]);
	return -1;
}

void xattr_recall_self_check(void);
void xattr_recall_self_check(void)
{
	int a, b;

	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(page_size) == NULL)
		writable_pool_init();

	a = scratch_file(0, "aaaa");
	if (a < 0) {
		printf("(no user xattrs in /tmp) ");
		return;
	}
	b = scratch_file(1, "bbbb");
	if (b < 0)
		BUG("xattr recall: user xattrs on one scratch file but not another");

	fake_snapshot_str_copies = true;
	check("fgetxattr: a call substituted onto another file was judged on the first",
	      fgetxattr_anomalies(a, b, "bbbb") == 0);
	check("fgetxattr: a substituted call answering the first file's value was not reported",
	      fgetxattr_anomalies(a, b, "aaaa") > 0);
	fake_snapshot_str_copies = false;

	close(a);
	close(b);
	unlink(scratch[0]);
	unlink(scratch[1]);

	if (failed != 0)
		BUG("an xattr re-call judged the wrong file");
}
