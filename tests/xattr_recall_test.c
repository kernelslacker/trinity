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
#include "syscalls/syscalls.h"	/* syscall_fgetxattr, syscall_flistxattr */
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

/* The size the calls are handed, which the sanitisers keep half the time,
 * room for a scratch file's name list. */
#define RECALL_SIZE	256

static const char recall_name[] = "user.trinity_recall";

/* A getter that takes an fd in a1, the counter its oracle bumps, and the
 * slot of the buffer it fills, whose size is the slot after; fgetxattr
 * takes the attribute's name in a2. */
struct fd_getter {
	struct syscallentry *entry;
	unsigned long *anomalies;
	unsigned int buf_slot;
	bool named;
};

/* @g's calls the sanitiser built on @fd, which the kernel ran on @final,
 * each answering the @len bytes at @answer; the anomalies its re-call
 * reports. */
static unsigned long fd_getter_anomalies(const struct fd_getter *g, int fd,
					 int final, const void *answer,
					 size_t len)
{
	unsigned long before = *g->anomalies;
	static struct syscallrecord rec;
	static char name[XATTR_NAME_BUFSZ];
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned long *buf = slots[g->buf_slot - 1], *size = slots[g->buf_slot];
	unsigned int i, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		for (tries = 0; tries < 4096; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a1 = (unsigned long) fd;
			if (g->named) {
				strcpy(name, recall_name);
				rec.a2 = (unsigned long) name;
			}
			*buf = (unsigned long) get_writable_address(page_size);
			*size = RECALL_SIZE;
			g->entry->sanitise(&rec);
			if (*size == RECALL_SIZE)
				break;
			free((void *) rec.post_state);
		}
		if (tries == 4096)
			BUG("an xattr sanitiser never kept the size it was handed");

		memcpy((void *) *buf, answer, len);
		rec.a1 = (unsigned long) final;
		rec.arg_snapshot_mask = g->entry->arg_snapshot_mask;
		rec.arg_shadow[0] = rec.a1;
		rec.arg_shadow[g->buf_slot] = *size;
		rec.retval = len;
		g->entry->post(&rec);
	}
	return *g->anomalies - before;
}

static char scratch[2][sizeof("/tmp/trinity-xattr-recall-test.XXXXXX")];

/* A scratch file whose recall_name holds @value, which also carries a
 * name of its own as long as the other's, open; or -1 where the filesystem
 * keeps no user xattrs. */
static int scratch_file(unsigned int n, const char *value)
{
	char own[] = "user.trinity_N";
	int fd;

	strcpy(scratch[n], "/tmp/trinity-xattr-recall-test.XXXXXX");
	fd = mkstemp(scratch[n]);
	if (fd < 0)
		BUG("xattr recall: cannot make a scratch file");
	own[sizeof(own) - 2] = (char) ('0' + n);
	if (fsetxattr(fd, recall_name, value, strlen(value), 0) == 0 &&
	    fsetxattr(fd, own, "", 0, 0) == 0)
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
	const struct fd_getter fgetxattr_getter = {
		&syscall_fgetxattr, &shm->stats.oracle.fgetxattr_oracle_anomalies,
		3, true,
	};
	const struct fd_getter flistxattr_getter = {
		&syscall_flistxattr, &shm->stats.oracle.flistxattr_oracle_anomalies,
		2, false,
	};
	char list[2][RECALL_SIZE];
	ssize_t len[2];
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
	len[0] = flistxattr(a, list[0], sizeof(list[0]));
	len[1] = flistxattr(b, list[1], sizeof(list[1]));
	if (len[0] <= 0 || len[1] != len[0] || memcmp(list[0], list[1], len[0]) == 0)
		BUG("xattr recall: the scratch files' name lists are not distinct lists of one length");

	fake_snapshot_str_copies = true;
	check("fgetxattr: a call substituted onto another file was judged on the first",
	      fd_getter_anomalies(&fgetxattr_getter, a, b, "bbbb", 4) == 0);
	check("fgetxattr: a substituted call answering the first file's value was not reported",
	      fd_getter_anomalies(&fgetxattr_getter, a, b, "aaaa", 4) > 0);
	check("flistxattr: a call substituted onto another file was judged on the first",
	      fd_getter_anomalies(&flistxattr_getter, a, b, list[1], len[1]) == 0);
	check("flistxattr: a substituted call answering the first file's list was not reported",
	      fd_getter_anomalies(&flistxattr_getter, a, b, list[0], len[0]) > 0);
	fake_snapshot_str_copies = false;

	close(a);
	close(b);
	unlink(scratch[0]);
	unlink(scratch[1]);

	if (failed != 0)
		BUG("an xattr re-call judged the wrong file");
}
