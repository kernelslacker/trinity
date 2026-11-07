/*
 * Self-check for the xattr getters' re-call oracles: each runs its
 * sanitiser and post handler as shipped on files of the test's own, handed
 * the bytes the fuzzed call wrote, and counts the anomalies its sampled
 * re-call reports.  Chain substitution can hand the kernel another fd than
 * the sanitiser drew, and the re-call has to go to that one.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "kernel/unistd.h"	/* SYS_listxattrat */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_fgetxattr, ... */
#include "utils.h"
#include "utils-macros.h"	/* ARRAY_SIZE */
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

/* The fd a call was built or run on, and listxattrat's at_flags. */
struct recall_args {
	int fd;
	unsigned long at_flags;
};

/* A getter that takes an fd in a1, the counter its oracle bumps, and the
 * slot of the buffer it fills, whose size is the slot after.  fgetxattr
 * takes the attribute's name in a2, and listxattrat an empty path in a2
 * with its at_flags in a3. */
struct fd_getter {
	struct syscallentry *entry;
	unsigned long *anomalies;
	unsigned int buf_slot;
	enum { FD_ONLY, FD_NAMED, FD_EMPTY_PATH } shape;
};

/* @g's calls the sanitiser built on @built, which the kernel ran on @ran,
 * each answering the @len bytes at @answer; the anomalies its re-call
 * reports. */
static unsigned long fd_getter_anomalies(const struct fd_getter *g,
					 const struct recall_args *built,
					 const struct recall_args *ran,
					 const void *answer, size_t len)
{
	unsigned long before = *g->anomalies;
	static struct syscallrecord rec;
	static char name[XATTR_NAME_BUFSZ];
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned long *buf = slots[g->buf_slot - 1], *size = slots[g->buf_slot];
	unsigned int i, k, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		for (tries = 0; tries < 4096; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a1 = (unsigned long) built->fd;
			if (g->shape == FD_NAMED) {
				strcpy(name, recall_name);
				rec.a2 = (unsigned long) name;
			} else if (g->shape == FD_EMPTY_PATH) {
				rec.a2 = (unsigned long) "";
				rec.a3 = built->at_flags;
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
		rec.a1 = (unsigned long) ran->fd;
		if (g->shape == FD_EMPTY_PATH)
			rec.a3 = ran->at_flags;
		/* The shadow __do_syscall() takes of what the kernel was handed. */
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec.arg_shadow[k] = *slots[k];
		rec.arg_snapshot_mask = g->entry->arg_snapshot_mask;
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
		3, FD_NAMED,
	};
	const struct fd_getter flistxattr_getter = {
		&syscall_flistxattr, &shm->stats.oracle.flistxattr_oracle_anomalies,
		2, FD_ONLY,
	};
#ifdef SYS_listxattrat
	const struct fd_getter listxattrat_getter = {
		&syscall_listxattrat, &shm->stats.oracle.listxattrat_oracle_anomalies,
		4, FD_EMPTY_PATH,
	};
	struct recall_args on_a_by_path;
#endif
	struct recall_args on_a, on_b;
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

	on_a = (struct recall_args) { a, AT_EMPTY_PATH };
	on_b = (struct recall_args) { b, AT_EMPTY_PATH };

	fake_snapshot_str_copies = true;
	check("fgetxattr: a call substituted onto another file was judged on the first",
	      fd_getter_anomalies(&fgetxattr_getter, &on_a, &on_b, "bbbb", 4) == 0);
	check("fgetxattr: a substituted call answering the first file's value was not reported",
	      fd_getter_anomalies(&fgetxattr_getter, &on_a, &on_b, "aaaa", 4) > 0);
	check("flistxattr: a call substituted onto another file was judged on the first",
	      fd_getter_anomalies(&flistxattr_getter, &on_a, &on_b, list[1], len[1]) == 0);
	check("flistxattr: a substituted call answering the first file's list was not reported",
	      fd_getter_anomalies(&flistxattr_getter, &on_a, &on_b, list[0], len[0]) > 0);
#ifdef SYS_listxattrat
	/* Without AT_EMPTY_PATH the empty path names nothing. */
	on_a_by_path = (struct recall_args) { a, 0 };
	if (syscall(SYS_listxattrat, a, "", AT_EMPTY_PATH, NULL, 0) == len[0]) {
		check("listxattrat: a call substituted onto another file was judged on the first",
		      fd_getter_anomalies(&listxattrat_getter, &on_a, &on_b, list[1], len[1]) == 0);
		check("listxattrat: a substituted call answering the first file's list was not reported",
		      fd_getter_anomalies(&listxattrat_getter, &on_a, &on_b, list[0], len[0]) > 0);
		check("listxattrat: a torn copy from a call whose at_flags were rewritten was not reported",
		      fd_getter_anomalies(&listxattrat_getter, &on_a_by_path, &on_a, list[1], len[1]) > 0);
	} else {
		printf("(no listxattrat) ");
	}
#endif
	fake_snapshot_str_copies = false;

	close(a);
	close(b);
	unlink(scratch[0]);
	unlink(scratch[1]);

	if (failed != 0)
		BUG("an xattr re-call judged the wrong file");
}
