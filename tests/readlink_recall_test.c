/*
 * Self-check for readlinkat's re-call oracle: it runs the sanitiser and post
 * handler as shipped on symlinks of the test's own, handed the target the
 * fuzzed call read, and counts the anomalies its sampled re-call reports.
 * Chain substitution can hand the kernel another dfd or bufsiz than the
 * sanitiser drew, and the re-call has to read the link the kernel read.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_readlinkat */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern bool fake_snapshot_str_copies;		/* arg_coupling_test.c */

static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "readlink recall: %s\n", what);
	failed++;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

/* The dfd and bufsiz a call was built or run on. */
struct readlinkat_args {
	int dfd;
	unsigned long bufsiz;
};

/* readlinkat calls of "link" the sanitiser built on @built, which the kernel
 * ran on @ran, each reading the @len bytes at @answer; the anomalies the
 * re-call reports. */
static unsigned long readlinkat_anomalies(const struct readlinkat_args *built,
					  const struct readlinkat_args *ran,
					  const char *answer, size_t len)
{
	unsigned long before = shm->stats.oracle.readlinkat_oracle_anomalies;
	static struct syscallrecord rec;
	static char name[] = "link";
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int i, k;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) built->dfd;
		rec.a2 = (unsigned long) name;
		rec.a3 = (unsigned long) get_writable_address(page_size);
		rec.a4 = built->bufsiz;
		syscall_readlinkat.sanitise(&rec);

		memcpy((void *) rec.a3, answer, len);
		rec.a1 = (unsigned long) ran->dfd;
		rec.a4 = ran->bufsiz;
		/* The shadow __do_syscall() takes of what the kernel was handed. */
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec.arg_shadow[k] = *slots[k];
		rec.arg_snapshot_mask = syscall_readlinkat.arg_snapshot_mask;
		rec.retval = len;
		syscall_readlinkat.post(&rec);
	}
	return shm->stats.oracle.readlinkat_oracle_anomalies - before;
}

static char scratch[2][sizeof("/tmp/trinity-readlink-recall-test.XXXXXX")];

/* A scratch directory holding a symlink "link" to @target, open. */
static int scratch_dir(unsigned int n, const char *target)
{
	int dfd;

	strcpy(scratch[n], "/tmp/trinity-readlink-recall-test.XXXXXX");
	if (mkdtemp(scratch[n]) == NULL)
		BUG("readlink recall: cannot make a scratch directory");
	dfd = open(scratch[n], O_RDONLY | O_DIRECTORY);
	if (dfd < 0 || symlinkat(target, dfd, "link") != 0)
		BUG("readlink recall: cannot make a scratch symlink");
	return dfd;
}

void readlink_recall_self_check(void);
void readlink_recall_self_check(void)
{
	struct readlinkat_args on_a, on_b, short_on_a;
	int a, b;

	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(page_size) == NULL)
		writable_pool_init();

	a = scratch_dir(0, "aaaa");
	b = scratch_dir(1, "bbbb");
	on_a = (struct readlinkat_args) { a, 64 };
	on_b = (struct readlinkat_args) { b, 64 };
	short_on_a = (struct readlinkat_args) { a, 2 };

	fake_snapshot_str_copies = true;
	check("readlinkat: a call substituted onto another dfd was judged on the first",
	      readlinkat_anomalies(&on_a, &on_b, "bbbb", 4) == 0);
	check("readlinkat: a substituted call answering the first link's target was not reported",
	      readlinkat_anomalies(&on_a, &on_b, "aaaa", 4) > 0);
	check("readlinkat: a call whose bufsiz was rewritten larger was held to the first",
	      readlinkat_anomalies(&short_on_a, &on_a, "aaaa", 4) == 0);
	fake_snapshot_str_copies = false;

	unlinkat(a, "link", 0);
	unlinkat(b, "link", 0);
	close(a);
	close(b);
	rmdir(scratch[0]);
	rmdir(scratch[1]);

	if (failed != 0)
		BUG("a readlinkat re-call read the wrong link");
}
