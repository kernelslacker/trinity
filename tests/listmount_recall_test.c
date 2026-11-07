/*
 * Self-check for listmount's re-call oracle: it runs the sanitiser and post
 * handler as shipped on a mount of the host's own, handed the ids the kernel
 * listed under it, and counts the anomalies its sampled re-call reports.
 * The order the ids come in depends on the flags the kernel was handed,
 * and how many on the nr_mnt_ids, either of which chain substitution can
 * rewrite after the sanitiser drew its own.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "kernel/mount.h"	/* struct mnt_id_req, LISTMOUNT_REVERSE */
#include "kernel/unistd.h"	/* SYS_listmount */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_listmount */
#include "utils-macros.h"	/* ARRAY_SIZE */

void listmount_recall_self_check(void);

#ifdef SYS_listmount
static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "listmount recall: %s\n", what);
	failed++;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

/* Tries for the sanitiser to draw the nr and flags a case builds on. */
#define DRAW_TRIES	100000

/* An nr_mnt_ids the sanitiser draws, and the most ids the re-call
 * compares: a mount with fewer under it is listed whole, so a mount made
 * or gone while a case runs changes the count, which the re-call skips. */
#define LIST_ALL	64

/* The nr_mnt_ids and flags a call was built or run on. */
struct listmount_args {
	unsigned long nr;
	unsigned int flags;
};

/* The mount the cases list under. */
static __u64 parent;

/* The ids listmount() lists under @under on @args, into @ids; how many. */
static long list_under(__u64 under, const struct listmount_args *args,
		       __u64 *ids)
{
	struct mnt_id_req req = {
		.size = MNT_ID_REQ_SIZE_VER0,
		.mnt_id = under,
	};

	return syscall(SYS_listmount, &req, ids, args->nr, args->flags);
}

/* listmount calls under parent the sanitiser built on @built, which the
 * kernel ran on @ran, each answering the @n ids at @answer; the anomalies
 * the re-call reports. */
static unsigned long listmount_anomalies(const struct listmount_args *built,
					 const struct listmount_args *ran,
					 const __u64 *answer, long n)
{
	unsigned long before = shm->stats.oracle.listmount_oracle_anomalies;
	static struct syscallrecord rec;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int i, k, tries;

	for (i = 0; i < RECALL_CALLS; i++) {
		struct mnt_id_req *req;

		for (tries = 0; tries < DRAW_TRIES; tries++) {
			memset(&rec, 0, sizeof(rec));
			syscall_listmount.sanitise(&rec);
			if (rec.a3 == built->nr && rec.a4 == built->flags)
				break;
			free((void *) rec.post_state);
			while (rec.owned_count > 0)
				free(rec.owned[--rec.owned_count]);
		}
		if (tries == DRAW_TRIES)
			BUG("listmount's sanitiser never drew the nr and flags");

		/* The sanitiser's request, asking about parent. */
		req = (struct mnt_id_req *) rec.a1;
		req->size = MNT_ID_REQ_SIZE_VER0;
		req->mnt_id = parent;
		req->param = 0;
		memcpy((void *) rec.a2, answer, (size_t) n * sizeof(*answer));
		rec.a3 = ran->nr;
		rec.a4 = ran->flags;
		/* The shadow __do_syscall() takes of what the kernel was handed. */
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec.arg_shadow[k] = *slots[k];
		rec.arg_snapshot_mask = syscall_listmount.arg_snapshot_mask;
		rec.retval = (unsigned long) n;
		syscall_listmount.post(&rec);
		while (rec.owned_count > 0)
			free(rec.owned[--rec.owned_count]);
	}
	return shm->stats.oracle.listmount_oracle_anomalies - before;
}

/* A mount with at least three mounts under it, and fewer than LIST_ALL;
 * 0 if none. */
static __u64 pick_parent(void)
{
	const struct listmount_args all = { LIST_ALL, 0 };
	__u64 ids[LIST_ALL], under[LIST_ALL];
	long i, n, m;

	n = list_under(LSMT_ROOT, &all, ids);
	for (i = 0; i < n; i++) {
		m = list_under(ids[i], &all, under);
		if (m >= 3 && m < LIST_ALL)
			return ids[i];
	}
	return 0;
}

void listmount_recall_self_check(void)
{
	const struct listmount_args forward = { LIST_ALL, 0 };
	const struct listmount_args reverse = { LIST_ALL, LISTMOUNT_REVERSE };
	const struct listmount_args first_two = { 2, 0 };
	__u64 fwd[LIST_ALL], rev[LIST_ALL], swapped[2];
	long n;

	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(page_size) == NULL)
		writable_pool_init();

	parent = pick_parent();
	if (parent == 0) {
		printf("(no mount with a few under it) ");
		return;
	}
	n = list_under(parent, &forward, fwd);
	if (n < 3 || list_under(parent, &reverse, rev) != n) {
		printf("(the mounts under it moved) ");
		return;
	}

	check("listmount: a reverse call was re-called in the other order",
	      listmount_anomalies(&reverse, &reverse, rev, n) == 0);
	check("listmount: a reverse call answering the ids in the other order was not reported",
	      listmount_anomalies(&reverse, &reverse, fwd, n) > 0);
	check("listmount: a call whose flags were rewritten to reverse was re-called forward",
	      listmount_anomalies(&forward, &reverse, rev, n) == 0);
	swapped[0] = fwd[1];
	swapped[1] = fwd[0];
	check("listmount: a torn copy from a call whose nr was rewritten smaller was not reported",
	      listmount_anomalies(&forward, &first_two, swapped, 2) > 0);

	if (failed != 0)
		BUG("a listmount re-call listed in the wrong order");
}
#else
void listmount_recall_self_check(void)
{
	printf("(no listmount) ");
}
#endif
