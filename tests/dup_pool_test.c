/*
 * Self-check for how dup, dup2, dup3 and fcntl(F_DUPFD*) pool the
 * descriptor they return, and for how close and close_range retire what
 * they free.  The post handlers run as shipped against a fake object
 * pool.  A copy joins the pool its source came from, and stays out of
 * every pool when the source is untracked or protected, the call failed,
 * or the type is one publish_resource() does not route.  Whatever object
 * a number held before the call is retired, copy pooled or not, and a
 * retire never closes the number: it names the copy by then.  The close
 * itself is reported once, through notify_child_fd_closed(), as before.
 *
 * A close retires the local objects under its number once the kernel has
 * freed it, which a failed close has too unless it says EBADF.  A
 * close_range retires the objects under the numbers it closed: [lo, hi],
 * the complement of [lo, hi] with EXCEPT, and with CLOEXEC_ONLY just the
 * pooled fds the kernel no longer has.  One that only marks close-on-exec
 * retires nothing.  Its sanitiser never leaves a protected fd in the set
 * the call closes.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arg_coupling.h"	/* validate_arg_coupling */
#include "child.h"
#include "debug.h"		/* BUG */
#include "fd.h"			/* lowest_protected_fd_in_range */
#include "fd-event.h"		/* notify_child_fd_closed */
#include "kcov-shared.h"	/* kcov_shm */
#include "objects.h"
#include "publish_resource.h"
#include "rnd.h"		/* rnd_seed */
#include "sanitise.h"		/* get_pid */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_dup, syscall_close, ... */

#include "kernel/fcntl.h"	/* F_DUPFD_CLOEXEC */

extern struct childdata *fake_this_child;	/* fake_shm.c */
extern struct object *(*fake_find_object_by_fd)(int fd);	/* fake_fds.c */
extern const void *post_state_disowned;	/* post_oracle_test.c */

/* Numbers no fd table in the test holds, so the post handlers' fstat()
 * oracle finds nothing to compare. */
#define SRC		90001
#define NEW		90002
#define KCOV_FD		90100
#define KCOV_CMP_FD	90101

#define POOL_MAX	16
#define LOG_MAX		8	/* closes and range closes a case can log */
#define STALE		0xdeadUL	/* in publish_call_nr: marks an object that predates the call */

struct pool_entry {
	bool used;
	bool local;
	int fd;
	struct object obj;
};

static struct pool_entry pool[POOL_MAX];
static struct childdata fake_child;

/* What the fakes saw. */
static unsigned int published;
static unsigned int retires;
static int retired_fd;
static unsigned int closes;
static int closed_fds[LOG_MAX];
static unsigned int range_retires;
static unsigned int range_retired_lo;
static unsigned int range_retired_hi;
static unsigned int range_closes;
static int closed_lo[LOG_MAX];
static int closed_hi[LOG_MAX];
static unsigned int global_removes;

/* A type publish_resource() does not route: it returns NULL for it. */
static enum objecttype unrouted;

static unsigned int failed;

static void check(const char *what, const char *case_name, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "fd pool: %s: %s\n", case_name, what);
	failed++;
}

static void pool_add(bool local, int fd, enum objecttype type)
{
	unsigned int i;

	for (i = 0; i < POOL_MAX; i++) {
		struct pool_entry *e = &pool[i];

		if (e->used)
			continue;
		memset(e, 0, sizeof(*e));
		e->used = true;
		e->local = local;
		e->fd = fd;
		e->obj.obj_type = type;
		e->obj.publish_call_nr = STALE;
		return;
	}
	BUG("fd pool: the fake pool is full");
}

static struct pool_entry *pool_find(int fd, enum objecttype type)
{
	unsigned int i;

	for (i = 0; i < POOL_MAX; i++) {
		if (pool[i].used && pool[i].fd == fd &&
		    pool[i].obj.obj_type == type)
			return &pool[i];
	}
	return NULL;
}

static unsigned int pool_count(int fd)
{
	unsigned int i, n = 0;

	for (i = 0; i < POOL_MAX; i++) {
		if (pool[i].used && pool[i].fd == fd)
			n++;
	}
	return n;
}

static struct object *fake_lookup(int fd)
{
	unsigned int i;

	for (i = 0; i < POOL_MAX; i++) {
		if (pool[i].used && pool[i].fd == fd)
			return &pool[i].obj;
	}
	return NULL;
}

struct object *publish_resource(enum objecttype type, unsigned long id,
				const struct resource_meta *meta)
{
	unsigned int i;

	(void) meta;
	if (type == unrouted)
		return NULL;

	for (i = 0; i < POOL_MAX; i++) {
		struct pool_entry *e = &pool[i];

		if (e->used)
			continue;
		memset(e, 0, sizeof(*e));
		e->used = true;
		e->local = true;
		e->fd = (int) id;
		e->obj.obj_type = type;
		published++;
		return &e->obj;
	}
	BUG("fd pool: the fake pool is full");
	return NULL;
}

/* Drops every local object at @fd, as the real one does, so a handler
 * that retires after it publishes loses the object it just made. */
void remove_local_objects_by_fd(int fd)
{
	unsigned int i;

	retires++;
	retired_fd = fd;
	for (i = 0; i < POOL_MAX; i++) {
		if (pool[i].used && pool[i].local && pool[i].fd == fd)
			pool[i].used = false;
	}
}

void notify_child_fd_closed(struct childdata *child, int fd)
{
	(void) child;
	if (closes < LOG_MAX)
		closed_fds[closes] = fd;
	closes++;
}

/* Drops every local object whose number is in [lo, hi], the walk of the
 * pool the real one makes, asking @gone about each when there is one, and
 * records the bounds it was given. */
void remove_local_objects_in_range(unsigned int lo, unsigned int hi,
				   bool (*gone)(int fd))
{
	unsigned int i;

	range_retires++;
	range_retired_lo = lo;
	range_retired_hi = hi;
	for (i = 0; i < POOL_MAX; i++) {
		if (pool[i].used && pool[i].local && pool[i].fd >= 0 &&
		    (unsigned int) pool[i].fd >= lo &&
		    (unsigned int) pool[i].fd <= hi &&
		    (gone == NULL || gone(pool[i].fd)))
			pool[i].used = false;
	}
}

void notify_child_fd_closed_range(struct childdata *child, int lo, int hi)
{
	(void) child;
	if (range_closes < LOG_MAX) {
		closed_lo[range_closes] = lo;
		closed_hi[range_closes] = hi;
	}
	range_closes++;
}

/* The parent-side close path, a no-op in a child. */
void remove_object_by_fd(int fd)
{
	(void) fd;
	global_removes++;
}

/* fcntl's sanitiser picks the owner pid for F_SETOWN; only it reaches
 * this, and these cases run the post handler. */
unsigned int get_pid(void)
{
	BUG("fd pool: a handler asked for a pid");
	return 0;
}

/* What the fakes saw, from the last call on. */
static void forget_calls(void)
{
	published = 0;
	retires = 0;
	closes = 0;
	range_retires = 0;
	range_closes = 0;
	global_removes = 0;
}

/* Run @entry's post handler on a call that returned @retval, and check
 * that the call counts as one dup when it worked and none when it did
 * not. */
static void run(const struct syscallentry *entry, const char *case_name,
		unsigned long a1, unsigned long a2, unsigned long retval)
{
	static struct syscallrecord rec;
	unsigned long duped = shm->stats.fd.duped;
	bool worked = (long) retval >= 0 && retval < (1UL << 20);

	memset(&rec, 0, sizeof(rec));
	rec.a1 = a1;
	rec.a2 = a2;
	rec.retval = retval;
	rec.errno_post = (retval == (unsigned long) -1L) ? EBADF : 0;

	forget_calls();
	entry->post(&rec);

	check("the dup count did not move by one per call that worked",
	      case_name, shm->stats.fd.duped == duped + (worked ? 1 : 0));
}

static void reset(void)
{
	memset(pool, 0, sizeof(pool));
	unrouted = OBJ_NONE;
}

/* The copy of a socket carries its triplet, as an accepted one does. */
static void copy_joins_the_sources_pool(void)
{
	const struct syscallentry *entries[] = {
		&syscall_dup, &syscall_dup2, &syscall_dup3,
	};
	unsigned int i;

	for (i = 0; i < 3; i++) {
		const char *name = entries[i]->name;
		struct pool_entry *e;

		reset();
		pool_add(false, SRC, OBJ_FD_SOCKET);
		pool_find(SRC, OBJ_FD_SOCKET)->obj.sockinfo.triplet =
			(struct socket_triplet) { 2, 1, 6 };
		pool_add(true, 90010, OBJ_FD_EVENTFD);

		run(entries[i], name, SRC, NEW, NEW);
		e = pool_find(NEW, OBJ_FD_SOCKET);
		check("a copy of a global socket is not a local socket",
		      name, e != NULL && e->local);
		check("the copy of a socket lost its triplet", name,
		      e != NULL && e->obj.sockinfo.triplet.family == 2 &&
		      e->obj.sockinfo.triplet.type == 1 &&
		      e->obj.sockinfo.triplet.protocol == 6);
		check("the copy is not the only object at its number", name,
		      pool_count(NEW) == 1);
		check("the source left its pool", name,
		      pool_find(SRC, OBJ_FD_SOCKET) != NULL);
		check("a retire took an object at another number", name,
		      pool_find(90010, OBJ_FD_EVENTFD) != NULL);

		/* The type is the source's, not a fixed one. */
		reset();
		pool_add(true, SRC, OBJ_FD_EVENTFD);
		run(entries[i], name, SRC, NEW, NEW);
		check("a copy of an eventfd is not a local eventfd", name,
		      pool_find(NEW, OBJ_FD_EVENTFD) != NULL &&
		      pool_count(NEW) == 1);
	}
}

/* A number the call returns can hold an object from before: a fd that
 * was closed and its number handed out again, or the file dup2 closed.
 * It goes, whether or not the copy is pooled, and never takes the copy
 * with it. */
static void old_object_is_retired(void)
{
	const struct syscallentry *entries[] = { &syscall_dup2, &syscall_dup3 };
	unsigned int i;

	for (i = 0; i < 2; i++) {
		const char *name = entries[i]->name;
		struct pool_entry *e;

		/* Another type held the number. */
		reset();
		pool_add(false, SRC, OBJ_FD_SOCKET);
		pool_add(true, NEW, OBJ_FD_PIPE);
		run(entries[i], name, SRC, NEW, NEW);
		check("the replaced pipe is still pooled", name,
		      pool_find(NEW, OBJ_FD_PIPE) == NULL);
		check("the copy is not a local socket", name,
		      pool_find(NEW, OBJ_FD_SOCKET) != NULL &&
		      pool_count(NEW) == 1);
		check("the replaced number was not retired exactly once", name,
		      retires == 1 && retired_fd == NEW);
		check("the close of the replaced fd was not reported once", name,
		      closes == 1 && closed_fds[0] == NEW);

		/* The same type held it: one object, and a new one. */
		reset();
		pool_add(true, SRC, OBJ_FD_EVENTFD);
		pool_add(true, NEW, OBJ_FD_EVENTFD);
		run(entries[i], name, SRC, NEW, NEW);
		e = pool_find(NEW, OBJ_FD_EVENTFD);
		check("an eventfd copied over an eventfd is not one object",
		      name, pool_count(NEW) == 1);
		check("the replaced eventfd's object was kept", name,
		      e != NULL && e->obj.publish_call_nr != STALE);
		check("the source's own object was disturbed", name,
		      pool_find(SRC, OBJ_FD_EVENTFD) != NULL &&
		      pool_find(SRC, OBJ_FD_EVENTFD)->obj.publish_call_nr == STALE);

		/* The source is not tracked: nothing joins a pool, but the
		 * file the copy replaced is gone all the same. */
		reset();
		pool_add(true, NEW, OBJ_FD_PIPE);
		run(entries[i], name, SRC, NEW, NEW);
		check("the replaced pipe is still pooled when the copy is not",
		      name, pool_count(NEW) == 0);
		check("an untracked source was pooled", name, published == 0);
	}

	/* dup: a free number, held by an object whose fd was closed. */
	reset();
	pool_add(true, SRC, OBJ_FD_TIMERFD);
	pool_add(true, NEW, OBJ_FD_PIPE);
	run(&syscall_dup, "dup", SRC, 0, NEW);
	check("a stale object at the number dup returned is still pooled",
	      "dup", pool_find(NEW, OBJ_FD_PIPE) == NULL &&
	      pool_find(NEW, OBJ_FD_TIMERFD) != NULL && pool_count(NEW) == 1);
	check("dup reported a close it did not make", "dup", closes == 0);

	reset();
	pool_add(true, NEW, OBJ_FD_PIPE);
	run(&syscall_dup, "dup", SRC, 0, NEW);
	check("a stale object survived a dup of an untracked fd",
	      "dup", pool_count(NEW) == 0 && published == 0);
}

/* dup2(fd, fd) succeeds and changes nothing: nothing is closed, retired
 * or published, so the object the fd has stays the one it had.  dup3
 * refuses the call before the post handler sees it. */
static void same_fd_is_a_no_op(void)
{
	struct pool_entry *e;

	reset();
	pool_add(true, SRC, OBJ_FD_PIPE);
	run(&syscall_dup2, "dup2(fd, fd)", SRC, SRC, SRC);
	e = pool_find(SRC, OBJ_FD_PIPE);
	check("dup2(fd, fd) replaced the fd's object", "dup2(fd, fd)",
	      e != NULL && e->obj.publish_call_nr == STALE &&
	      pool_count(SRC) == 1);
	check("dup2(fd, fd) retired, published or reported a close",
	      "dup2(fd, fd)", retires == 0 && published == 0 && closes == 0);
}

/* A call that failed, or returned what no fd table holds, pools and
 * retires nothing. */
static void failed_call_pools_nothing(void)
{
	static const unsigned long returns[] = {
		(unsigned long) -1L, 1UL << 20, (unsigned long) -4096L,
	};
	const struct syscallentry *entries[] = {
		&syscall_dup, &syscall_dup2, &syscall_dup3,
	};
	unsigned int i, j;

	for (i = 0; i < 3; i++) {
		for (j = 0; j < 3; j++) {
			const char *name = entries[i]->name;

			reset();
			pool_add(false, SRC, OBJ_FD_SOCKET);
			pool_add(true, NEW, OBJ_FD_PIPE);
			run(entries[i], name, SRC, NEW, returns[j]);
			check("a call that returned no fd changed the pool", name,
			      published == 0 && retires == 0 && closes == 0 &&
			      pool_count(NEW) == 1 &&
			      pool_find(NEW, OBJ_FD_PIPE) != NULL);
		}
	}
}

/* stdio is never pooled; a dup that lands there leaves it alone. */
static void stdio_is_not_pooled(void)
{
	unsigned long fd;

	for (fd = 0; fd <= 2; fd++) {
		reset();
		pool_add(false, SRC, OBJ_FD_SOCKET);
		run(&syscall_dup, "dup", SRC, 0, fd);
		check("a dup that landed on stdio was pooled", "dup",
		      published == 0 && retires == 0 && pool_count((int) fd) == 0);
	}
}

/* The fds the protected registry shields stay out of every pool, as the
 * source of a copy and as the number a dup2 overwrites. */
static void protected_fds_are_not_pooled(void)
{
	reset();
	pool_add(false, SRC, OBJ_FD_SOCKET);
	run(&syscall_dup2, "dup2", SRC, KCOV_FD, KCOV_FD);
	check("a dup2 over the kcov fd pooled it", "dup2",
	      published == 0 && retires == 0 && pool_count(KCOV_FD) == 0);

	/* An object under the protected number: the registry, not an
	 * untracked source, is what keeps its copy out. */
	reset();
	pool_add(false, KCOV_CMP_FD, OBJ_FD_EVENTFD);
	run(&syscall_dup, "dup", KCOV_CMP_FD, 0, NEW);
	check("a dup of the kcov cmp fd was pooled", "dup",
	      published == 0 && pool_count(NEW) == 0);

	reset();
	pool_add(false, KCOV_CMP_FD, OBJ_FD_EVENTFD);
	run(&syscall_dup3, "dup3", KCOV_CMP_FD, NEW, NEW);
	check("a dup3 of the kcov cmp fd was pooled", "dup3",
	      published == 0 && pool_count(NEW) == 0);
}

/* A type publish_resource() cannot route stays unpooled, and the copy
 * stays open: the handler must not close what it could not pool. */
static void unrouted_type_stays_open(void)
{
	int src = open("/dev/null", O_RDONLY);
	int copy;

	if (src < 0)
		BUG("fd pool: cannot open /dev/null");
	copy = dup(src);
	if (copy < 0)
		BUG("fd pool: cannot dup /dev/null");

	reset();
	unrouted = OBJ_FD_SCRATCH_BLOCK;
	pool_add(false, src, OBJ_FD_SCRATCH_BLOCK);
	run(&syscall_dup, "dup", (unsigned long) src, 0, (unsigned long) copy);
	check("a copy of an unrouted type was pooled", "dup",
	      pool_count(copy) == 0);
	check("the copy of an unrouted type was closed", "dup",
	      fcntl(copy, F_GETFD) != -1);

	close(copy);
	close(src);
}

/* Run fcntl's post handler on a call of @cmd on @a1 that returned
 * @retval, and check that it counts as one dup when a duplicating cmd
 * worked and none otherwise. */
static void run_fcntl(unsigned long cmd, unsigned long a1,
		      unsigned long retval, const char *case_name)
{
	static struct syscallrecord rec;
	unsigned long duped = shm->stats.fd.duped;
	bool dups = cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC;
	bool worked = (long) retval >= 0 && retval < (1UL << 20);

	memset(&rec, 0, sizeof(rec));
	rec.a1 = a1;
	rec.a2 = cmd;
	rec.retval = retval;
	rec.errno_post = (retval == (unsigned long) -1L) ? EBADF : 0;

	forget_calls();
	syscall_fcntl.post(&rec);

	check("the dup count did not move by one per duplicating call that worked",
	      case_name, shm->stats.fd.duped == duped + (dups && worked ? 1 : 0));
}

/* F_DUPFD and F_DUPFD_CLOEXEC copy a descriptor as dup does: the copy
 * joins the pool its source came from, and the number it took is retired
 * first, copy pooled or not. */
static void fcntl_dupfd_pools_the_copy(void)
{
	static const struct {
		const char *name;
		unsigned long cmd;
	} cmds[] = {
		{ "fcntl(F_DUPFD)", F_DUPFD },
		{ "fcntl(F_DUPFD_CLOEXEC)", F_DUPFD_CLOEXEC },
	};
	static const unsigned long no_fd[] = { (unsigned long) -1L, 1UL << 20 };
	unsigned int i, j;

	for (i = 0; i < 2; i++) {
		const char *name = cmds[i].name;
		struct pool_entry *e;

		reset();
		pool_add(false, SRC, OBJ_FD_SOCKET);
		pool_find(SRC, OBJ_FD_SOCKET)->obj.sockinfo.triplet =
			(struct socket_triplet) { 2, 1, 6 };
		pool_add(true, 90010, OBJ_FD_EVENTFD);
		run_fcntl(cmds[i].cmd, SRC, NEW, name);
		e = pool_find(NEW, OBJ_FD_SOCKET);
		check("a copy of a global socket is not a local socket", name,
		      e != NULL && e->local);
		check("the copy of a socket lost its triplet", name,
		      e != NULL && e->obj.sockinfo.triplet.family == 2 &&
		      e->obj.sockinfo.triplet.type == 1 &&
		      e->obj.sockinfo.triplet.protocol == 6);
		check("the copy is not the only object at its number", name,
		      pool_count(NEW) == 1);
		check("the source left its pool", name,
		      pool_find(SRC, OBJ_FD_SOCKET) != NULL);
		check("a retire took an object at another number", name,
		      pool_find(90010, OBJ_FD_EVENTFD) != NULL);

		/* The type is the source's, not a fixed one. */
		reset();
		pool_add(true, SRC, OBJ_FD_EVENTFD);
		run_fcntl(cmds[i].cmd, SRC, NEW, name);
		check("a copy of an eventfd is not a local eventfd", name,
		      pool_find(NEW, OBJ_FD_EVENTFD) != NULL &&
		      pool_count(NEW) == 1);

		/* The number it took held an object from before. */
		reset();
		pool_add(true, SRC, OBJ_FD_TIMERFD);
		pool_add(true, NEW, OBJ_FD_PIPE);
		run_fcntl(cmds[i].cmd, SRC, NEW, name);
		check("a stale object under the F_DUPFD result is still pooled",
		      name, pool_find(NEW, OBJ_FD_PIPE) == NULL &&
		      pool_find(NEW, OBJ_FD_TIMERFD) != NULL &&
		      pool_count(NEW) == 1);
		check("the stale number was not retired exactly once", name,
		      retires == 1 && retired_fd == NEW);
		check("F_DUPFD reported a close it did not make", name,
		      closes == 0);

		/* The source is not tracked: nothing joins a pool, but the
		 * number is free all the same. */
		reset();
		pool_add(true, NEW, OBJ_FD_PIPE);
		run_fcntl(cmds[i].cmd, SRC, NEW, name);
		check("a stale object survived an F_DUPFD of an untracked fd",
		      name, pool_count(NEW) == 0 && published == 0);

		/* A call that failed, or returned what no fd table holds. */
		for (j = 0; j < 2; j++) {
			reset();
			pool_add(false, SRC, OBJ_FD_SOCKET);
			pool_add(true, NEW, OBJ_FD_PIPE);
			run_fcntl(cmds[i].cmd, SRC, no_fd[j], name);
			check("an F_DUPFD that returned no fd changed the pool",
			      name, published == 0 && retires == 0 &&
			      pool_count(NEW) == 1);
		}

		/* stdio and the protected fds stay out of every pool. */
		reset();
		pool_add(false, SRC, OBJ_FD_SOCKET);
		run_fcntl(cmds[i].cmd, SRC, 1, name);
		check("an F_DUPFD that landed on stdio was pooled", name,
		      published == 0 && retires == 0 && pool_count(1) == 0);

		reset();
		pool_add(false, KCOV_CMP_FD, OBJ_FD_EVENTFD);
		run_fcntl(cmds[i].cmd, KCOV_CMP_FD, NEW, name);
		check("an F_DUPFD of the kcov cmp fd was pooled", name,
		      published == 0 && pool_count(NEW) == 0);
	}
}

/* A cmd that is not a dup returns a number that only looks like an fd: a
 * flags word, a pipe size, an owner pid.  None of them is pooled. */
static void fcntl_other_cmds_pool_nothing(void)
{
	static const struct {
		const char *name;
		unsigned long cmd;
	} cmds[] = {
		{ "fcntl(F_GETFL)", F_GETFL },
		{ "fcntl(F_GETPIPE_SZ)", F_GETPIPE_SZ },
		{ "fcntl(F_GETOWN)", F_GETOWN },
	};
	unsigned int i;

	for (i = 0; i < 3; i++) {
		reset();
		pool_add(false, SRC, OBJ_FD_SOCKET);
		pool_add(true, NEW, OBJ_FD_PIPE);
		run_fcntl(cmds[i].cmd, SRC, NEW, cmds[i].name);
		check("a cmd that is not a dup pooled or retired something",
		      cmds[i].name, published == 0 && retires == 0 &&
		      pool_count(NEW) == 1);
	}
}

/* A type publish_resource() cannot route stays unpooled, and the copy
 * stays open: the handler must not close what it could not pool. */
static void fcntl_dupfd_of_an_unrouted_type_stays_open(void)
{
	int src = open("/dev/null", O_RDONLY);
	int copy;

	if (src < 0)
		BUG("fd pool: cannot open /dev/null");
	copy = fcntl(src, F_DUPFD, 0);
	if (copy < 0)
		BUG("fd pool: cannot F_DUPFD /dev/null");

	reset();
	unrouted = OBJ_FD_SCRATCH_BLOCK;
	pool_add(false, src, OBJ_FD_SCRATCH_BLOCK);
	run_fcntl(F_DUPFD, (unsigned long) src, (unsigned long) copy,
		  "fcntl(F_DUPFD)");
	check("a copy of an unrouted type was pooled", "fcntl(F_DUPFD)",
	      pool_count(copy) == 0);
	check("the copy of an unrouted type was closed", "fcntl(F_DUPFD)",
	      fcntl(copy, F_GETFD) != -1);

	close(copy);
	close(src);
}

/* close_range()'s flag bits, as the kernel reads them. */
#define CR_UNSHARE		(1U << 1)
#define CR_CLOEXEC		(1U << 2)
#define CR_EXCEPT		(1U << 3)
#define CR_CLOEXEC_ONLY		(1U << 4)

/* How far past the first number of a span close_range reports. */
#define REPORT_CAP		1024

/* The snapshot syscalls/fs/close_range.c installs and its post handler
 * reads back.  A drift in either makes the handler skip the call, which
 * the cases below report as a retire that did not happen. */
struct close_range_snap {
	unsigned long magic;
	unsigned int fd;
	unsigned int max_fd;
	unsigned int flags;
};
#define CLOSE_RANGE_SNAP_MAGIC	0x43524E474D41475FUL

/* Set to leave rec->aN holding what a sibling's stray write could leave
 * there, so a handler that reads the slots, not the snapshot, goes wrong. */
static bool stomped_args;

static void run_close(unsigned long fd, unsigned long retval, int err)
{
	static struct syscallrecord rec;

	memset(&rec, 0, sizeof(rec));
	rec.a1 = fd;
	rec.retval = retval;
	rec.errno_post = err;

	forget_calls();
	syscall_close.post(&rec);
}

/* Run close_range's post handler on a call for [lo, hi] with @flags that
 * returned @retval, the way sanitise would have recorded it. */
static void run_close_range(unsigned int lo, unsigned int hi,
			    unsigned int flags, unsigned long retval)
{
	static struct syscallrecord rec;
	struct close_range_snap *snap = malloc(sizeof(*snap));

	if (snap == NULL)
		BUG("fd pool: cannot allocate a close_range snapshot");
	*snap = (struct close_range_snap) {
		.magic = CLOSE_RANGE_SNAP_MAGIC,
		.fd = lo, .max_fd = hi, .flags = flags,
	};

	memset(&rec, 0, sizeof(rec));
	rec.a1 = stomped_args ? 0 : lo;
	rec.a2 = stomped_args ? UINT_MAX : hi;
	rec.a3 = stomped_args ? 0 : flags;
	rec.post_state = (unsigned long) snap;
	rec.retval = retval;
	rec.errno_post = retval == 0 ? 0 : EINVAL;

	forget_calls();
	syscall_close_range.post(&rec);
}

/* Whether the child was told, one number at a time, that @fd closed. */
static bool reported_closed(int fd)
{
	unsigned int i;

	for (i = 0; i < closes && i < LOG_MAX; i++) {
		if (closed_fds[i] == fd)
			return true;
	}
	return false;
}

/* A close that worked frees its number: whatever local object it held
 * names a file that is gone.  The child's global object is not the pool's
 * to retire, and the close is still reported once. */
static void close_retires_the_fds_objects(void)
{
	reset();
	pool_add(true, SRC, OBJ_FD_SOCKET);
	pool_add(true, 90010, OBJ_FD_EVENTFD);
	run_close(SRC, 0, 0);
	check("the closed fd's local object is still pooled", "close",
	      pool_count(SRC) == 0);
	check("a close retired an object at another number", "close",
	      pool_find(90010, OBJ_FD_EVENTFD) != NULL);
	check("close did not retire its number exactly once", "close",
	      retires == 1 && retired_fd == SRC);
	check("close did not report the close exactly once", "close",
	      closes == 1 && closed_fds[0] == SRC);
	check("close retired a range", "close", range_retires == 0);

	/* A number a stale object and a newer one both name. */
	reset();
	pool_add(true, SRC, OBJ_FD_EVENTFD);
	pool_add(true, SRC, OBJ_FD_PIPE);
	run_close(SRC, 0, 0);
	check("an object survived the close of a number two held", "close",
	      pool_count(SRC) == 0);

	reset();
	pool_add(false, SRC, OBJ_FD_PIPE);
	run_close(SRC, 0, 0);
	check("close retired the child's global object", "close",
	      pool_find(SRC, OBJ_FD_PIPE) != NULL);
}

/* close() takes the number off the fd table before it flushes the file,
 * so a close that failed in the flush freed it all the same.  Only EBADF,
 * no such fd, leaves the number and its object alone, and so does
 * --dry-run's synthesized ENOSYS, which never reached the kernel. */
static void a_failed_close_retires_only_what_it_freed(void)
{
	static const struct {
		int err;
		bool freed;
	} failures[] = {
		{ EIO, true }, { EINTR, true }, { ENOSPC, true },
		{ EBADF, false }, { ENOSYS, false },
	};
	unsigned int i;

	for (i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
		char name[32];

		snprintf(name, sizeof(name), "close failed with errno %d",
			 failures[i].err);
		reset();
		pool_add(true, SRC, OBJ_FD_PIPE);
		run_close(SRC, (unsigned long) -1L, failures[i].err);
		if (failures[i].freed)
			check("a close that freed its number left the object pooled",
			      name, pool_count(SRC) == 0 && retires == 1 &&
			      closes == 1 && closed_fds[0] == SRC);
		else
			check("a close that freed nothing changed the pool",
			      name, pool_count(SRC) == 1 && retires == 0 &&
			      closes == 0);
	}
}

/* A plain close_range, with or without UNSHARE, closes every number in
 * [lo, hi] in the caller's table: unshared, the copy it keeps lacks them. */
static void close_range_retires_the_range(void)
{
	static const struct {
		const char *name;
		unsigned int flags;
	} plain[] = {
		{ "close_range", 0 },
		{ "close_range(UNSHARE)", CR_UNSHARE },
	};
	unsigned int i;
	int live;

	for (i = 0; i < 2; i++) {
		const char *name = plain[i].name;

		reset();
		pool_add(true, 90010, OBJ_FD_EVENTFD);
		pool_add(true, 90020, OBJ_FD_PIPE);
		pool_add(true, 90025, OBJ_FD_SOCKET);
		pool_add(true, 90030, OBJ_FD_TIMERFD);
		pool_add(true, 90040, OBJ_FD_MEMFD);
		pool_add(false, 90025, OBJ_FD_PIPE);
		run_close_range(90020, 90030, plain[i].flags, 0);
		check("an object in the closed range is still pooled", name,
		      pool_find(90020, OBJ_FD_PIPE) == NULL &&
		      pool_find(90025, OBJ_FD_SOCKET) == NULL &&
		      pool_find(90030, OBJ_FD_TIMERFD) == NULL);
		check("an object outside the closed range was retired", name,
		      pool_find(90010, OBJ_FD_EVENTFD) != NULL &&
		      pool_find(90040, OBJ_FD_MEMFD) != NULL);
		check("a close_range retired the child's global object", name,
		      pool_find(90025, OBJ_FD_PIPE) != NULL);
		check("the retire did not take the bounds of the call", name,
		      range_retires == 1 && range_retired_lo == 90020 &&
		      range_retired_hi == 90030);
		check("the close was not reported once for the range", name,
		      range_closes == 1 && closed_lo[0] == 90020 &&
		      closed_hi[0] == 90030);
		check("close_range retired numbers one at a time", name,
		      retires == 0);
	}

	/* The kernel's zero is the whole answer for a plain close: a pooled
	 * number the test never closed goes all the same. */
	live = open("/dev/null", O_RDONLY);
	if (live < 0)
		BUG("fd pool: cannot open /dev/null");
	reset();
	pool_add(true, live, OBJ_FD_PIPE);
	run_close_range(live, live, 0, 0);
	check("a plain close_range probed a pooled fd before retiring it",
	      "close_range", pool_count(live) == 0);
	close(live);
}

/* EXCEPT closes everything outside [lo, hi]: those numbers are what gets
 * retired and what gets reported, as the span below lo and the span above
 * hi, each capped like any other report.  A span no fd can be in is not
 * reported, and an object inside [lo, hi] is not the call's to retire. */
static void close_range_except_retires_the_complement(void)
{
	static const int numbers[] = {
		5, 90010, 90020, 90025, 90030, 90031, 95000, 95015,
	};
	static const struct {
		const char *name;
		unsigned int lo, hi, flags;
		unsigned int spans;
		int span_lo[2], span_hi[2];
	} cases[] = {
		{ "EXCEPT [90020, 90030]", 90020, 90030, CR_EXCEPT, 2,
		  { 0, 90031 }, { REPORT_CAP, 90031 + REPORT_CAP } },
		{ "EXCEPT|UNSHARE [90020, 90030]", 90020, 90030,
		  CR_EXCEPT | CR_UNSHARE, 2,
		  { 0, 90031 }, { REPORT_CAP, 90031 + REPORT_CAP } },
		{ "EXCEPT [0, 90030]", 0, 90030, CR_EXCEPT, 1,
		  { 90031 }, { 90031 + REPORT_CAP } },
		{ "EXCEPT [90020, ~0U]", 90020, UINT_MAX, CR_EXCEPT, 1,
		  { 0 }, { REPORT_CAP } },
		{ "EXCEPT [0, ~0U]", 0, UINT_MAX, CR_EXCEPT, 0 },
		{ "EXCEPT [1 << 31, ~0U]", 1U << 31, UINT_MAX, CR_EXCEPT, 1,
		  { 0 }, { REPORT_CAP } },
		{ "EXCEPT [10, (1 << 31) + 5]", 10, (1U << 31) + 5, CR_EXCEPT,
		  1, { 0 }, { 9 } },
		{ "EXCEPT [10, INT_MAX - 100]", 10, INT_MAX - 100, CR_EXCEPT,
		  2, { 0, INT_MAX - 99 }, { 9, INT_MAX } },
	};
	unsigned int c, n, s;

	for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		const char *name = cases[c].name;

		reset();
		for (n = 0; n < sizeof(numbers) / sizeof(numbers[0]); n++)
			pool_add(true, numbers[n], OBJ_FD_PIPE);
		run_close_range(cases[c].lo, cases[c].hi, cases[c].flags, 0);

		for (n = 0; n < sizeof(numbers) / sizeof(numbers[0]); n++) {
			unsigned int fd = (unsigned int) numbers[n];
			bool outside = fd < cases[c].lo || fd > cases[c].hi;
			char what[64];

			snprintf(what, sizeof(what), "fd %u %s", fd, outside ?
				 "outside the window is still pooled" :
				 "inside the window was retired");
			check(what, name, outside ? pool_count(fd) == 0 :
			      pool_count(fd) == 1);
		}
		check("the closed spans were not reported once each", name,
		      range_closes == cases[c].spans);
		for (s = 0; s < cases[c].spans && s < range_closes; s++)
			check("a reported span is not one the call closed", name,
			      closed_lo[s] == cases[c].span_lo[s] &&
			      closed_hi[s] == cases[c].span_hi[s]);
		check("EXCEPT retired numbers one at a time", name,
		      retires == 0);
	}
}

/* CLOEXEC_ONLY closes only what was close-on-exec, which the call does
 * not say, so the handler asks the kernel about the pooled fds in the
 * span it acted on and retires and reports the ones it no longer has.  A
 * fd that is still open is neither, and nothing outside that span is the
 * call's to retire, whatever state its number is in. */
static void close_range_cloexec_only_retires_what_is_gone(void)
{
	int devnull = open("/dev/null", O_RDONLY);
	int dead_low, live_mid, dead_mid, live_high;
	unsigned int i;

	if (devnull < 0)
		BUG("fd pool: cannot open /dev/null");
	/* dead_low < live_mid < dead_mid < live_high, so the numbers are
	 * real: the test closes two of them and leaves two open. */
	dead_low = fcntl(devnull, F_DUPFD, 300);
	live_mid = dead_low < 0 ? -1 : fcntl(devnull, F_DUPFD, dead_low + 1);
	dead_mid = live_mid < 0 ? -1 : fcntl(devnull, F_DUPFD, live_mid + 1);
	live_high = dead_mid < 0 ? -1 : fcntl(devnull, F_DUPFD, dead_mid + 1);
	if (live_high < 0)
		BUG("fd pool: cannot get four fds above 300");
	close(dead_low);
	close(dead_mid);

	for (i = 0; i < 2; i++) {
		unsigned int flags = CR_CLOEXEC_ONLY | (i ? CR_UNSHARE : 0);
		const char *name = i ? "CLOEXEC_ONLY|UNSHARE" : "CLOEXEC_ONLY";

		reset();
		pool_add(true, dead_low, OBJ_FD_EVENTFD);
		pool_add(true, live_mid, OBJ_FD_PIPE);
		pool_add(true, dead_mid, OBJ_FD_TIMERFD);
		pool_add(true, live_high, OBJ_FD_SOCKET);
		pool_add(true, 90010, OBJ_FD_MEMFD);
		run_close_range(dead_low, dead_mid, flags, 0);
		check("a pooled fd the kernel no longer has stayed pooled",
		      name, pool_count(dead_low) == 0 &&
		      pool_count(dead_mid) == 0);
		check("a pooled fd that is still open was retired", name,
		      pool_count(live_mid) == 1);
		check("an object outside the span was retired", name,
		      pool_count(live_high) == 1 && pool_count(90010) == 1);
		check("the fds found gone were not reported one by one", name,
		      closes == 2 && reported_closed(dead_low) &&
		      reported_closed(dead_mid));
		check("the report named a fd that is still open", name,
		      !reported_closed(live_mid) && !reported_closed(live_high));
		check("a span was reported for a close of some of it", name,
		      range_closes == 0);
	}

	/* The window [live_mid, dead_mid] is what the call leaves alone: the
	 * gone fds below and above it are its doing, and the one in it, gone
	 * though it is, is not. */
	reset();
	pool_add(true, dead_low, OBJ_FD_EVENTFD);
	pool_add(true, live_mid, OBJ_FD_PIPE);
	pool_add(true, dead_mid, OBJ_FD_TIMERFD);
	pool_add(true, live_high, OBJ_FD_SOCKET);
	pool_add(true, 90010, OBJ_FD_MEMFD);
	run_close_range(live_mid, dead_mid, CR_EXCEPT | CR_CLOEXEC_ONLY, 0);
	check("a gone fd outside the window stayed pooled",
	      "EXCEPT|CLOEXEC_ONLY",
	      pool_count(dead_low) == 0 && pool_count(90010) == 0);
	check("an object inside the window was retired", "EXCEPT|CLOEXEC_ONLY",
	      pool_count(live_mid) == 1 && pool_count(dead_mid) == 1);
	check("an open fd outside the window was retired",
	      "EXCEPT|CLOEXEC_ONLY", pool_count(live_high) == 1);
	check("the fds found gone were not reported one by one",
	      "EXCEPT|CLOEXEC_ONLY", closes == 2 &&
	      reported_closed(dead_low) && reported_closed(90010));
	check("the report named a fd the call left open",
	      "EXCEPT|CLOEXEC_ONLY", !reported_closed(live_mid) &&
	      !reported_closed(dead_mid) && !reported_closed(live_high));
	check("a span was reported for a close of some of it",
	      "EXCEPT|CLOEXEC_ONLY", range_closes == 0);

	close(live_mid);
	close(live_high);
	close(devnull);
}

/* Marking close-on-exec closes nothing, and the kernel never answers a
 * flags word it does not know with a zero. */
static void close_range_that_closes_nothing(void)
{
	static const unsigned int flags[] = {
		CR_CLOEXEC, CR_CLOEXEC | CR_UNSHARE, CR_CLOEXEC | CR_EXCEPT,
		CR_CLOEXEC | CR_CLOEXEC_ONLY, 1U << 30, 1U << 31,
		CR_EXCEPT | (1U << 5),
	};
	unsigned int i;

	for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
		char name[48];

		snprintf(name, sizeof(name), "close_range flags %#x", flags[i]);
		reset();
		pool_add(true, 90025, OBJ_FD_SOCKET);
		run_close_range(90020, 90030, flags[i], 0);
		check("a close_range that closed nothing retired objects",
		      name, range_retires == 0 && pool_count(90025) == 1);
		check("a close_range that closed nothing reported a close",
		      name, range_closes == 0 && closes == 0);
	}
}

/* [lo, ~0U] is how a caller closes everything above lo.  The retire
 * walks the pool, so it reaches every object however far up the range
 * goes, where the span the call reports is capped. */
static void close_range_to_the_top_walks_the_pool(void)
{
	reset();
	pool_add(true, 90010, OBJ_FD_EVENTFD);
	pool_add(true, 90020, OBJ_FD_PIPE);
	pool_add(true, 90015 + 5000, OBJ_FD_SOCKET);
	run_close_range(90015, UINT_MAX, 0, 0);
	check("an object above lo survived a close_range to UINT_MAX",
	      "close_range", pool_find(90020, OBJ_FD_PIPE) == NULL &&
	      pool_find(90015 + 5000, OBJ_FD_SOCKET) == NULL);
	check("an object below lo was retired by a close_range to UINT_MAX",
	      "close_range", pool_find(90010, OBJ_FD_EVENTFD) != NULL);
	check("the retire was not given the whole range", "close_range",
	      range_retires == 1 && range_retired_lo == 90015 &&
	      range_retired_hi == UINT_MAX);
}

/* A call that failed closed nothing, and a snapshot that names no range
 * the kernel could have closed is not acted on.  The slots the post
 * handler is called with are not what it acts on either. */
static void close_range_guards(void)
{
	reset();
	pool_add(true, 90025, OBJ_FD_SOCKET);
	run_close_range(90020, 90030, 0, (unsigned long) -1L);
	check("a close_range that failed changed the pool", "close_range",
	      range_retires == 0 && range_closes == 0 &&
	      pool_count(90025) == 1);

	run_close_range(90030, 90020, 0, 0);
	check("an inverted range retired objects", "close_range",
	      range_retires == 0 && pool_count(90025) == 1);

	run_close_range(90030, 90020, CR_EXCEPT, 0);
	check("an inverted EXCEPT window retired objects", "close_range",
	      range_retires == 0 && pool_count(90025) == 1);

	run_close_range(1U << 31, UINT_MAX, 0, 0);
	check("a range of negative fds retired objects", "close_range",
	      range_retires == 0 && pool_count(90025) == 1);

	/* A stray write to the slots after the call must not redirect the
	 * retire: it destroys objects. */
	reset();
	pool_add(true, 90025, OBJ_FD_SOCKET);
	pool_add(true, 90050, OBJ_FD_PIPE);
	stomped_args = true;
	run_close_range(90020, 90030, 0, 0);
	stomped_args = false;
	check("a stomped slot redirected the retire", "close_range",
	      range_retired_lo == 90020 && range_retired_hi == 90030 &&
	      pool_find(90050, OBJ_FD_PIPE) != NULL &&
	      pool_find(90025, OBJ_FD_SOCKET) == NULL);
}

/* The generator draws the flags from the entry's list, so the list is
 * what the guard and the retire above have to cover: every flag the
 * kernel reads, and none it does not. */
static void close_range_offers_the_flags_it_handles(void)
{
	const struct arglist *list = &syscall_close_range.arg_params[2].list;
	unsigned long offered = 0;
	unsigned int i;

	for (i = 0; i < list->num; i++)
		offered |= list->values[i];
	check("the flags offered are not the flags the handlers cover",
	      "close_range", offered == (CR_UNSHARE | CR_CLOEXEC | CR_EXCEPT |
					 CR_CLOEXEC_ONLY));
}

/* close_range()'s disposable high-fd sandbox, which its sanitiser opens
 * on first use: where it starts and the most slots it takes. */
#define SANDBOX_BASE		2048
#define SANDBOX_SLOTS		64

/* The sanitiser's last word on the range, whatever shape it picked: the
 * kernel is never told to close a protected fd.  A plain range holds none
 * of them.  EXCEPT closes everything outside the range, so there the
 * range holds all of them.  The fake child's protected fds are stderr and
 * its two kcov fds. */
static void close_range_sanitiser_spares_protected_fds(void)
{
	static const struct {
		unsigned long a1, a2;
	} presets[] = {
		{ 90000, 90010 },	/* clear of every protected fd */
		{ 90010, 90000 },	/* inverted; may come out upright */
		{ 3, 90100 },		/* holds one kcov fd, not the other */
		{ 90100, 90101 },	/* the kcov pair, not stderr */
		{ 0, 1 },		/* below stderr */
		{ 3, UINT_MAX },	/* open-ended */
		{ UINT_MAX, UINT_MAX },	/* gen_arg_fd's exhaustion fallback */
	};
	static const unsigned int flagsets[] = {
		0, CR_UNSHARE, CR_CLOEXEC_ONLY, CR_EXCEPT,
		CR_EXCEPT | CR_UNSHARE, CR_EXCEPT | CR_CLOEXEC_ONLY,
		CR_EXCEPT | CR_CLOEXEC,
	};
	static const unsigned int protected_fds[] = {
		STDERR_FILENO, KCOV_FD, KCOV_CMP_FD,
	};
	const unsigned int npresets = sizeof(presets) / sizeof(presets[0]);
	const unsigned int nflagsets = sizeof(flagsets) / sizeof(flagsets[0]);
	static struct syscallrecord rec;
	unsigned int except_calls = 0, plain_calls = 0;
	unsigned int widened = 0, truncated = 0;
	unsigned int n, p;

	/* The registry the cases expect: stderr and the fake child's kcov
	 * pair, and nothing in between. */
	if (lowest_protected_fd_in_range(STDERR_FILENO + 1, KCOV_FD - 1) >= 0)
		BUG("fd pool: an unexpected fd is protected");

	kcov_shm = calloc(1, sizeof(*kcov_shm));
	if (kcov_shm == NULL)
		BUG("fd pool: cannot allocate the kcov diag block");
	rnd_seed(1);

	for (n = 0; n < 150 * npresets * nflagsets; n++) {
		unsigned int w = n / nflagsets % npresets;
		unsigned int f = n % nflagsets;
		unsigned long before =
			kcov_shm->pc_diag.close_range_protect_truncate_count;
		bool ok = true, widened_now = false, truncated_now = false;
		unsigned int lo, hi, flags;
		char name[96];

		memset(&rec, 0, sizeof(rec));
		rec.a1 = presets[w].a1;
		rec.a2 = presets[w].a2;
		rec.a3 = flagsets[f];
		syscall_close_range.sanitise(&rec);
		lo = (unsigned int) rec.a1;
		hi = (unsigned int) rec.a2;
		flags = (unsigned int) rec.a3;

		/* An inverted range is refused before anything is closed. */
		if (lo <= hi) {
			for (p = 0; p < 3; p++) {
				bool inside = lo <= protected_fds[p] &&
					      protected_fds[p] <= hi;

				ok = ok && (inside == !!(flags & CR_EXCEPT));
			}
			if (flags & CR_EXCEPT) {
				except_calls++;
				widened_now = lo == STDERR_FILENO &&
					      hi == KCOV_CMP_FD;
			} else {
				plain_calls++;
				truncated_now = lo == 3 && hi == KCOV_FD - 1;
			}
		}
		widened += widened_now;
		truncated += truncated_now;

		snprintf(name, sizeof(name),
			 "sanitise(preset %u, flags %#x) -> [%u, %u], flags %#x",
			 w, flagsets[f], lo, hi, flags);
		check(flags & CR_EXCEPT ?
		      "EXCEPT left a protected fd outside its window" :
		      "a plain range sweeps a protected fd", name, ok);
		check("a rewritten range was not counted exactly once", name,
		      (!widened_now && !truncated_now) ||
		      kcov_shm->pc_diag.close_range_protect_truncate_count ==
		      before + 1);

		/* Release the snapshot sanitise took. */
		rec.retval = (unsigned long) -1L;
		rec.errno_post = EINVAL;
		syscall_close_range.post(&rec);
		if (!ok)
			goto out;
	}

	/* The loop above is only worth anything if it reached the shapes
	 * the guard acts on. */
	check("the sanitiser never produced an EXCEPT range", "close_range",
	      except_calls >= 100);
	check("the sanitiser never produced a plain range", "close_range",
	      plain_calls >= 100);
	check("the sanitiser never widened an EXCEPT range", "close_range",
	      widened > 0);
	check("the sanitiser never truncated a plain range", "close_range",
	      truncated > 0);

out:
	free(kcov_shm);
	kcov_shm = NULL;
}

/* The sanitiser's snapshot records the triple it vetted, and the guard on
 * the range only means something if that triple is what reaches the
 * kernel.  Chain substitution rewrites one slot after the sanitiser, and
 * all three take a number: a return of 8 in the flags is EXCEPT, a pid in
 * max_fd runs the range back over the kcov fds.  validate_arg_coupling()
 * has to pass a call as vetted, judging each slot as the kernel reads it,
 * refuse any other, and refuse a record whose snapshot cannot vouch for
 * it: an unvetted range does more harm than one wasted call. */
static void close_range_validator_holds_the_vetted_range(void)
{
	static const struct {
		unsigned long a1, a2, a3;
	} presets[] = {
		{ 90000, 90010, 0 },
		{ 3, 90100, CR_EXCEPT },
		{ 90010, 90000, CR_UNSHARE },
		{ UINT_MAX, UINT_MAX, CR_EXCEPT | CR_CLOEXEC_ONLY },
		{ 5, 9, CR_CLOEXEC },
	};
	const unsigned int npresets = sizeof(presets) / sizeof(presets[0]);
	struct syscallentry entry = syscall_close_range;
	struct syscallentry other = { .name = "probe", .num_args = 3 };
	static struct syscallrecord rec;
	unsigned long *const slot[3] = { &rec.a1, &rec.a2, &rec.a3 };
	struct close_range_snap *snap;
	unsigned long was;
	unsigned int n, s;

	entry.is_close_range = true;
	rnd_seed(1);

	/* Whatever the sanitiser draws is a call it vetted. */
	for (n = 0; n < 500; n++) {
		memset(&rec, 0, sizeof(rec));
		rec.entry = &entry;
		rec.a1 = presets[n % npresets].a1;
		rec.a2 = presets[n % npresets].a2;
		rec.a3 = presets[n % npresets].a3;
		entry.sanitise(&rec);
		check("a call the sanitiser vetted was refused", "close_range",
		      validate_arg_coupling(&rec) == 0);
		rec.retval = (unsigned long) -1L;
		rec.errno_post = EINVAL;
		entry.post(&rec);
	}

	memset(&rec, 0, sizeof(rec));
	rec.entry = &entry;
	rec.a1 = 90000;
	rec.a2 = 90010;
	entry.sanitise(&rec);
	snap = (struct close_range_snap *) rec.post_state;

	/* Each slot, rewritten to what a substitute can be: EXCEPT, a value
	 * past the base the protected fds sit above, all ones, and the two
	 * ways an upper half can come along.  Only a rewrite the kernel reads
	 * differently is refused. */
	for (s = 0; s < 3; s++) {
		was = *slot[s];
		for (n = 0; n < 6; n++) {
			unsigned long sub;
			bool changed;
			char name[64];

			switch (n) {
			case 0: sub = CR_EXCEPT; break;
			case 1: sub = PROTECTED_FD_HIGH_BASE + 5; break;
			case 2: sub = UINT_MAX; break;
			case 3: sub = was | (1UL << 40); break;
			case 4: sub = (1UL << 40) | (was ^ 1); break;
			default: sub = was; break;
			}
			changed = (unsigned int) sub != (unsigned int) was;
			*slot[s] = sub;
			snprintf(name, sizeof(name), "a%u := %#lx, vetted %#lx",
				 s + 1, sub, was);
			check(changed ? "a rewritten slot reached the kernel" :
			      "a slot the kernel reads as vetted was refused",
			      name, validate_arg_coupling(&rec) ==
			      (changed ? -1 : 0));
			*slot[s] = was;
		}
	}

	/* Nothing vouches for the range without its snapshot: none at all,
	 * a pid where the pointer was, one the ownership table does not
	 * hold, or one whose magic is not close_range's. */
	rec.post_state = 0;
	check("a call with no snapshot was passed", "close_range",
	      validate_arg_coupling(&rec) == -1);
	rec.post_state = 12345;
	check("a call whose snapshot is a pid was passed", "close_range",
	      validate_arg_coupling(&rec) == -1);
	rec.post_state = (unsigned long) snap;
	post_state_disowned = snap;
	check("a call whose snapshot is not owned was passed", "close_range",
	      validate_arg_coupling(&rec) == -1);
	post_state_disowned = NULL;
	snap->magic ^= 1UL;
	check("a call whose snapshot has the wrong magic was passed",
	      "close_range", validate_arg_coupling(&rec) == -1);
	snap->magic ^= 1UL;
	check("a call refused for its snapshot was refused once it was whole",
	      "close_range", validate_arg_coupling(&rec) == 0);

	/* Only close_range is held to a snapshot. */
	rec.entry = &other;
	rec.a3 = CR_EXCEPT;
	check("a syscall other than close_range was refused", "close_range",
	      validate_arg_coupling(&rec) == 0);
	rec.entry = &entry;

	rec.retval = (unsigned long) -1L;
	rec.errno_post = EINVAL;
	entry.post(&rec);
}

void dup_pool_self_check(void);
void dup_pool_self_check(void)
{
	bool sandbox_was_open[SANDBOX_SLOTS];
	unsigned int i;

	fake_child.kcov.fd = KCOV_FD;
	fake_child.kcov.cmp_fd = KCOV_CMP_FD;
	fake_child.tainted_fd = -1;
	fake_child.fail_nth_fd = -1;
	fake_this_child = &fake_child;
	fake_find_object_by_fd = fake_lookup;

	copy_joins_the_sources_pool();
	old_object_is_retired();
	same_fd_is_a_no_op();
	failed_call_pools_nothing();
	stdio_is_not_pooled();
	protected_fds_are_not_pooled();
	unrouted_type_stays_open();
	fcntl_dupfd_pools_the_copy();
	fcntl_other_cmds_pool_nothing();
	fcntl_dupfd_of_an_unrouted_type_stays_open();
	close_retires_the_fds_objects();
	a_failed_close_retires_only_what_it_freed();
	close_range_retires_the_range();
	close_range_except_retires_the_complement();
	close_range_cloexec_only_retires_what_is_gone();
	close_range_that_closes_nothing();
	close_range_to_the_top_walks_the_pool();
	close_range_guards();
	close_range_offers_the_flags_it_handles();

	/* The sanitiser opens close_range's sandbox on first use, in this
	 * process: put the fd table back once both tests are done. */
	for (i = 0; i < SANDBOX_SLOTS; i++)
		sandbox_was_open[i] =
			fcntl(SANDBOX_BASE + (int) i, F_GETFD) != -1;
	close_range_sanitiser_spares_protected_fds();
	close_range_validator_holds_the_vetted_range();
	for (i = 0; i < SANDBOX_SLOTS; i++) {
		if (!sandbox_was_open[i])
			close(SANDBOX_BASE + (int) i);
	}

	fake_find_object_by_fd = NULL;
	fake_this_child = NULL;

	if (failed != 0)
		BUG("an fd handler pooled or retired the wrong objects");
}
