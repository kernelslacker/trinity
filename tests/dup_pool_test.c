/*
 * Self-check for how dup, dup2 and dup3 pool the descriptor they return.
 * The post handlers run as shipped against a fake object pool.  A copy
 * joins the pool its source came from, and stays out of every pool when
 * the source is untracked or protected, the call failed, or the type is
 * one publish_resource() does not route.  Whatever object a number held
 * before the call is retired, copy pooled or not, and a retire never
 * closes the number: it names the copy by then.  The close itself is
 * reported once, through notify_child_fd_closed(), as before.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "child.h"
#include "debug.h"		/* BUG */
#include "fd-event.h"		/* notify_child_fd_closed */
#include "objects.h"
#include "publish_resource.h"
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_dup, syscall_dup2, syscall_dup3 */

extern struct childdata *fake_this_child;	/* fake_shm.c */
extern struct object *(*fake_find_object_by_fd)(int fd);	/* fake_fds.c */

/* Numbers no fd table in the test holds, so the post handlers' fstat()
 * oracle finds nothing to compare. */
#define SRC		90001
#define NEW		90002
#define KCOV_FD		90100
#define KCOV_CMP_FD	90101

#define POOL_MAX	16
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
static int closed_fd;

/* A type publish_resource() does not route: it returns NULL for it. */
static enum objecttype unrouted;

static unsigned int failed;

static void check(const char *what, const char *case_name, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "dup pool: %s: %s\n", case_name, what);
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
	BUG("dup pool: the fake pool is full");
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
	BUG("dup pool: the fake pool is full");
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
	closes++;
	closed_fd = fd;
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

	published = 0;
	retires = 0;
	closes = 0;
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
		      closes == 1 && closed_fd == NEW);

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
		BUG("dup pool: cannot open /dev/null");
	copy = dup(src);
	if (copy < 0)
		BUG("dup pool: cannot dup /dev/null");

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

void dup_pool_self_check(void);
void dup_pool_self_check(void)
{
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

	fake_find_object_by_fd = NULL;
	fake_this_child = NULL;

	if (failed != 0)
		BUG("a dup handler pooled or retired the wrong objects");
}
