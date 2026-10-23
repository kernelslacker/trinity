/*
 * Self-check for owned_fd_ring_record() (include/owned-fd-ring.h): a ring
 * closes an aged-out fd only while its number still names the file it
 * recorded.  A fuzzed close() frees the number and the next fd-creating
 * call hands it to an unrelated file, which the ring must leave open.
 * owned_fd_ring_retire() takes a number out of every ring without closing
 * it, and leaves the other slots as they were.  account_fd_and_group() runs
 * as shipped and retires the number of every fd a call returns, except one
 * the call was handed itself.
 * Pipes stand in for provider fds: each has an inode of its own, and the
 * two ends of one pipe share it, which models a number that fstat() cannot
 * tell from the one that was recorded.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "owned-fd-ring.h"
#include "params.h"		/* group_bias */
#include "random_syscall/strategy-accounting-internal.h"	/* account_fd_and_group */
#include "strategy.h"		/* frontier_group_antilock_mode */
#include "syscall.h"		/* struct syscallentry, struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_dup, syscall_dup2 */
#include "utils-macros.h"	/* ARRAY_SIZE */

/*
 * What account_fd_and_group() reaches besides the rings, none of it under
 * test: the two knobs it reads stay off, and the live-fd push is counted.
 */
bool group_bias;
enum frontier_group_antilock_mode frontier_group_antilock_mode;

static unsigned int pushes;
static int pushed_fd;

void child_fd_ring_push(struct child_fd_ring *ring, int fd)
{
	(void) ring;
	pushes++;
	pushed_fd = fd;
}

/* Record @n fresh dups of @src, saving their numbers in @out for cleanup. */
static void record_fresh(struct owned_fd_ring *ring, int src, int *out,
			 unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		out[i] = dup(src);
		if (out[i] < 0)
			BUG("owned fd ring: dup failed");
		owned_fd_ring_record(ring, out[i]);
	}
}

static void close_all(const int *fds, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		close(fds[i]);
}

/*
 * Make @ring own a dup of @src, then close that fd behind the ring's back.
 * Returns the number it freed.
 */
static int own_and_close(struct owned_fd_ring *ring, int src)
{
	int owned = dup(src);

	if (owned < 0)
		BUG("owned fd ring: dup failed");
	owned_fd_ring_record(ring, owned);
	if (close(owned) < 0)
		BUG("owned fd ring: close failed");
	return owned;
}

/* Wrap @ring, and say whether @fd is still open once it has. */
static bool open_after_wrap(struct owned_fd_ring *ring, int src, int fd)
{
	int fresh[MAX_OWNED_FDS];
	bool still_open;

	record_fresh(ring, src, fresh, MAX_OWNED_FDS);
	still_open = fcntl(fd, F_GETFD) >= 0;
	close_all(fresh, MAX_OWNED_FDS);
	return still_open;
}

/* Account a call that returned @retval, given @a1 and @a2 as its arguments. */
static void account(struct syscallentry *entry, int a1, int a2, int retval)
{
	static struct syscallrecord rec;
	static struct childdata child;

	memset(&rec, 0, sizeof(rec));
	rec.a1 = (unsigned long) a1;
	rec.a2 = (unsigned long) a2;
	rec.retval = (unsigned long) retval;
	pushes = 0;
	account_fd_and_group(&child, entry, &rec, false);
}

/*
 * A call that returns an fd retires the slots naming it, so a stale slot
 * cannot close the new owner when its ring wraps: a dup() handed a number its
 * ring still lists, and a dup2() that put another file under a listed one.
 * A call that hands back the fd it was given opened nothing, and a return
 * value that is not an fd names nothing: the slot stays, and the ring closes
 * the fd as it would have.
 */
static void account_self_check(const int *a, const int *b)
{
	static struct owned_fd_ring dup_ring, dup2_ring, same_ring, typed_ring,
				    bytes_ring;
	/* signalfd() on an existing signalfd answers with the fd it was given. */
	static struct syscallentry typed_operand = {
		.rettype = RET_FD,
		.argtype = { [0] = ARG_FD_SIGNALFD },
	};
	/* A read(): a byte count that can equal an fd number. */
	static struct syscallentry byte_count = {
		.rettype = RET_NUM_BYTES,
		.argtype = { [0] = ARG_FD },
	};
	const struct {
		struct owned_fd_ring *ring;
		struct syscallentry *entry;
		bool a1_owned, a2_owned;
		const char *bug;
	} keeps[] = {
		{ &same_ring, &syscall_dup2, true, true,
		  "owned fd ring: dup2(fd, fd) retired a live slot" },
		{ &typed_ring, &typed_operand, true, false,
		  "owned fd ring: returning a typed fd operand retired a live slot" },
		{ &bytes_ring, &byte_count, false, false,
		  "owned fd ring: a return value that is not an fd retired a slot" },
	};
	unsigned int i;
	int owned;

	owned = own_and_close(&dup_ring, a[1]);
	if (dup2(a[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	account(&syscall_dup, a[0], 0, owned);
	if (pushes != 1 || pushed_fd != owned)
		BUG("owned fd ring: a returned fd skipped the live-fd push");
	if (!open_after_wrap(&dup_ring, b[1], owned))
		BUG("owned fd ring: a stale slot closed an fd a call returned");
	close(owned);

	owned = dup(a[1]);
	if (owned < 0)
		BUG("owned fd ring: dup failed");
	owned_fd_ring_record(&dup2_ring, owned);
	if (dup2(a[0], owned) != owned)
		BUG("owned fd ring: cannot put another file under the fd");
	account(&syscall_dup2, a[0], owned, owned);
	if (!open_after_wrap(&dup2_ring, b[1], owned))
		BUG("owned fd ring: a slot closed the file dup2() put under its number");
	close(owned);

	for (i = 0; i < ARRAY_SIZE(keeps); i++) {
		owned = dup(a[1]);
		if (owned < 0)
			BUG("owned fd ring: dup failed");
		owned_fd_ring_record(keeps[i].ring, owned);
		account(keeps[i].entry, keeps[i].a1_owned ? owned : a[0],
			keeps[i].a2_owned ? owned : 0, owned);
		if (keeps[i].entry->rettype == RET_FD &&
		    (pushes != 1 || pushed_fd != owned))
			BUG("owned fd ring: a returned fd skipped the live-fd push");
		if (open_after_wrap(keeps[i].ring, b[1], owned))
			BUG(keeps[i].bug);
	}
}

void owned_fd_ring_self_check(void);
void owned_fd_ring_self_check(void)
{
	/*
	 * A ring links itself into a process-wide list the first time it
	 * records, so each scenario gets one of its own with static storage
	 * instead of clearing one.
	 */
	static struct owned_fd_ring wrap_ring, recycled_ring, reissued_ring,
				    unreadable_ring, first_ring, second_ring,
				    retired_ring, selective_ring;
	int fresh[MAX_OWNED_FDS];
	struct stat st, want;
	int a[2], b[2], owned, other;

	if (pipe(a) < 0 || pipe(b) < 0)
		BUG("owned fd ring: pipe failed");

	/* The owned fd is closed once the ring wraps, and not before. */
	owned = dup(a[1]);
	if (owned < 0)
		BUG("owned fd ring: dup failed");
	owned_fd_ring_record(&wrap_ring, owned);
	record_fresh(&wrap_ring, b[1], fresh, MAX_OWNED_FDS - 1);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: closed an fd before the ring wrapped");
	record_fresh(&wrap_ring, b[1], fresh + MAX_OWNED_FDS - 1, 1);
	if (fcntl(owned, F_GETFD) >= 0)
		BUG("owned fd ring: kept an fd past the end of the ring");
	close_all(fresh, MAX_OWNED_FDS);

	/*
	 * The owned fd was closed behind the ring's back and its number went
	 * to a different file: eviction must leave that file alone.
	 */
	owned = own_and_close(&recycled_ring, a[1]);
	if (dup2(b[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	record_fresh(&recycled_ring, b[1], fresh, MAX_OWNED_FDS);
	if (fstat(owned, &st) < 0 || fstat(b[0], &want) < 0 ||
	    st.st_dev != want.st_dev || st.st_ino != want.st_ino)
		BUG("owned fd ring: closed a recycled fd number");
	close_all(fresh, MAX_OWNED_FDS);
	close(owned);

	/*
	 * Same, but the number came back as an fd the ring was handed again,
	 * and its new file is one fstat() cannot tell from the old.  The
	 * stale slot must not close it while the new slot still owns it.
	 */
	owned = own_and_close(&reissued_ring, a[1]);
	if (dup2(a[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	owned_fd_ring_record(&reissued_ring, owned);
	record_fresh(&reissued_ring, b[1], fresh, MAX_OWNED_FDS - 1);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: a stale slot closed its number's new owner");
	record_fresh(&reissued_ring, b[1], fresh + MAX_OWNED_FDS - 1, 1);
	if (fcntl(owned, F_GETFD) >= 0)
		BUG("owned fd ring: kept a re-issued fd past the end of the ring");
	close_all(fresh, MAX_OWNED_FDS);

	/*
	 * An fd whose identity cannot be read when it is recorded is never
	 * closed.  The number is already free here, so fstat() fails, and by
	 * the time the ring wraps it names an unrelated file.
	 */
	owned = dup(a[1]);
	if (owned < 0 || close(owned) < 0)
		BUG("owned fd ring: cannot free an fd number");
	owned_fd_ring_record(&unreadable_ring, owned);
	if (dup2(b[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	record_fresh(&unreadable_ring, b[1], fresh, MAX_OWNED_FDS);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: closed an fd it could not identify");
	close_all(fresh, MAX_OWNED_FDS);
	close(owned);

	/*
	 * The number came back as an fd another provider's ring was handed,
	 * and its new file is one fstat() cannot tell from the old.  The
	 * first ring's stale slot must not close it; the second ring owns it
	 * and closes it when that ring wraps.
	 */
	owned = own_and_close(&first_ring, a[1]);
	if (dup2(a[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	owned_fd_ring_record(&second_ring, owned);
	record_fresh(&first_ring, b[1], fresh, MAX_OWNED_FDS);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: another ring's stale slot closed the new owner");
	close_all(fresh, MAX_OWNED_FDS);
	record_fresh(&second_ring, b[1], fresh, MAX_OWNED_FDS);
	if (fcntl(owned, F_GETFD) >= 0)
		BUG("owned fd ring: kept an fd past the end of its ring");
	close_all(fresh, MAX_OWNED_FDS);

	/*
	 * The number was freed behind the ring's back and handed out again to
	 * a file fstat() cannot tell from the recorded one, by a call other
	 * than the ring's provider.  Its stale slot is retired, so the ring
	 * leaves the new fd open when it wraps.
	 */
	owned = own_and_close(&retired_ring, a[1]);
	if (dup2(a[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	owned_fd_ring_retire(owned);
	record_fresh(&retired_ring, b[1], fresh, MAX_OWNED_FDS);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: a retired slot closed its number's new owner");
	close_all(fresh, MAX_OWNED_FDS);
	close(owned);

	/*
	 * Retiring a number closes nothing and touches no other slot: the
	 * fd stays open now and after the wrap, and the ring still closes the
	 * fd it owns that was not retired.
	 */
	owned = dup(a[1]);
	other = dup(a[1]);
	if (owned < 0 || other < 0)
		BUG("owned fd ring: dup failed");
	owned_fd_ring_record(&selective_ring, owned);
	owned_fd_ring_record(&selective_ring, other);
	owned_fd_ring_retire(owned);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: retiring a slot closed its fd");
	record_fresh(&selective_ring, b[1], fresh, MAX_OWNED_FDS);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: closed an fd after its slot was retired");
	if (fcntl(other, F_GETFD) >= 0)
		BUG("owned fd ring: retiring a number kept another slot's fd");
	close_all(fresh, MAX_OWNED_FDS);
	close(owned);

	account_self_check(a, b);

	close(a[0]);
	close(a[1]);
	close(b[0]);
	close(b[1]);
}
