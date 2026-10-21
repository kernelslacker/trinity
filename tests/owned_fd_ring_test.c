/*
 * Self-check for owned_fd_ring_record() (include/owned-fd-ring.h): a ring
 * closes an aged-out fd only while its number still names the file it
 * recorded.  A fuzzed close() frees the number and the next fd-creating
 * call hands it to an unrelated file, which the ring must leave open.
 * Pipes stand in for provider fds: each has an inode of its own, and the
 * two ends of one pipe share it, which models a number that fstat() cannot
 * tell from the one that was recorded.
 */

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "owned-fd-ring.h"

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
	memset(ring, 0, sizeof(*ring));
	owned_fd_ring_record(ring, owned);
	if (close(owned) < 0)
		BUG("owned fd ring: close failed");
	return owned;
}

void owned_fd_ring_self_check(void);
void owned_fd_ring_self_check(void)
{
	struct owned_fd_ring ring;
	int fresh[MAX_OWNED_FDS];
	struct stat st, want;
	int a[2], b[2], owned;

	if (pipe(a) < 0 || pipe(b) < 0)
		BUG("owned fd ring: pipe failed");

	/* The owned fd is closed once the ring wraps, and not before. */
	memset(&ring, 0, sizeof(ring));
	owned = dup(a[1]);
	if (owned < 0)
		BUG("owned fd ring: dup failed");
	owned_fd_ring_record(&ring, owned);
	record_fresh(&ring, b[1], fresh, MAX_OWNED_FDS - 1);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: closed an fd before the ring wrapped");
	record_fresh(&ring, b[1], fresh + MAX_OWNED_FDS - 1, 1);
	if (fcntl(owned, F_GETFD) >= 0)
		BUG("owned fd ring: kept an fd past the end of the ring");
	close_all(fresh, MAX_OWNED_FDS);

	/*
	 * The owned fd was closed behind the ring's back and its number went
	 * to a different file: eviction must leave that file alone.
	 */
	owned = own_and_close(&ring, a[1]);
	if (dup2(b[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	record_fresh(&ring, b[1], fresh, MAX_OWNED_FDS);
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
	owned = own_and_close(&ring, a[1]);
	if (dup2(a[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	owned_fd_ring_record(&ring, owned);
	record_fresh(&ring, b[1], fresh, MAX_OWNED_FDS - 1);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: a stale slot closed its number's new owner");
	record_fresh(&ring, b[1], fresh + MAX_OWNED_FDS - 1, 1);
	if (fcntl(owned, F_GETFD) >= 0)
		BUG("owned fd ring: kept a re-issued fd past the end of the ring");
	close_all(fresh, MAX_OWNED_FDS);

	/*
	 * An fd whose identity cannot be read when it is recorded is never
	 * closed.  The number is already free here, so fstat() fails, and by
	 * the time the ring wraps it names an unrelated file.
	 */
	memset(&ring, 0, sizeof(ring));
	owned = dup(a[1]);
	if (owned < 0 || close(owned) < 0)
		BUG("owned fd ring: cannot free an fd number");
	owned_fd_ring_record(&ring, owned);
	if (dup2(b[0], owned) != owned)
		BUG("owned fd ring: cannot recycle the fd number");
	record_fresh(&ring, b[1], fresh, MAX_OWNED_FDS);
	if (fcntl(owned, F_GETFD) < 0)
		BUG("owned fd ring: closed an fd it could not identify");
	close_all(fresh, MAX_OWNED_FDS);
	close(owned);

	close(a[0]);
	close(a[1]);
	close(b[0]);
	close(b[1]);
}
