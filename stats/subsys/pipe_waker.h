#ifndef _TRINITY_STATS_SUBSYS_PIPE_WAKER_H
#define _TRINITY_STATS_SUBSYS_PIPE_WAKER_H

/*
 * pipe-waker counters.  Iterates pipe writer-end fds and writes a
 * single byte non-blocking, so a concurrent reader on an empty pipe
 * never parks in wait_event_interruptible_exclusive(pipe->rd_wait).
 * The kernel already makes pipe-reads killable; this is a belt-and-
 * suspenders defense against orphaned blocking readers (see
 * fds/pipes.c open_pipe_pair() comment).
 *
 * Bespoke (non-category) RAW group.  All bumps RELAXED on shm->stats;
 * diagnostic-only, no live decision consumes any of these counters.
 * The surrounding struct stats_s composes an instance of struct
 * pipe_waker_stats as its "pipe_waker" member.
 */
struct pipe_waker_stats {
	unsigned long bytes_written;	/* successful 1-byte write() to a writer-end pipe fd */
	unsigned long no_target;	/* fired but the pool walk returned no writer-end fd */
	unsigned long write_failed;	/* write() returned <0 (EAGAIN on full pipe, EBADF on closed fd, etc.) */
};

#endif	/* _TRINITY_STATS_SUBSYS_PIPE_WAKER_H */
