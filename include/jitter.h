#ifndef _TRINITY_JITTER_H
#define _TRINITY_JITTER_H

#include <stdlib.h>

/*
 * One-shot per-invocation ±50% jitter on a per-childop upper bound.
 *
 * For N >= 2 this yields a value in [N/2 + 1, 3*N/2], with the original
 * constant acting as the centre of the jitter range.  Always returns >= 1.
 * Uses the global rand() — childops already pull from it heavily, so no
 * new RNG plumbing is required.
 *
 * Intended use: replace bare uses of a hardcoded per-invocation iteration
 * or budget cap inside a hot-loop guard so that successive invocations
 * sample different temporal pressure profiles, exposing timing-sensitive
 * bugs that a fixed budget would mask.
 */
#define JITTER_RANGE(N)		((N) / 2 + (rand() % (N) + 1))

#endif	/* _TRINITY_JITTER_H */
