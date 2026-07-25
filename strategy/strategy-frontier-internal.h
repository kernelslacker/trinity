/*
 * Private declarations shared between strategy-frontier.c and its
 * per-seam siblings (strategy-frontier-bitmap.c etc.).  Not a public
 * API -- do NOT include from outside the strategy-frontier* translation
 * units.
 */
#ifndef _TRINITY_STRATEGY_FRONTIER_INTERNAL_H
#define _TRINITY_STRATEGY_FRONTIER_INTERNAL_H

#include <stdbool.h>

/*
 * Producer-observer bitmap accessors.  Implementation lives in
 * strategy-frontier-bitmap.c; the bitmap tables themselves stay file-
 * static inside that TU.
 */
void ensure_producer_observer_built(void);
bool producer_observer_lookup(unsigned int nr, bool do32);

#endif /* _TRINITY_STRATEGY_FRONTIER_INTERNAL_H */
