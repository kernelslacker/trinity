#ifndef _TRINITY_STATS_SUBSYS_CRED_CLASS_H
#define _TRINITY_STATS_SUBSYS_CRED_CLASS_H

#include "cred_throttle.h"	/* CRED_CLASS_NR */

/*
 * Credential-syscall observability oracle (always on) + flag-gated
 * throttle counters.  See include/cred_throttle.h for the contract.
 * calls counts EVERY completed credential syscall in the class (the
 * denominator).  success / eperm / einval are the bucket splits the
 * throttle predicate reads to decide "provably impossible".
 * throttled is bumped each time the --cred-throttle gate rejected a
 * pick for this class -- always zero when the flag is off, so the
 * dump column doubles as a "flag was active" indicator.  The
 * surrounding struct stats_s composes an instance of struct
 * cred_class_stats as its "cred_class" member.
 */
struct cred_class_stats {
	unsigned long calls[CRED_CLASS_NR];
	unsigned long success[CRED_CLASS_NR];
	unsigned long eperm[CRED_CLASS_NR];
	unsigned long einval[CRED_CLASS_NR];
	unsigned long throttled[CRED_CLASS_NR];
};

#endif	/* _TRINITY_STATS_SUBSYS_CRED_CLASS_H */
