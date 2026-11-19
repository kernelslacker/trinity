#pragma once

/*
 * TCA_MIRRED_* attribute types are enum members upstream, not macros, so
 * #ifndef cannot tell whether <linux/tc_act/tc_mirred.h> has one.
 * configure compile-tests each and emits HAVE_<SYMBOL>; the fallback below
 * exists only where the header lacks the member.  The header is included
 * first so a misfiring probe cannot put a macro ahead of the enum body.
 */
#include <linux/tc_act/tc_mirred.h>

#ifndef HAVE_TCA_MIRRED_BLOCKID
#define TCA_MIRRED_BLOCKID		4
#endif
