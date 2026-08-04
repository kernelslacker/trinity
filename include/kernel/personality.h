#pragma once

/*
 * Shim guards for personality(2) upper flag bits that may be absent on
 * older uapi headers.  Values match include/uapi/linux/personality.h.
 *
 * All four are upper-word flags (above PER_MASK) that OR onto a base
 * persona.  ADDR_NO_RANDOMIZE, ADDR_COMPAT_LAYOUT, and READ_IMPLIES_EXEC
 * appear in PER_CLEAR_ON_SETID but not in any named PER_* persona constant.
 * UNAME26 is consumed only by kernel/sys.c:override_release() and is likewise
 * absent from every named PER_* constant.
 */

#ifndef UNAME26
#define UNAME26			0x0020000	/* request 2.6 uname on 3.x kernels */
#endif

#ifndef ADDR_NO_RANDOMIZE
#define ADDR_NO_RANDOMIZE	0x0040000	/* disable VA-space randomisation */
#endif

#ifndef ADDR_COMPAT_LAYOUT
#define ADDR_COMPAT_LAYOUT	0x0200000	/* old mmap layout compat */
#endif

#ifndef READ_IMPLIES_EXEC
#define READ_IMPLIES_EXEC	0x0400000	/* PROT_READ implies PROT_EXEC */
#endif
