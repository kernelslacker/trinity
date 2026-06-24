#pragma once

/*
 * Wrapper around <linux/psp.h> that ships #ifndef-guarded fallbacks
 * for the PSP_CMD_* / PSP_A_* ids the installed uapi header may be
 * too old to know (or absent entirely on stripped sysroots).
 * Including <linux/psp.h> here lets a .c pull "kernel/psp.h" once
 * and get the real uapi enums plus the fallback shims for ids the
 * installed header is missing.
 *
 * The <linux/psp.h> include is itself `__has_include`-guarded so a
 * stripped sysroot that lacks the header still compiles -- the
 * fallback shims below carry the file on their own in that case.
 *
 * Purely handler-local trinity policy knobs (outer-loop budget, inner
 * burst sizes, recv-timeout) stay with their handler in the .c.
 */
#if __has_include(<linux/psp.h>)
#include <linux/psp.h>
#endif

/* PSP UAPI integers (mainlined in 6.10).  Values mirror
 * include/uapi/linux/psp.h: enum { PSP_CMD_DEV_GET = 1, ... } and
 * enum { PSP_A_DEV_ID = 1, ... }.  Supplied as fallbacks for stripped
 * sysroots that omit <linux/psp.h>; the kernel returns -EOPNOTSUPP /
 * -ENOPROTOOPT on an unknown command and the cap-gate latches. */
#ifndef PSP_FAMILY_NAME
#define PSP_FAMILY_NAME			"psp"
#endif
#ifndef PSP_CMD_DEV_GET
#define PSP_CMD_DEV_GET			1
#endif
#ifndef PSP_CMD_KEY_ROTATE
#define PSP_CMD_KEY_ROTATE		6
#endif
#ifndef PSP_CMD_TX_ASSOC
#define PSP_CMD_TX_ASSOC		9
#endif
#ifndef PSP_A_DEV_ID
#define PSP_A_DEV_ID			1
#endif
#ifndef PSP_A_ASSOC_DEV_ID
#define PSP_A_ASSOC_DEV_ID		1
#endif
#ifndef PSP_A_ASSOC_VERSION
#define PSP_A_ASSOC_VERSION		2
#endif
#ifndef PSP_A_ASSOC_SOCK_FD
#define PSP_A_ASSOC_SOCK_FD		5
#endif
