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

/* Additional PSP UAPI integers consumed by the genl family grammar in
 * net/netlink-genl-fam-psp.c.  Values mirror include/uapi/linux/psp.h
 * (the rest of enum psp_cmd plus the PSP_A_DEV_* / PSP_A_ASSOC_*
 * nest-leaf / PSP_A_KEYS_* / PSP_A_STATS_* namespaces).  Supplied as
 * fallbacks for stripped sysroots that omit <linux/psp.h>; existing
 * defines above are left untouched so the psp_key_rotate childop
 * keeps building on hosts whose installed uapi already carried the
 * narrower set. */
#ifndef PSP_FAMILY_VERSION
#define PSP_FAMILY_VERSION		1
#endif
#ifndef PSP_CMD_DEV_SET
#define PSP_CMD_DEV_SET			4
#endif
#ifndef PSP_CMD_RX_ASSOC
#define PSP_CMD_RX_ASSOC		8
#endif
#ifndef PSP_CMD_GET_STATS
#define PSP_CMD_GET_STATS		10
#endif
#ifndef PSP_A_DEV_IFINDEX
#define PSP_A_DEV_IFINDEX		2
#endif
#ifndef PSP_A_DEV_PSP_VERSIONS_CAP
#define PSP_A_DEV_PSP_VERSIONS_CAP	3
#endif
#ifndef PSP_A_DEV_PSP_VERSIONS_ENA
#define PSP_A_DEV_PSP_VERSIONS_ENA	4
#endif
#ifndef PSP_A_ASSOC_RX_KEY
#define PSP_A_ASSOC_RX_KEY		3
#endif
#ifndef PSP_A_ASSOC_TX_KEY
#define PSP_A_ASSOC_TX_KEY		4
#endif
#ifndef PSP_A_KEYS_KEY
#define PSP_A_KEYS_KEY			1
#endif
#ifndef PSP_A_KEYS_SPI
#define PSP_A_KEYS_SPI			2
#endif
#ifndef PSP_A_STATS_DEV_ID
#define PSP_A_STATS_DEV_ID		1
#endif
#ifndef PSP_A_STATS_KEY_ROTATIONS
#define PSP_A_STATS_KEY_ROTATIONS	2
#endif
#ifndef PSP_A_STATS_STALE_EVENTS
#define PSP_A_STATS_STALE_EVENTS	3
#endif
#ifndef PSP_A_STATS_RX_PACKETS
#define PSP_A_STATS_RX_PACKETS		4
#endif
#ifndef PSP_A_STATS_RX_BYTES
#define PSP_A_STATS_RX_BYTES		5
#endif
#ifndef PSP_A_STATS_RX_AUTH_FAIL
#define PSP_A_STATS_RX_AUTH_FAIL	6
#endif
#ifndef PSP_A_STATS_RX_ERROR
#define PSP_A_STATS_RX_ERROR		7
#endif
#ifndef PSP_A_STATS_RX_BAD
#define PSP_A_STATS_RX_BAD		8
#endif
#ifndef PSP_A_STATS_TX_PACKETS
#define PSP_A_STATS_TX_PACKETS		9
#endif
#ifndef PSP_A_STATS_TX_BYTES
#define PSP_A_STATS_TX_BYTES		10
#endif
#ifndef PSP_A_STATS_TX_ERROR
#define PSP_A_STATS_TX_ERROR		11
#endif
