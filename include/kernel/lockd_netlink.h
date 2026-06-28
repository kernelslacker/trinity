#pragma once

/*
 * Wrapper around <linux/lockd_netlink.h> that ships the #ifndef-guarded
 * fallbacks for LOCKD_FAMILY_NAME / LOCKD_FAMILY_VERSION and every
 * LOCKD_CMD_* / LOCKD_A_* id the grammar references.  Build hosts whose
 * installed uapi predates a given symbol silently miss it from the
 * validator coverage; the fallback values match the upstream uapi
 * enum ordering so the wire-format ids the kernel parses match the
 * ones the message generator emits.
 *
 * The .c side includes this from inside its `#if __has_include(
 * <linux/lockd_netlink.h>)` gate, so the header itself can include
 * <linux/lockd_netlink.h> unconditionally.
 */
#include <linux/lockd_netlink.h>

#ifndef LOCKD_FAMILY_NAME
#define LOCKD_FAMILY_NAME		"lockd"
#endif
#ifndef LOCKD_FAMILY_VERSION
#define LOCKD_FAMILY_VERSION		1
#endif

#ifndef LOCKD_CMD_SERVER_SET
#define LOCKD_CMD_SERVER_SET		1
#endif
#ifndef LOCKD_CMD_SERVER_GET
#define LOCKD_CMD_SERVER_GET		2
#endif

#ifndef LOCKD_A_SERVER_GRACETIME
#define LOCKD_A_SERVER_GRACETIME	1
#endif
#ifndef LOCKD_A_SERVER_TCP_PORT
#define LOCKD_A_SERVER_TCP_PORT		2
#endif
#ifndef LOCKD_A_SERVER_UDP_PORT
#define LOCKD_A_SERVER_UDP_PORT		3
#endif
