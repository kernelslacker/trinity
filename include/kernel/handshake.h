#pragma once

/*
 * Wrapper around <linux/handshake.h> that ships #ifndef-guarded
 * fallbacks for the HANDSHAKE_CMD_* / HANDSHAKE_A_* ids and the
 * HANDSHAKE_FAMILY_NAME / HANDSHAKE_FAMILY_VERSION macros.  Build
 * hosts whose installed uapi header is older than the upstream
 * Documentation/netlink/specs/handshake.yaml silently miss the newer
 * ids; the fallback values match the upstream uapi enum ordering so
 * the wire-format ids the kernel parses match the ones the message
 * generator emits.
 *
 * The .c side includes this from inside its `#if __has_include(
 * <linux/handshake.h>)` gate, so the header itself can include
 * <linux/handshake.h> unconditionally.
 */
#include <linux/handshake.h>

#ifndef HANDSHAKE_FAMILY_NAME
#define HANDSHAKE_FAMILY_NAME		"handshake"
#endif
#ifndef HANDSHAKE_FAMILY_VERSION
#define HANDSHAKE_FAMILY_VERSION	1
#endif

#ifndef HANDSHAKE_CMD_READY
#define HANDSHAKE_CMD_READY		1
#endif
#ifndef HANDSHAKE_CMD_ACCEPT
#define HANDSHAKE_CMD_ACCEPT		2
#endif
#ifndef HANDSHAKE_CMD_DONE
#define HANDSHAKE_CMD_DONE		3
#endif

#ifndef HANDSHAKE_A_ACCEPT_SOCKFD
#define HANDSHAKE_A_ACCEPT_SOCKFD		1
#endif
#ifndef HANDSHAKE_A_ACCEPT_HANDLER_CLASS
#define HANDSHAKE_A_ACCEPT_HANDLER_CLASS	2
#endif
#ifndef HANDSHAKE_A_ACCEPT_MESSAGE_TYPE
#define HANDSHAKE_A_ACCEPT_MESSAGE_TYPE		3
#endif
#ifndef HANDSHAKE_A_ACCEPT_TIMEOUT
#define HANDSHAKE_A_ACCEPT_TIMEOUT		4
#endif
#ifndef HANDSHAKE_A_ACCEPT_AUTH_MODE
#define HANDSHAKE_A_ACCEPT_AUTH_MODE		5
#endif
#ifndef HANDSHAKE_A_ACCEPT_PEER_IDENTITY
#define HANDSHAKE_A_ACCEPT_PEER_IDENTITY	6
#endif
#ifndef HANDSHAKE_A_ACCEPT_CERTIFICATE
#define HANDSHAKE_A_ACCEPT_CERTIFICATE		7
#endif
#ifndef HANDSHAKE_A_ACCEPT_PEERNAME
#define HANDSHAKE_A_ACCEPT_PEERNAME		8
#endif
#ifndef HANDSHAKE_A_ACCEPT_KEYRING
#define HANDSHAKE_A_ACCEPT_KEYRING		9
#endif
