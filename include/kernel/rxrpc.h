#pragma once

/*
 * Wrapper around <linux/rxrpc.h> that ships #ifndef-guarded fallbacks
 * for a couple of AF_RXRPC UAPI symbols that proto-rxrpc.c was carrying
 * inline.  Values are the stable kernel UAPI values; stripped sysroots
 * may be missing them on older build hosts.
 */
#include <linux/rxrpc.h>

#ifndef SOL_RXRPC
#define SOL_RXRPC		272
#endif
#ifndef RXRPC_MANAGE_RESPONSE
#define RXRPC_MANAGE_RESPONSE	7
#endif
