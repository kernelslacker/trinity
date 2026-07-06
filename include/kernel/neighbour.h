#pragma once

/*
 * Wrapper around <linux/neighbour.h> that ships #ifndef-guarded
 * fallbacks for the neighbour UAPI values touched by
 * childops/net/ipv6-ndisc-proxy.c.  The real header is pulled in behind
 * __has_include so stripped sysroots that don't ship <linux/neighbour.h>
 * still compile; per-symbol #ifndef fallbacks then supply any missing
 * values.  NDA_DST is enum-backed in <linux/neighbour.h>, so the
 * canonical-first ordering is mandatory -- an inline #ifndef alone
 * would miss the enum.  NTF_PROXY is a plain #define.  Values mirror
 * the upstream uapi enum/#define literals exactly.
 */
#if __has_include(<linux/neighbour.h>)
#include <linux/neighbour.h>
#endif

#ifndef NDA_DST
#define NDA_DST			1
#endif
#ifndef NTF_PROXY
#define NTF_PROXY		(1 << 3)
#endif
