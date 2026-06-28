#pragma once

/*
 * Wrapper around <linux/tcp_metrics.h> that ships the #ifndef-guarded
 * fallbacks for TCP_METRICS_CMD_* / TCP_METRICS_ATTR_* ids and the
 * TCP_METRICS_GENL_NAME / TCP_METRICS_GENL_VERSION macros.  The .c
 * side includes this from inside its
 * `#if __has_include(<linux/tcp_metrics.h>)` gate, so the header
 * itself can include <linux/tcp_metrics.h> unconditionally.
 */
#include <linux/tcp_metrics.h>

#ifndef TCP_METRICS_GENL_NAME
#define TCP_METRICS_GENL_NAME		"tcp_metrics"
#endif
#ifndef TCP_METRICS_GENL_VERSION
#define TCP_METRICS_GENL_VERSION	0x1
#endif

/*
 * Per-symbol shims for TCP_METRICS_CMD_* / TCP_METRICS_ATTR_* ids.
 * Build hosts whose <linux/tcp_metrics.h> predates a given attribute
 * (the SADDR_IPV4 / SADDR_IPV6 source-key pair, PAD) silently miss
 * it from the validator coverage; the fallback values match the
 * upstream uapi enum ordering so the wire-format ids the kernel
 * parses match the ones the generator emits.
 */
#ifndef TCP_METRICS_CMD_GET
#define TCP_METRICS_CMD_GET			1
#endif
#ifndef TCP_METRICS_CMD_DEL
#define TCP_METRICS_CMD_DEL			2
#endif

#ifndef TCP_METRICS_ATTR_ADDR_IPV4
#define TCP_METRICS_ATTR_ADDR_IPV4		1
#endif
#ifndef TCP_METRICS_ATTR_ADDR_IPV6
#define TCP_METRICS_ATTR_ADDR_IPV6		2
#endif
#ifndef TCP_METRICS_ATTR_AGE
#define TCP_METRICS_ATTR_AGE			3
#endif
#ifndef TCP_METRICS_ATTR_TW_TSVAL
#define TCP_METRICS_ATTR_TW_TSVAL		4
#endif
#ifndef TCP_METRICS_ATTR_TW_TS_STAMP
#define TCP_METRICS_ATTR_TW_TS_STAMP		5
#endif
#ifndef TCP_METRICS_ATTR_VALS
#define TCP_METRICS_ATTR_VALS			6
#endif
#ifndef TCP_METRICS_ATTR_FOPEN_MSS
#define TCP_METRICS_ATTR_FOPEN_MSS		7
#endif
#ifndef TCP_METRICS_ATTR_FOPEN_SYN_DROPS
#define TCP_METRICS_ATTR_FOPEN_SYN_DROPS	8
#endif
#ifndef TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS
#define TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS	9
#endif
#ifndef TCP_METRICS_ATTR_FOPEN_COOKIE
#define TCP_METRICS_ATTR_FOPEN_COOKIE		10
#endif
#ifndef TCP_METRICS_ATTR_SADDR_IPV4
#define TCP_METRICS_ATTR_SADDR_IPV4		11
#endif
#ifndef TCP_METRICS_ATTR_SADDR_IPV6
#define TCP_METRICS_ATTR_SADDR_IPV6		12
#endif
#ifndef TCP_METRICS_ATTR_PAD
#define TCP_METRICS_ATTR_PAD			13
#endif
