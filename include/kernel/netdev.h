#pragma once

/*
 * Wrapper around <linux/netdev.h> that ships #ifndef-guarded fallbacks
 * for the NETDEV_CMD_* / NETDEV_A_* enum values added after the
 * installed uapi header.  Including <linux/netdev.h> here lets a .c
 * pull "kernel/netdev.h" once and get the real uapi enums plus the
 * fallback shims for ids the installed header is too old to know.
 *
 * Purely handler-local trinity values (e.g. the genl_family_grammar
 * tables) stay with their handler in the .c.
 */
#include <linux/netdev.h>

/*
 * Per-symbol shims for NETDEV_CMD_* / NETDEV_A_* ids.  Build hosts
 * whose <linux/netdev.h> predates a given command or attribute (the
 * BIND_RX / BIND_TX commands, the QSTATS_GET / QSTATS attributes, the
 * DMABUF attribute namespace) silently miss it from the validator
 * coverage; the fallback values match the upstream uapi enum ordering
 * so the wire-format ids the kernel parses match the ones the generator
 * emits.
 */
#ifndef NETDEV_CMD_DEV_GET
#define NETDEV_CMD_DEV_GET		1
#endif
#ifndef NETDEV_CMD_QUEUE_GET
#define NETDEV_CMD_QUEUE_GET		10
#endif
#ifndef NETDEV_CMD_NAPI_GET
#define NETDEV_CMD_NAPI_GET		11
#endif
#ifndef NETDEV_CMD_QSTATS_GET
#define NETDEV_CMD_QSTATS_GET		12
#endif
#ifndef NETDEV_CMD_BIND_RX
#define NETDEV_CMD_BIND_RX		13
#endif
#ifndef NETDEV_CMD_BIND_TX
#define NETDEV_CMD_BIND_TX		15
#endif

#ifndef NETDEV_A_DEV_IFINDEX
#define NETDEV_A_DEV_IFINDEX		1
#endif
#ifndef NETDEV_A_NAPI_ID
#define NETDEV_A_NAPI_ID		2
#endif
#ifndef NETDEV_A_QUEUE_TYPE
#define NETDEV_A_QUEUE_TYPE		3
#endif
#ifndef NETDEV_A_QSTATS_SCOPE
#define NETDEV_A_QSTATS_SCOPE		4
#endif
#ifndef NETDEV_A_DMABUF_QUEUES
#define NETDEV_A_DMABUF_QUEUES		2
#endif
#ifndef NETDEV_A_DMABUF_FD
#define NETDEV_A_DMABUF_FD		3
#endif
#ifndef NETDEV_A_NAPI_DEFER_HARD_IRQS
#define NETDEV_A_NAPI_DEFER_HARD_IRQS	5
#endif
#ifndef NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT
#define NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT	6
#endif

/*
 * Enum members the shims above leave out, the cmds of page pools, NAPI
 * configuration and queue leasing and the attributes that came after
 * v6.12.  configure probes each of them and emits HAVE_<SYMBOL>.
 */
#ifndef HAVE_NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT
#define NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT	7
#endif
#ifndef HAVE_NETDEV_A_NAPI_THREADED
#define NETDEV_A_NAPI_THREADED			8
#endif
#ifndef HAVE_NETDEV_A_DMABUF_RX_PAGE_SIZE
#define NETDEV_A_DMABUF_RX_PAGE_SIZE		5
#endif
#ifndef HAVE_NETDEV_A_QUEUE_LEASE
#define NETDEV_A_QUEUE_LEASE			8
#endif
#ifndef HAVE_NETDEV_A_LEASE_IFINDEX
#define NETDEV_A_LEASE_IFINDEX			1
#endif
#ifndef HAVE_NETDEV_A_LEASE_QUEUE
#define NETDEV_A_LEASE_QUEUE			2
#endif
#ifndef HAVE_NETDEV_A_LEASE_NETNS_ID
#define NETDEV_A_LEASE_NETNS_ID			3
#endif
#ifndef HAVE_NETDEV_CMD_PAGE_POOL_GET
#define NETDEV_CMD_PAGE_POOL_GET		5
#endif
#ifndef HAVE_NETDEV_CMD_PAGE_POOL_STATS_GET
#define NETDEV_CMD_PAGE_POOL_STATS_GET		9
#endif
#ifndef HAVE_NETDEV_CMD_NAPI_SET
#define NETDEV_CMD_NAPI_SET			14
#endif
#ifndef HAVE_NETDEV_CMD_QUEUE_CREATE
#define NETDEV_CMD_QUEUE_CREATE			16
#endif
