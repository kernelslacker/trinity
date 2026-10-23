#pragma once

/*
 * bpf(2) commands and attach types are enum members upstream, not
 * macros, so the #ifndef guards below always fire and the #defines are
 * the definition on every kernel; a wrong number is wrong everywhere.
 * <linux/bpf.h> is included first so the enum bodies are parsed before
 * the macros go live, whatever the consumer's include order.
 */
#include <linux/bpf.h>

/* Commands added after trinity's original definitions */
#ifndef BPF_OBJ_PIN
#define BPF_OBJ_PIN 6
#define BPF_OBJ_GET 7
#endif
#ifndef BPF_PROG_ATTACH
#define BPF_PROG_ATTACH			8
#define BPF_PROG_DETACH			9
#endif
#ifndef BPF_PROG_TEST_RUN
#define BPF_PROG_TEST_RUN		10
#endif
#ifndef BPF_PROG_GET_NEXT_ID
#define BPF_PROG_GET_NEXT_ID		11
#define BPF_MAP_GET_NEXT_ID		12
#define BPF_PROG_GET_FD_BY_ID		13
#define BPF_MAP_GET_FD_BY_ID		14
#define BPF_OBJ_GET_INFO_BY_FD		15
#define BPF_PROG_QUERY			16
#endif
#ifndef BPF_RAW_TRACEPOINT_OPEN
#define BPF_RAW_TRACEPOINT_OPEN		17
#endif
#ifndef BPF_BTF_LOAD
#define BPF_BTF_LOAD			18
#define BPF_BTF_GET_FD_BY_ID		19
#define BPF_TASK_FD_QUERY		20
#endif
#ifndef BPF_MAP_LOOKUP_AND_DELETE_ELEM
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM	21
#endif
#ifndef BPF_MAP_FREEZE
#define BPF_MAP_FREEZE			22
#endif
#ifndef BPF_BTF_GET_NEXT_ID
#define BPF_BTF_GET_NEXT_ID		23
#endif
#ifndef BPF_MAP_LOOKUP_BATCH
#define BPF_MAP_LOOKUP_BATCH		24
#define BPF_MAP_LOOKUP_AND_DELETE_BATCH	25
#define BPF_MAP_UPDATE_BATCH		26
#define BPF_MAP_DELETE_BATCH		27
#endif
#ifndef BPF_LINK_CREATE
#define BPF_LINK_CREATE			28
#define BPF_LINK_UPDATE			29
#define BPF_LINK_GET_FD_BY_ID		30
#define BPF_LINK_GET_NEXT_ID		31
#endif
#ifndef BPF_ENABLE_STATS
#define BPF_ENABLE_STATS		32
#endif
#ifndef BPF_ITER_CREATE
#define BPF_ITER_CREATE			33
#endif
#ifndef BPF_LINK_DETACH
#define BPF_LINK_DETACH			34
#endif
#ifndef BPF_PROG_BIND_MAP
#define BPF_PROG_BIND_MAP		35
#endif
#ifndef BPF_TOKEN_CREATE
#define BPF_TOKEN_CREATE		36
#endif
#ifndef BPF_PROG_STREAM_READ_BY_FD
#define BPF_PROG_STREAM_READ_BY_FD	37
#endif
#ifndef BPF_PROG_ASSOC_STRUCT_OPS
#define BPF_PROG_ASSOC_STRUCT_OPS	38
#endif

/* Attach types not present in older bpf.h headers */
#ifndef BPF_TRACE_KPROBE_SESSION
#define BPF_TRACE_KPROBE_SESSION	56
#endif
#ifndef BPF_TRACE_UPROBE_SESSION
#define BPF_TRACE_UPROBE_SESSION	57
#endif
#ifndef BPF_TRACE_FSESSION
#define BPF_TRACE_FSESSION		58
#endif
