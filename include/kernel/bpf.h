#pragma once

/*
 * bpf(2) commands, map types and attach types are enum members upstream,
 * not macros, so #ifndef cannot tell whether <linux/bpf.h> has one.  A
 * fallback under #ifndef HAVE_<SYMBOL> is compile-tested by configure
 * (check_enum_member) and exists only where the header lacks the member,
 * so it never shadows the real one.  The rest still sit under
 * #ifndef <SYMBOL>, which always fires: those macros are the definition on
 * every kernel, and a wrong number is wrong everywhere.  <linux/bpf.h> is
 * included first so the enum bodies are parsed before any macro goes
 * live, whatever the consumer's include order.  The map flags further down
 * are macros upstream, so their guards behave, except BPF_F_LOCK, which is
 * an enum member as well.
 */
#include <linux/bpf.h>

/* Commands added after trinity's original definitions */
#ifndef HAVE_BPF_OBJ_PIN
#define BPF_OBJ_PIN			6
#endif
#ifndef HAVE_BPF_OBJ_GET
#define BPF_OBJ_GET			7
#endif
#ifndef HAVE_BPF_PROG_ATTACH
#define BPF_PROG_ATTACH			8
#endif
#ifndef HAVE_BPF_PROG_DETACH
#define BPF_PROG_DETACH			9
#endif
#ifndef HAVE_BPF_PROG_TEST_RUN
#define BPF_PROG_TEST_RUN		10
#endif
#ifndef HAVE_BPF_PROG_GET_NEXT_ID
#define BPF_PROG_GET_NEXT_ID		11
#endif
#ifndef HAVE_BPF_MAP_GET_NEXT_ID
#define BPF_MAP_GET_NEXT_ID		12
#endif
#ifndef HAVE_BPF_PROG_GET_FD_BY_ID
#define BPF_PROG_GET_FD_BY_ID		13
#endif
#ifndef HAVE_BPF_MAP_GET_FD_BY_ID
#define BPF_MAP_GET_FD_BY_ID		14
#endif
#ifndef HAVE_BPF_OBJ_GET_INFO_BY_FD
#define BPF_OBJ_GET_INFO_BY_FD		15
#endif
#ifndef HAVE_BPF_PROG_QUERY
#define BPF_PROG_QUERY			16
#endif
#ifndef HAVE_BPF_RAW_TRACEPOINT_OPEN
#define BPF_RAW_TRACEPOINT_OPEN		17
#endif
#ifndef HAVE_BPF_BTF_LOAD
#define BPF_BTF_LOAD			18
#endif
#ifndef HAVE_BPF_BTF_GET_FD_BY_ID
#define BPF_BTF_GET_FD_BY_ID		19
#endif
#ifndef HAVE_BPF_TASK_FD_QUERY
#define BPF_TASK_FD_QUERY		20
#endif
#ifndef HAVE_BPF_MAP_LOOKUP_AND_DELETE_ELEM
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM	21
#endif
#ifndef HAVE_BPF_MAP_FREEZE
#define BPF_MAP_FREEZE			22
#endif
#ifndef HAVE_BPF_BTF_GET_NEXT_ID
#define BPF_BTF_GET_NEXT_ID		23
#endif
#ifndef HAVE_BPF_MAP_LOOKUP_BATCH
#define BPF_MAP_LOOKUP_BATCH		24
#endif
#ifndef HAVE_BPF_MAP_LOOKUP_AND_DELETE_BATCH
#define BPF_MAP_LOOKUP_AND_DELETE_BATCH	25
#endif
#ifndef HAVE_BPF_MAP_UPDATE_BATCH
#define BPF_MAP_UPDATE_BATCH		26
#endif
#ifndef HAVE_BPF_MAP_DELETE_BATCH
#define BPF_MAP_DELETE_BATCH		27
#endif
#ifndef HAVE_BPF_LINK_CREATE
#define BPF_LINK_CREATE			28
#endif
#ifndef HAVE_BPF_LINK_UPDATE
#define BPF_LINK_UPDATE			29
#endif
#ifndef HAVE_BPF_LINK_GET_FD_BY_ID
#define BPF_LINK_GET_FD_BY_ID		30
#endif
#ifndef HAVE_BPF_LINK_GET_NEXT_ID
#define BPF_LINK_GET_NEXT_ID		31
#endif
#ifndef HAVE_BPF_ENABLE_STATS
#define BPF_ENABLE_STATS		32
#endif
#ifndef HAVE_BPF_ITER_CREATE
#define BPF_ITER_CREATE			33
#endif
#ifndef HAVE_BPF_LINK_DETACH
#define BPF_LINK_DETACH			34
#endif
#ifndef HAVE_BPF_PROG_BIND_MAP
#define BPF_PROG_BIND_MAP		35
#endif
#ifndef HAVE_BPF_TOKEN_CREATE
#define BPF_TOKEN_CREATE		36
#endif
#ifndef HAVE_BPF_PROG_STREAM_READ_BY_FD
#define BPF_PROG_STREAM_READ_BY_FD	37
#endif
#ifndef HAVE_BPF_PROG_ASSOC_STRUCT_OPS
#define BPF_PROG_ASSOC_STRUCT_OPS	38
#endif

/*
 * Attach-type fallbacks for older /usr/include/linux/bpf.h.  Consumed
 * by bpf_attach_types[] in struct_catalog/bpf.c and by the tracing /
 * kprobe / uprobe attach-type pools in struct_catalog/bpf-link.c;
 * shared here so both sites see the same numeric values.
 */
#ifndef BPF_TRACE_KPROBE_SESSION
#define BPF_TRACE_KPROBE_SESSION	56
#endif
#ifndef BPF_TRACE_UPROBE_SESSION
#define BPF_TRACE_UPROBE_SESSION	57
#endif
#ifndef BPF_TRACE_FSESSION
#define BPF_TRACE_FSESSION		58
#endif
#ifndef BPF_TRACE_FENTRY_MULTI
#define BPF_TRACE_FENTRY_MULTI		59
#endif
#ifndef BPF_TRACE_FEXIT_MULTI
#define BPF_TRACE_FEXIT_MULTI		60
#endif
#ifndef BPF_TRACE_FSESSION_MULTI
#define BPF_TRACE_FSESSION_MULTI	61
#endif

/*
 * Map-type fallback defines for older /usr/include/linux/bpf.h.  Both
 * syscalls/bpf-map.c (the map_type draw in sanitise) and
 * struct_catalog/bpf-map.c (FT_ENUM annotation in the bpf_attr MAP_CREATE
 * variant) walk the same vocabulary, bpf_map_types[] in
 * struct_catalog/bpf.c, so the fallback set lives here.
 */
#ifndef HAVE_BPF_MAP_TYPE_LRU_HASH
#define BPF_MAP_TYPE_LRU_HASH		9
#endif
#ifndef HAVE_BPF_MAP_TYPE_LRU_PERCPU_HASH
#define BPF_MAP_TYPE_LRU_PERCPU_HASH	10
#endif
#ifndef HAVE_BPF_MAP_TYPE_LPM_TRIE
#define BPF_MAP_TYPE_LPM_TRIE		11
#endif
#ifndef HAVE_BPF_MAP_TYPE_ARRAY_OF_MAPS
#define BPF_MAP_TYPE_ARRAY_OF_MAPS	12
#endif
#ifndef HAVE_BPF_MAP_TYPE_HASH_OF_MAPS
#define BPF_MAP_TYPE_HASH_OF_MAPS	13
#endif
#ifndef HAVE_BPF_MAP_TYPE_DEVMAP
#define BPF_MAP_TYPE_DEVMAP		14
#endif
#ifndef HAVE_BPF_MAP_TYPE_SOCKMAP
#define BPF_MAP_TYPE_SOCKMAP		15
#endif
#ifndef HAVE_BPF_MAP_TYPE_CPUMAP
#define BPF_MAP_TYPE_CPUMAP		16
#endif
#ifndef HAVE_BPF_MAP_TYPE_XSKMAP
#define BPF_MAP_TYPE_XSKMAP		17
#endif
#ifndef HAVE_BPF_MAP_TYPE_SOCKHASH
#define BPF_MAP_TYPE_SOCKHASH		18
#endif
#ifndef HAVE_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
#define BPF_MAP_TYPE_REUSEPORT_SOCKARRAY	20
#endif
#ifndef HAVE_BPF_MAP_TYPE_QUEUE
#define BPF_MAP_TYPE_QUEUE		22
#endif
#ifndef HAVE_BPF_MAP_TYPE_STACK
#define BPF_MAP_TYPE_STACK		23
#endif
#ifndef HAVE_BPF_MAP_TYPE_SK_STORAGE
#define BPF_MAP_TYPE_SK_STORAGE		24
#endif
#ifndef HAVE_BPF_MAP_TYPE_DEVMAP_HASH
#define BPF_MAP_TYPE_DEVMAP_HASH	25
#endif
#ifndef HAVE_BPF_MAP_TYPE_STRUCT_OPS
#define BPF_MAP_TYPE_STRUCT_OPS		26
#endif
#ifndef HAVE_BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF		27
#endif
#ifndef HAVE_BPF_MAP_TYPE_INODE_STORAGE
#define BPF_MAP_TYPE_INODE_STORAGE	28
#endif
#ifndef HAVE_BPF_MAP_TYPE_TASK_STORAGE
#define BPF_MAP_TYPE_TASK_STORAGE	29
#endif
#ifndef HAVE_BPF_MAP_TYPE_BLOOM_FILTER
#define BPF_MAP_TYPE_BLOOM_FILTER	30
#endif
#ifndef HAVE_BPF_MAP_TYPE_USER_RINGBUF
#define BPF_MAP_TYPE_USER_RINGBUF	31
#endif
#ifndef HAVE_BPF_MAP_TYPE_CGRP_STORAGE
#define BPF_MAP_TYPE_CGRP_STORAGE	32
#endif
#ifndef HAVE_BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA		33
#endif
#ifndef HAVE_BPF_MAP_TYPE_INSN_ARRAY
#define BPF_MAP_TYPE_INSN_ARRAY		34
#endif
#ifndef HAVE_BPF_MAP_TYPE_RHASH
#define BPF_MAP_TYPE_RHASH		35
#endif

#ifndef BPF_F_NO_COMMON_LRU
#define BPF_F_NO_COMMON_LRU     (1U << 1)
#endif

/* Flags referenced from the MAP_CREATE schema annotation. */
#ifndef BPF_F_MMAPABLE
# define BPF_F_MMAPABLE			(1U << 10)
#endif
#ifndef BPF_F_PRESERVE_ELEMS
# define BPF_F_PRESERVE_ELEMS		(1U << 11)
#endif
#ifndef BPF_F_INNER_MAP
# define BPF_F_INNER_MAP		(1U << 12)
#endif
#ifndef BPF_F_LINK
# define BPF_F_LINK			(1U << 13)
#endif
#ifndef BPF_F_PATH_FD
# define BPF_F_PATH_FD			(1U << 14)
#endif
#ifndef BPF_F_VTYPE_BTF_OBJ_FD
# define BPF_F_VTYPE_BTF_OBJ_FD		(1U << 15)
#endif
#ifndef BPF_F_TOKEN_FD
# define BPF_F_TOKEN_FD			(1U << 16)
#endif
#ifndef BPF_F_SEGV_ON_FAULT
# define BPF_F_SEGV_ON_FAULT		(1U << 17)
#endif
#ifndef BPF_F_NO_USER_CONV
# define BPF_F_NO_USER_CONV		(1U << 18)
#endif
/* Map-update flags that may be absent on older build hosts */
#ifndef BPF_F_LOCK
# define BPF_F_LOCK			4
#endif
