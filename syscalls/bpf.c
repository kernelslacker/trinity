/*
 * SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
 */
#ifdef USE_BPF
#include <sys/utsname.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/version.h>
#include "arch.h"
#include "bpf.h"
#include "net.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"

static __u32 get_kern_version(void)
{
	struct utsname buf;
	unsigned int major, minor, patch;

	if (uname(&buf) != 0)
		return 0;
	if (sscanf(buf.release, "%u.%u.%u", &major, &minor, &patch) != 3)
		return 0;
	return KERNEL_VERSION(major, minor, patch);
}

static unsigned long bpf_prog_types[] = {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL,
	BPF_PROG_TYPE_NETFILTER,
};

static const char license[] = "GPLv2";

static void bpf_prog_load(union bpf_attr *attr)
{
	attr->prog_type = RAND_ARRAY(bpf_prog_types);

	if (attr->prog_type == BPF_PROG_TYPE_SOCKET_FILTER && ONE_IN(2)) {
		/* Classic BPF via sock_fprog for socket filters */
		unsigned long *insns = NULL, len = 0;
		bpf_gen_filter(&insns, &len);
		attr->insn_cnt = len;
		attr->insns = (u64) insns;
	} else {
		/* eBPF for everything else (and sometimes socket filters) */
		int insn_count = 0;
		struct bpf_insn *insns = ebpf_gen_program(&insn_count, attr->prog_type);
		attr->insn_cnt = insn_count;
		attr->insns = (u64) insns;
	}

	attr->license = (u64) license;
	attr->log_level = 0;
	attr->log_size = rand() % page_size;
	attr->log_buf = (u64) get_writable_address(page_size);
	attr->kern_version = get_kern_version();
}

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

/* Map types added after trinity's original definitions */
#ifndef BPF_MAP_TYPE_ARRAY_OF_MAPS
#define BPF_MAP_TYPE_ARRAY_OF_MAPS	12
#define BPF_MAP_TYPE_HASH_OF_MAPS	13
#endif
#ifndef BPF_MAP_TYPE_DEVMAP
#define BPF_MAP_TYPE_DEVMAP		14
#define BPF_MAP_TYPE_SOCKMAP		15
#define BPF_MAP_TYPE_CPUMAP		16
#endif
#ifndef BPF_MAP_TYPE_XSKMAP
#define BPF_MAP_TYPE_XSKMAP		17
#define BPF_MAP_TYPE_SOCKHASH		18
#endif
#ifndef BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
#define BPF_MAP_TYPE_REUSEPORT_SOCKARRAY 20
#endif
#ifndef BPF_MAP_TYPE_QUEUE
#define BPF_MAP_TYPE_QUEUE		22
#define BPF_MAP_TYPE_STACK		23
#endif
#ifndef BPF_MAP_TYPE_SK_STORAGE
#define BPF_MAP_TYPE_SK_STORAGE		24
#endif
#ifndef BPF_MAP_TYPE_DEVMAP_HASH
#define BPF_MAP_TYPE_DEVMAP_HASH	25
#endif
#ifndef BPF_MAP_TYPE_STRUCT_OPS
#define BPF_MAP_TYPE_STRUCT_OPS		26
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF		27
#endif
#ifndef BPF_MAP_TYPE_INODE_STORAGE
#define BPF_MAP_TYPE_INODE_STORAGE	28
#endif
#ifndef BPF_MAP_TYPE_TASK_STORAGE
#define BPF_MAP_TYPE_TASK_STORAGE	29
#endif
#ifndef BPF_MAP_TYPE_BLOOM_FILTER
#define BPF_MAP_TYPE_BLOOM_FILTER	30
#endif
#ifndef BPF_MAP_TYPE_USER_RINGBUF
#define BPF_MAP_TYPE_USER_RINGBUF	31
#endif
#ifndef BPF_MAP_TYPE_CGRP_STORAGE
#define BPF_MAP_TYPE_CGRP_STORAGE	32
#endif
#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA		33
#endif

static void sanitise_bpf(struct syscallrecord *rec)
{
	union bpf_attr *attr;
	unsigned long bpf_map_types[] = {
		BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY,
		BPF_MAP_TYPE_PROG_ARRAY, BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		BPF_MAP_TYPE_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_ARRAY,
		BPF_MAP_TYPE_STACK_TRACE, BPF_MAP_TYPE_CGROUP_ARRAY,
		BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH,
		BPF_MAP_TYPE_LPM_TRIE,
		BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS,
		BPF_MAP_TYPE_DEVMAP, BPF_MAP_TYPE_SOCKMAP,
		BPF_MAP_TYPE_CPUMAP, BPF_MAP_TYPE_XSKMAP,
		BPF_MAP_TYPE_SOCKHASH,
		BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
		BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK,
		BPF_MAP_TYPE_SK_STORAGE, BPF_MAP_TYPE_DEVMAP_HASH,
		BPF_MAP_TYPE_STRUCT_OPS, BPF_MAP_TYPE_RINGBUF,
		BPF_MAP_TYPE_INODE_STORAGE, BPF_MAP_TYPE_TASK_STORAGE,
		BPF_MAP_TYPE_BLOOM_FILTER, BPF_MAP_TYPE_USER_RINGBUF,
		BPF_MAP_TYPE_CGRP_STORAGE, BPF_MAP_TYPE_ARENA,
	};

	attr = zmalloc(sizeof(union bpf_attr));
	rec->a2 = (unsigned long) attr;

	switch (rec->a1) {
	case BPF_MAP_CREATE:
		attr->map_type = RAND_ARRAY(bpf_map_types);
		attr->key_size = rand() % 1024;
		attr->value_size = rand() % (1024 * 64);
		attr->max_entries = rand() % 1024;
		attr->flags = RAND_RANGE(0, 4);
		rec->a3 = 20;
		break;

	case BPF_MAP_LOOKUP_ELEM:
	case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		attr->value = rand();
		rec->a3 = 32;
		break;

	case BPF_MAP_UPDATE_ELEM:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		attr->value = rand();
		attr->next_key = rand();
		attr->flags = RAND_RANGE(0, 4);
		rec->a3 = 32;
		break;

	case BPF_MAP_DELETE_ELEM:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		rec->a3 = 32;
		break;

	case BPF_MAP_GET_NEXT_KEY:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		attr->value = rand();
		rec->a3 = 32;
		break;

	case BPF_MAP_FREEZE:
		attr->map_fd = get_rand_bpf_fd();
		rec->a3 = 4;
		break;

	case BPF_OBJ_PIN:
	case BPF_OBJ_GET:
		attr->map_fd = get_rand_bpf_fd();
		rec->a3 = 32;
		break;

	case BPF_PROG_LOAD:
		bpf_prog_load(attr);
		rec->a3 = 48;
		break;

	case BPF_PROG_ATTACH:
	case BPF_PROG_DETACH:
		attr->target_fd = get_rand_bpf_fd();
		attr->attach_bpf_fd = get_rand_bpf_fd();
		attr->attach_type = rand() % 64;
		rec->a3 = 16;
		break;

	case BPF_PROG_TEST_RUN:
		attr->test.prog_fd = get_rand_bpf_fd();
		attr->test.data_size_in = rand() % page_size;
		attr->test.data_in = (u64) get_address();
		attr->test.data_size_out = rand() % page_size;
		attr->test.data_out = (u64) get_writable_address(page_size);
		attr->test.repeat = rand() % 256;
		rec->a3 = sizeof(attr->test);
		break;

	case BPF_PROG_GET_NEXT_ID:
	case BPF_MAP_GET_NEXT_ID:
	case BPF_BTF_GET_NEXT_ID:
	case BPF_LINK_GET_NEXT_ID:
		attr->start_id = rand();
		rec->a3 = 8;
		break;

	case BPF_PROG_GET_FD_BY_ID:
	case BPF_MAP_GET_FD_BY_ID:
	case BPF_BTF_GET_FD_BY_ID:
	case BPF_LINK_GET_FD_BY_ID:
		attr->start_id = rand();
		rec->a3 = 8;
		break;

	case BPF_OBJ_GET_INFO_BY_FD:
		attr->info.bpf_fd = get_rand_bpf_fd();
		attr->info.info_len = rand() % page_size;
		attr->info.info = (u64) get_writable_address(page_size);
		rec->a3 = sizeof(attr->info);
		break;

	case BPF_LINK_CREATE:
		attr->link_create.prog_fd = get_rand_bpf_fd();
		attr->link_create.target_fd = get_rand_bpf_fd();
		attr->link_create.attach_type = rand() % 64;
		attr->link_create.flags = rand() % 16;
		rec->a3 = sizeof(attr->link_create);
		break;

	case BPF_LINK_UPDATE:
		attr->link_update.link_fd = get_rand_bpf_fd();
		attr->link_update.new_prog_fd = get_rand_bpf_fd();
		attr->link_update.flags = rand() % 4;
		rec->a3 = sizeof(attr->link_update);
		break;

	case BPF_LINK_DETACH:
		attr->link_detach.link_fd = get_rand_bpf_fd();
		rec->a3 = 4;
		break;

	case BPF_ENABLE_STATS:
		attr->enable_stats.type = rand() % 4;
		rec->a3 = 4;
		break;

	case BPF_ITER_CREATE:
		attr->iter_create.link_fd = get_rand_bpf_fd();
		attr->iter_create.flags = 0;
		rec->a3 = sizeof(attr->iter_create);
		break;

	case BPF_PROG_BIND_MAP:
		attr->prog_bind_map.prog_fd = get_rand_bpf_fd();
		attr->prog_bind_map.map_fd = get_rand_bpf_fd();
		attr->prog_bind_map.flags = 0;
		rec->a3 = sizeof(attr->prog_bind_map);
		break;

	default:
		rec->a3 = sizeof(union bpf_attr);
		break;
	}
}

static void post_bpf(struct syscallrecord *rec)
{
	union bpf_attr *attr = (union bpf_attr *) rec->a2;
	int fd = rec->retval;

	switch (rec->a1) {
	case BPF_MAP_CREATE:
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpfobj.map_fd = fd;
			obj->bpfobj.map_type = attr->map_type;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_MAP);
		}
		break;

	case BPF_PROG_LOAD:
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpfprogobj.fd = fd;
			obj->bpfprogobj.prog_type = attr->prog_type;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_PROG);
		}

		/* Free the instruction buffer (allocated by both generators) */
		{
			void *ptr = (void *)(unsigned long)attr->insns;
			free(ptr);
		}
		break;

	default:
		break;
	}

	freeptr(&rec->a2);
}

static unsigned long bpf_cmds[] = {
	BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD, BPF_OBJ_PIN, BPF_OBJ_GET,
	BPF_PROG_ATTACH, BPF_PROG_DETACH, BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID, BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID, BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD, BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD, BPF_BTF_GET_FD_BY_ID, BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM, BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
	BPF_MAP_LOOKUP_BATCH, BPF_MAP_LOOKUP_AND_DELETE_BATCH,
	BPF_MAP_UPDATE_BATCH, BPF_MAP_DELETE_BATCH,
	BPF_LINK_CREATE, BPF_LINK_UPDATE,
	BPF_LINK_GET_FD_BY_ID, BPF_LINK_GET_NEXT_ID,
	BPF_ENABLE_STATS, BPF_ITER_CREATE,
	BPF_LINK_DETACH, BPF_PROG_BIND_MAP,
	BPF_TOKEN_CREATE,
};

struct syscallentry syscall_bpf = {
	.name = "bpf",
	.group = GROUP_BPF,
	.num_args = 3,

	.arg1name = "cmd",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(bpf_cmds),
	.arg2name = "uattr",
	.arg3name = "size",
	.sanitise = sanitise_bpf,
	.post = post_bpf,
};
#endif
