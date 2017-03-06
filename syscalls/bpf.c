/*
 * SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
 */
#ifdef USE_BPF
#include <linux/bpf.h>
#include <linux/filter.h>
#include "arch.h"
#include "bpf.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"

static unsigned long bpf_prog_types[] = {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
};

static const char license[] = "GPLv2";

static void bpf_prog_load(union bpf_attr *attr)
{
	unsigned long *insns = NULL, len = 0;
	attr->prog_type = RAND_ARRAY(bpf_prog_types);

	switch (attr->prog_type) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		bpf_gen_filter(&insns, &len);
		break;

	default:
		// this will go away when all the other cases are enumerated
		insns = zmalloc(page_size);
		generate_rand_bytes((unsigned char *)insns, len);
		break;
	}

	attr->insn_cnt = len;
	attr->insns = (u64) insns;
	attr->license = (u64) license;
	attr->log_level = 0;
	attr->log_size = rnd() % page_size;
	attr->log_buf = (u64) get_writable_address(page_size);
	attr->kern_version = rnd();	// TODO: stick uname in here.
}

#ifndef BPF_OBJ_PIN
#define BPF_OBJ_PIN 6
#define BPF_OBJ_GET 7
#endif

static void sanitise_bpf(struct syscallrecord *rec)
{
	union bpf_attr *attr;
	unsigned long bpf_map_types[] = {
		BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PROG_ARRAY, BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		BPF_MAP_TYPE_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_STACK_TRACE, BPF_MAP_TYPE_CGROUP_ARRAY,
		BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_LPM_TRIE,
	};

	attr = zmalloc(sizeof(union bpf_attr));
	rec->a2 = (unsigned long) attr;

	switch (rec->a1) {
	case BPF_MAP_CREATE:
		attr->map_type = RAND_ARRAY(bpf_map_types);
		attr->key_size = rnd() % 1024;
		attr->value_size = rnd() % (1024 * 64);
		attr->max_entries = rnd() % 1024;
		attr->flags = RAND_RANGE(0, 4);
		rec->a3 = 20;
		break;

	case BPF_MAP_LOOKUP_ELEM:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		attr->value = rnd();
		rec->a3 = 32;
		break;

	case BPF_MAP_UPDATE_ELEM:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		attr->value = rnd();
		attr->next_key = rnd();
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
		attr->value = rnd();
		rec->a3 = 32;
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

	default:
		break;
	}
}

static void post_bpf(struct syscallrecord *rec)
{
	union bpf_attr *attr = (union bpf_attr *) rec->a2;

	switch (rec->a1) {
	case BPF_MAP_CREATE:
		//TODO: add fd to local object cache
		break;

	case BPF_PROG_LOAD:
		//TODO: add fd to local object cache

		if (attr->prog_type == BPF_PROG_TYPE_SOCKET_FILTER) {
			void *ptr = (void *) attr->insns;
			free(ptr);
		}
		break;
	default:
		break;
	}

	freeptr(&rec->a2);
}

static unsigned long bpf_cmds[] = {
	BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY, BPF_PROG_LOAD, BPF_OBJ_PIN, BPF_OBJ_GET,
};

struct syscallentry syscall_bpf = {
	.name = "bpf",
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
